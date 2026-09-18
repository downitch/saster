import ollama from 'ollama';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

const DEFAULT_MODEL = 'qwen3.6:27b';
const CONTEXT_LINES = 15;

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

export function parseArgs(argv) {
  const args = {
    reportPath: 'triage-report.json',
    repoRoot: '.',
    outJson: 'ai-review.json',
    outMd: 'ai-review.md',
    model: DEFAULT_MODEL,
    verdicts: ['BLOCK', 'WARN'],
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--report') args.reportPath = argv[++i];
    else if (a === '--repo-root') args.repoRoot = argv[++i];
    else if (a === '--out-json') args.outJson = argv[++i];
    else if (a === '--out-md') args.outMd = argv[++i];
    else if (a === '--model') args.model = argv[++i];
    else if (a === '--all') args.verdicts = ['BLOCK', 'WARN', 'ASYNC'];
    else if (a === '--help' || a === '-h') {
      printHelp();
      process.exit(0);
    }
  }
  return args;
}

function printHelp() {
  console.log(`Usage: node index.js [options]

  --report <path>     Path to triage-report.json produced by sast_triage.py (default: triage-report.json)
  --repo-root <path>  Path to the local checkout of target-app (default: current directory)
  --out-json <path>   Where to write the raw AI review results (default: ai-review.json)
  --out-md <path>     Where to write the human-readable summary (default: ai-review.md)
  --model <name>      Ollama model to use (default: ${DEFAULT_MODEL})
  --all               Also review ASYNC findings (default: BLOCK + WARN only)
`);
}

// ---------------------------------------------------------------------------
// Report loading
// ---------------------------------------------------------------------------

export async function fetchReport(reportPath) {
  const raw = await readFile(reportPath, 'utf-8');
  return JSON.parse(raw);
}

export function parseReport(report) {
  if (!report || !Array.isArray(report.findings)) {
    throw new Error('Unexpected report shape: missing "findings" array. Was this file produced by sast_triage.py?');
  }
  return report.findings;
}

// ---------------------------------------------------------------------------
// Source fetching
// ---------------------------------------------------------------------------

export async function fetchSourceWindow(repoRoot, file, startLine, endLine, contextLines = CONTEXT_LINES) {
  const fullPath = path.join(repoRoot, file);
  let content;
  try {
    content = await readFile(fullPath, 'utf-8');
  } catch (err) {
    return { ok: false, error: `Could not read ${fullPath}: ${err.message}` };
  }

  const lines = content.split('\n');
  const start = Math.max(1, (startLine || 1) - contextLines);
  const end = Math.min(lines.length, (endLine || startLine || 1) + contextLines);

  const numbered = lines
    .slice(start - 1, end)
    .map((line, idx) => `${start + idx}: ${line}`)
    .join('\n');

  return { ok: true, snippet: numbered, windowStart: start, windowEnd: end };
}

// ---------------------------------------------------------------------------
// Prompt construction
// ---------------------------------------------------------------------------

export function buildPrompt(finding, source) {
  return `You are assisting a security engineer triaging static analysis findings.
You are NOT making the final call — a human reviews your output before any
finding's status changes. Be conservative: if the code snippet doesn't give
you enough context to be sure, say "uncertain" rather than guessing.

Finding:
- Tool(s): ${finding.tools.join(', ')}
- Rule: ${finding.rule_id}
- Reported severity/confidence: ${finding.security_severity ?? 'n/a'} / ${finding.confidence}
- Location: ${finding.file}:${finding.line}
- Tool message: ${finding.message}

Source code (line numbers shown; the flagged line is ${finding.line}):
\`\`\`
${source.snippet}
\`\`\`

Respond with ONLY a JSON object in this exact shape, no prose outside the JSON:
{
  "verdict": "true_positive" | "false_positive" | "uncertain",
  "reachable_from_untrusted_input": "yes" | "no" | "unclear",
  "reasoning": "2-4 sentences explaining the call, referencing specific lines",
  "self_reported_confidence": "low" | "medium" | "high"
}`;
}

// ---------------------------------------------------------------------------
// Review a single finding
// ---------------------------------------------------------------------------

export async function reviewFinding(model, finding, repoRoot) {
  const source = await fetchSourceWindow(repoRoot, finding.file, finding.line, finding.line);
  if (!source.ok) {
    return { finding, ai: null, error: source.error };
  }

  const prompt = buildPrompt(finding, source);

  let response;
  try {
    response = await ollama.chat({
      model,
      messages: [{ role: 'user', content: prompt }],
      format: 'json',
      options: { temperature: 0 },
    });
  } catch (err) {
    return { finding, ai: null, error: `ollama error: ${err.message}` };
  }

  let parsed;
  try {
    parsed = JSON.parse(response.message.content);
  } catch (err) {
    return {
      finding,
      ai: null,
      error: `Model did not return valid JSON: ${response.message.content?.slice(0, 200)}`,
    };
  }

  return {
    finding,
    ai: parsed,
    sourceWindow: [source.windowStart, source.windowEnd],
    error: null,
  };
}

// ---------------------------------------------------------------------------
// Output rendering
// ---------------------------------------------------------------------------

export function renderMarkdown(results, model) {
  const lines = [];
  lines.push('## AI-Assisted Triage (advisory — not authoritative)\n');
  lines.push(
    `Model: \`${model}\`. This is a first opinion only. A human confirms every ` +
      `verdict below before it changes a finding's status — see DECISIONS.md ` +
      `for what evidence is required before trusting this output.\n`
  );
  lines.push('| Finding | AI Verdict | Reachable? | AI Confidence | Reasoning |');
  lines.push('|---|---|---|---|---|');
  for (const r of results) {
    const loc = `${r.finding.file}:${r.finding.line}`;
    if (r.error) {
      lines.push(`| \`${loc}\` | ⚠️ error | - | - | ${r.error.replace(/\|/g, '\\|')} |`);
      continue;
    }
    const { verdict, reachable_from_untrusted_input, reasoning, self_reported_confidence } = r.ai;
    lines.push(
      `| \`${loc}\` | ${verdict} | ${reachable_from_untrusted_input} | ` +
        `${self_reported_confidence} | ${String(reasoning).replace(/\|/g, '\\|')} |`
    );
  }
  return lines.join('\n') + '\n';
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

export async function main() {
  const args = parseArgs(process.argv.slice(2));

  const report = await fetchReport(args.reportPath);
  const allFindings = parseReport(report);
  const findings = allFindings.filter((f) => args.verdicts.includes(f.verdict));

  console.log(
    `Loaded ${allFindings.length} findings, reviewing ${findings.length} ` +
      `(verdicts: ${args.verdicts.join(', ')})`
  );

  if (findings.length === 0) {
    console.log('Nothing to review. Pass --all to include ASYNC findings too.');
  }

  const results = [];
  for (const finding of findings) {
    process.stdout.write(`  reviewing ${finding.file}:${finding.line} (${finding.rule_id})... `);
    const result = await reviewFinding(args.model, finding, args.repoRoot);
    console.log(result.error ? `error: ${result.error}` : result.ai.verdict);
    results.push(result);
  }

  await writeFile(args.outJson, JSON.stringify(results, null, 2));
  await writeFile(args.outMd, renderMarkdown(results, args.model));

  console.log(`\nWrote ${args.outJson} and ${args.outMd}`);
}

// Only run main() when this file is executed directly (not when imported for tests)
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}