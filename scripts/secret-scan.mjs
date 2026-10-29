#!/usr/bin/env node
/**
 * Repository secret scanner. Scans every tracked and untracked-but-not-ignored
 * file for credential patterns. Exceptions must be marked on the same line
 * with `secret-scan:allow <reason>` so each one is reviewed explicitly.
 * Matches are reported by file and line only; values are never printed.
 */
import { execFileSync } from 'node:child_process';
import { readFileSync, statSync } from 'node:fs';

const PATTERNS = [
  ['private key block', /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY-----/],
  ['AWS access key id', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/],
  ['GitHub token', /\bgh[pousr]_[A-Za-z0-9]{36,}\b/],
  ['GitHub fine-grained token', /\bgithub_pat_[A-Za-z0-9_]{50,}\b/],
  ['Slack token', /\bxox[abposr]-[A-Za-z0-9-]{10,}/],
  ['Stripe live key', /\b[rs]k_live_[A-Za-z0-9]{16,}/],
  ['Google API key', /\bAIza[0-9A-Za-z_-]{35}\b/],
  ['Anthropic API key', /\bsk-ant-[A-Za-z0-9_-]{20,}/],
  ['OpenAI-style API key', /\bsk-(?:proj-)?[A-Za-z0-9]{32,}\b/],
  ['JSON Web Token', /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/],
  [
    'connection string with password',
    /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^:\s/'"`<]+:[^@\s'"`$<>]{3,}@/,
  ],
  [
    'hard-coded secret assignment',
    /\b(?:password|passwd|secret|api[_-]?key|token|private[_-]?key)\b["']?\s*[:=]\s*["'][^"'\s]{12,}["']/i,
  ],
];

const ALLOW = /secret-scan:allow\s+\S/;
const SKIP_EXT = /\.(png|jpe?g|gif|ico|woff2?|ttf|pdf|zip|gz|lock)$/i;

const files = execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard'], {
  encoding: 'utf8',
})
  .split('\n')
  .filter(Boolean)
  .filter((f) => !SKIP_EXT.test(f) && f !== 'pnpm-lock.yaml');

const findings = [];
for (const file of files) {
  if (/(^|\/)\.env(\.|$)/.test(file) && !file.endsWith('.env.example')) {
    findings.push(`${file}: environment file must not be committed`);
    continue;
  }
  let text;
  try {
    if (statSync(file).size > 2_000_000) continue;
    text = readFileSync(file, 'utf8');
  } catch {
    continue;
  }
  text.split('\n').forEach((line, i) => {
    if (ALLOW.test(line)) return;
    for (const [name, re] of PATTERNS) {
      if (re.test(line)) findings.push(`${file}:${i + 1}: possible ${name}`);
    }
  });
}

if (findings.length) {
  console.error(`Secret scan found ${findings.length} issue(s):\n  ${findings.join('\n  ')}`);
  console.error(
    'Remove the secret (and rotate it), or mark a reviewed false positive with `secret-scan:allow <reason>`.',
  );
  process.exit(1);
}
console.log(`Secret scan passed (${files.length} files).`);
