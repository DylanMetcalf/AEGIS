#!/usr/bin/env node
/**
 * Inspects the built frontend (apps/web/dist) for things that must never
 * reach a browser: credentials, connection strings, server-only code, source
 * maps, and the literal values of secrets present in the build environment
 * (process env and a local .env, if any). Values are never printed.
 */
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const DIST = 'apps/web/dist';
if (!existsSync(join(DIST, 'index.html'))) {
  console.error(`${DIST} not found; run the web build first.`);
  process.exit(1);
}

const walk = (dir) =>
  readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
const files = walk(DIST);

const FORBIDDEN = [
  ['connection string', /\b(?:postgres(?:ql)?|redis|mysql):\/\/[^\s"'`]+/],
  ['private key block', /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
  ['AWS access key id', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/],
  [
    'server environment variable name',
    /\b(?:DATABASE_URL|DATABASE_MIGRATION_URL|TEST_DATABASE_ADMIN_URL|PG_ADMIN_URL)\b/,
  ],
  ['server-only code', /pg_advisory|set_config\(|@node-rs\/argon2|claim_job|audit_verify_chain/],
  ['process.env access', /process\.env\.[A-Z_]{3,}/],
];

// Secret values from the build environment and a local .env file.
const secretValues = new Set();
const consider = (k, v) => {
  if (!v || v.length < 8) return;
  if (/(SECRET|PASSWORD|TOKEN|KEY|DATABASE_URL|MIGRATION_URL)/.test(k)) secretValues.add(v);
};
for (const [k, v] of Object.entries(process.env)) consider(k, v);
if (existsSync('.env')) {
  for (const line of readFileSync('.env', 'utf8').split('\n')) {
    const m = /^([A-Z0-9_]+)=(.*)$/.exec(line.trim());
    if (m) consider(m[1], m[2]);
  }
}

const findings = [];
for (const f of files) {
  if (f.endsWith('.map')) findings.push(`${f}: source map shipped`);
  if (!/\.(js|css|html|json|svg|txt)$/.test(f)) continue;
  const text = readFileSync(f, 'utf8');
  for (const [name, re] of FORBIDDEN) if (re.test(text)) findings.push(`${f}: ${name}`);
  for (const v of secretValues)
    if (text.includes(v)) findings.push(`${f}: contains the value of a build-environment secret`);
}

if (findings.length) {
  console.error(`Bundle scan failed:\n  ${findings.join('\n  ')}`);
  process.exit(1);
}
console.log(
  `Bundle scan passed (${files.length} files, ${secretValues.size} secret values checked).`,
);
