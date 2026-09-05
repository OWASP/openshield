/**
 * Build-time extraction of live repository data.
 *
 * Everything the site shows about the project (rule counts, domains,
 * playbooks, contributors, latest release, docs index) is derived from the
 * repository itself at build time, so nothing here ever needs a manual edit
 * when the codebase moves on. The Pages workflow checks out full git history
 * (fetch-depth: 0) so contributor counting works in CI.
 */
import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

/**
 * Locate the repository root. Astro 7 bundles static entrypoints into
 * dist/.prerender before running them, so import.meta.url is not reliable
 * here; instead walk up from the working directory (and from this file)
 * until the marker files of the repository root appear.
 */
function isRepoRoot(dir: string): boolean {
  return (
    fs.existsSync(path.join(dir, 'scanner', 'rules')) &&
    fs.existsSync(path.join(dir, 'CHANGELOG.md'))
  );
}

function findRepoRoot(): string {
  if (process.env.REPO_ROOT) return path.resolve(process.env.REPO_ROOT);
  const starts = [process.cwd(), path.dirname(fileURLToPath(import.meta.url))];
  for (const start of starts) {
    let dir = start;
    for (let depth = 0; depth < 8; depth++) {
      if (isRepoRoot(dir)) return dir;
      const parent = path.dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
  }
  // Fallback to the classic layout: website/ sits directly under the root.
  return path.resolve(process.cwd(), '..');
}

export const repoRoot = findRepoRoot();

/* ------------------------------------------------------------------ */
/* Rules                                                               */
/* ------------------------------------------------------------------ */

export interface Rule {
  id: string;
  name: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  domain: string;
  category: string;
  frameworks: Record<string, string>;
  description: string;
  remediation: string;
  playbook: string;
}

const DOMAIN_LABELS: Record<string, string> = {
  net: 'Network',
  idn: 'Identity',
  secops: 'Security Operations',
  stor: 'Storage',
  sc: 'Supply Chain',
  db: 'Database',
  pe: 'Private Endpoint',
  kv: 'Key Vault',
  aks: 'AKS',
  func: 'Serverless',
  cmp: 'Compute',
  bak: 'Backup',
  pqc: 'Post-Quantum',
  dl: 'Data Link',
  cosmos: 'Cosmos DB',
  cache: 'Cache',
};

/** Repo sources occasionally contain em dashes; site copy never does. */
function clean(value: string): string {
  return value.replace(/\s*\u2014\s*/g, ', ');
}

function quoted(source: string, field: string): string {
  const m = source.match(new RegExp(`${field}\\s*=\\s*"((?:[^"\\\\]|\\\\.)*)"`));
  return m ? m[1] : '';
}

function multiline(source: string, field: string): string {
  const m = source.match(new RegExp(`${field}\\s*=\\s*\\(([\\s\\S]*?)\\n\\)`));
  if (!m) return quoted(source, field);
  const parts = [...m[1].matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((p) => p[1]);
  return parts.join('');
}

function parseFrameworks(source: string): Record<string, string> {
  const m = source.match(/FRAMEWORKS\s*=\s*\{([^}]*)\}/);
  const out: Record<string, string> = {};
  if (!m) return out;
  for (const pair of m[1].matchAll(/"([^"]+)"\s*:\s*"([^"]*)"/g)) {
    out[pair[1]] = pair[2];
  }
  return out;
}

function parseRules(): Rule[] {
  const dir = path.join(repoRoot, 'scanner', 'rules');
  const rules: Rule[] = [];
  for (const file of fs.readdirSync(dir).sort()) {
    if (!file.startsWith('az_') || !file.endsWith('.py') || file.startsWith('_')) continue;
    const source = fs.readFileSync(path.join(dir, file), 'utf8');
    const id = quoted(source, 'RULE_ID');
    if (!id) continue;
    const domain = file.replace(/^az_/, '').replace(/_\d+\.py$/, '');
    rules.push({
      id,
      name: clean(quoted(source, 'RULE_NAME')),
      severity: (quoted(source, 'SEVERITY') || 'LOW') as Rule['severity'],
      domain,
      category: clean(quoted(source, 'CATEGORY')) || DOMAIN_LABELS[domain] || domain,
      frameworks: parseFrameworks(source),
      description: clean(multiline(source, 'DESCRIPTION')),
      remediation: clean(multiline(source, 'REMEDIATION')),
      playbook: quoted(source, 'PLAYBOOK'),
    });
  }
  return rules;
}

/* ------------------------------------------------------------------ */
/* Playbooks, contributors, releases, docs                             */
/* ------------------------------------------------------------------ */

function countPlaybooks(): number {
  const dir = path.join(repoRoot, 'playbooks', 'cli');
  return fs.readdirSync(dir).filter((f) => f.startsWith('fix_az_') && f.endsWith('.sh')).length;
}

/** Historical aliases merged so one person is not counted several times. */
const ALIASES: Record<string, string> = {
  'ritik sah': 'Ritik Sah',
  ritiksah141: 'Ritik Sah',
  'vishnu ajith': 'Vishnu Ajith',
  vishnu2707: 'Vishnu Ajith',
  'tanvir farhad': 'Tanvir Farhad',
  tft444: 'Tanvir Farhad',
  'parth j rohit': 'Parth Rohit',
  'parth rohit': 'Parth Rohit',
  parthrohit22: 'Parth Rohit',
  'safid nadaf': 'Safid Nadaf',
  safidnadaf: 'Safid Nadaf',
  'sharique ahmad': 'Sharique Ahmad',
  shariqueahmad108: 'Sharique Ahmad',
  'shaurya k sharma': 'Shaurya K Sharma',
  shauryaksharma24: 'Shaurya K Sharma',
  'prayas gautam': 'Prayas Gautam',
  vogonprayas: 'Prayas Gautam',
};

function listContributors(): string[] {
  let raw: string;
  try {
    raw = execSync('git log --format=%aN', { cwd: repoRoot, encoding: 'utf8' });
  } catch {
    return [];
  }
  const seen = new Map<string, string>();
  for (const name of raw.split('\n')) {
    const trimmed = name.trim();
    if (!trimmed || trimmed.endsWith('[bot]')) continue;
    const canonical = ALIASES[trimmed.toLowerCase()] ?? trimmed;
    seen.set(canonical.toLowerCase(), canonical);
  }
  return [...seen.values()].sort((a, b) => a.localeCompare(b));
}

function latestRelease(): { tag: string; date: string } {
  const changelog = fs.readFileSync(path.join(repoRoot, 'CHANGELOG.md'), 'utf8');
  const m = changelog.match(/^##\s*\[(\d+\.\d+\.\d+)\]\s*-\s*(\d{4}-\d{2}-\d{2})/m);
  return m ? { tag: `v${m[1]}`, date: m[2] } : { tag: 'v0.0.0', date: '' };
}

export interface DocEntry {
  file: string;
  title: string;
  section: string;
}

function docTitle(file: string): string {
  const stem = file.replace(/\.md$/, '').replace(/[-_]/g, ' ');
  return stem
    .split(' ')
    .map((w) => (w.length > 2 && w === w.toUpperCase() ? w : w.charAt(0).toUpperCase() + w.slice(1)))
    .join(' ');
}

/** doc subfolders shown after the top-level guides, with their own heading */
const DOC_SUBFOLDERS: { dir: string; section: string }[] = [
  { dir: 'deployment', section: 'Deployment' },
  { dir: 'validation', section: 'Validation reports' },
];

function listDocs(): DocEntry[] {
  const docsDir = path.join(repoRoot, 'docs');
  const entries: DocEntry[] = [];
  for (const file of fs.readdirSync(docsDir).sort()) {
    if (file.endsWith('.md') && !file.startsWith('_')) {
      entries.push({ file, title: docTitle(file), section: 'Guides and references' });
    }
  }
  for (const { dir, section } of DOC_SUBFOLDERS) {
    const full = path.join(docsDir, dir);
    if (!fs.existsSync(full)) continue;
    for (const file of fs.readdirSync(full).sort()) {
      if (file.endsWith('.md') && !file.startsWith('_')) {
        entries.push({ file: `${dir}/${file}`, title: docTitle(file), section });
      }
    }
  }
  return entries;
}

/* ------------------------------------------------------------------ */
/* Assembled dataset                                                   */
/* ------------------------------------------------------------------ */

const rules = parseRules();

const domainCounts = new Map<string, number>();
for (const r of rules) domainCounts.set(r.domain, (domainCounts.get(r.domain) ?? 0) + 1);
const domains = [...domainCounts.entries()]
  .sort((a, b) => b[1] - a[1])
  .map(([key, count]) => ({ key, count, label: DOMAIN_LABELS[key] ?? key }));

export interface RepoData {
  rules: Rule[];
  domains: { key: string; count: number; label: string }[];
  ruleCount: number;
  domainCount: number;
  playbookCount: number;
  contributors: string[];
  contributorCount: number;
  release: { tag: string; date: string };
  docs: DocEntry[];
  /** demo scan: 6 high + 3 medium failing, everything else passing */
  sampleScan: { score: number; high: number; medium: number; passing: number };
}

export const repoData: RepoData = {
  rules,
  domains,
  ruleCount: rules.length,
  domainCount: domains.length,
  playbookCount: countPlaybooks(),
  contributors: listContributors(),
  contributorCount: listContributors().length,
  release: latestRelease(),
  docs: listDocs(),
  sampleScan: { score: 62, high: 6, medium: 3, passing: Math.max(rules.length - 9, 0) },
};

/** Compact [id, severity, name] triples in domain order, for the 3D hero. */
export const orbRules: [string, string, string][] = domains
  .flatMap((d) => rules.filter((r) => r.domain === d.key).sort((a, b) => a.id.localeCompare(b.id)))
  .map((r) => [r.id, r.severity, r.name]);

export const domainOrder: string[] = domains.map((d) => d.key);
