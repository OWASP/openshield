import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const dist = path.join(root, 'dist');
const failures = [];

function filesUnder(directory) {
  if (!fs.existsSync(directory)) return [];
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(directory, entry.name);
    return entry.isDirectory() ? filesUnder(full) : [full];
  });
}

const sourceFiles = [path.join(root, 'src'), path.join(root, 'public'), path.join(root, 'README.md')]
  .flatMap((entry) => fs.statSync(entry).isDirectory() ? filesUnder(entry) : [entry])
  .filter((file) => /\.(astro|css|html|js|json|md|mjs|svg|ts|xml|xsl)$/.test(file));

for (const file of sourceFiles) {
  const source = fs.readFileSync(file, 'utf8');
  if (source.includes('\u2014')) failures.push(`${path.relative(root, file)} contains an em dash`);
}

const htmlFiles = filesUnder(dist).filter((file) => file.endsWith('.html') && !file.includes(`${path.sep}admin${path.sep}`));
if (!htmlFiles.length) failures.push('dist contains no HTML pages; run npm run build first');

for (const file of htmlFiles) {
  const html = fs.readFileSync(file, 'utf8');
  const relative = path.relative(dist, file);
  if (!html.includes('<main id="main-content"')) failures.push(`${relative} has no main landmark`);
  if (!html.includes('href="#main-content"')) failures.push(`${relative} has no skip link`);
  if (!html.includes('<meta name="description"')) failures.push(`${relative} has no meta description`);
  if (!html.includes('<link rel="canonical"')) failures.push(`${relative} has no canonical URL`);
  for (const match of html.matchAll(/href="([^"]+)"/g)) {
    const href = match[1];
    if (!href.startsWith('/openshield/')) continue;
    const clean = href.replace('/openshield/', '').split(/[?#]/, 1)[0];
    const target = clean
      ? path.join(dist, clean.endsWith('/') ? clean : clean)
      : path.join(dist, 'index.html');
    const resolved = path.extname(target) ? target : path.join(target, 'index.html');
    if (!fs.existsSync(resolved)) failures.push(`${relative} links to missing internal path ${href}`);
  }
}

const index = fs.existsSync(path.join(dist, 'index.html'))
  ? fs.readFileSync(path.join(dist, 'index.html'), 'utf8')
  : '';
if (!index.includes('Illustrative output')) failures.push('homepage does not label sample scan output');

const cmsConfigPath = path.join(dist, 'admin', 'config.yml');
const adminPath = path.join(dist, 'admin', 'index.html');
const hasCmsConfig = fs.existsSync(cmsConfigPath);
const hasAdminShell = fs.existsSync(adminPath);
if (hasCmsConfig !== hasAdminShell) failures.push('generated CMS artifact is incomplete');
if (hasCmsConfig && hasAdminShell) {
  const cmsConfig = fs.readFileSync(cmsConfigPath, 'utf8');
  if (cmsConfig.includes('local_backend:')) failures.push('generated CMS config enables the local authentication backend');
  if (!/^\s*app_id:\s*[A-Za-z0-9]{12,128}\s*$/m.test(cmsConfig)) failures.push('generated CMS config has no valid OAuth Client ID');

  const admin = fs.readFileSync(adminPath, 'utf8');
  const cmsAssets = [
    {
      url: 'https://cdn.jsdelivr.net/npm/decap-cms@3.16.0/dist/cms.css',
      integrity: 'sha384-Ofw8+GuqbDe5y3beeOCG2GTh2pI9R6JEHecNYDHWLntqMcH/IrzpKCsGt070FUmc',
    },
    {
      url: 'https://cdn.jsdelivr.net/npm/decap-cms@3.16.0/dist/decap-cms.min.js',
      integrity: 'sha384-WFBlw1ZGvgE9W2ia0r2gJPu3HOVweIpoHCGmlm3f/9J2OURAjzuJ/lV55gUd4By4',
    },
  ];
  for (const asset of cmsAssets) {
    if (!admin.includes(`href="${asset.url}" integrity="${asset.integrity}" crossorigin="anonymous"`)
      && !admin.includes(`src="${asset.url}" integrity="${asset.integrity}" crossorigin="anonymous"`)) {
      failures.push(`CMS asset ${asset.url} does not use its verified SRI digest and anonymous CORS`);
    }
  }
}

const robotsPath = path.join(dist, 'robots.txt');
const robots = fs.existsSync(robotsPath) ? fs.readFileSync(robotsPath, 'utf8') : '';
if (!robots.includes('Disallow: /openshield/admin/')) failures.push('robots.txt does not exclude the CMS route');

const jsFiles = filesUnder(path.join(dist, '_astro')).filter((file) => file.endsWith('.js'));
const largestJs = jsFiles.reduce((largest, file) => Math.max(largest, fs.statSync(file).size), 0);
const jsBudget = 520 * 1024;
if (largestJs > jsBudget) failures.push(`largest JavaScript asset is ${Math.ceil(largestJs / 1024)} KiB; budget is 520 KiB`);

if (failures.length) {
  console.error(`Website verification failed:\n- ${failures.join('\n- ')}`);
  process.exit(1);
}

console.log(`Website verification passed for ${htmlFiles.length} HTML pages. Largest JavaScript asset: ${Math.ceil(largestJs / 1024)} KiB.`);
