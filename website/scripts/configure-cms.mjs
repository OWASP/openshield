import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const configPath = path.join(root, 'dist', 'admin', 'config.yml');
const clientId = process.env.DECAP_GITHUB_APP_ID?.trim();

if (!clientId) {
  fs.rmSync(path.dirname(configPath), { recursive: true, force: true });
  console.log('DECAP_GITHUB_APP_ID is not configured; omitted the optional CMS from the generated site.');
  process.exit(0);
}

if (!/^[A-Za-z0-9]{12,128}$/.test(clientId)) {
  console.error('DECAP_GITHUB_APP_ID must be a 12 to 128 character alphanumeric OAuth Client ID.');
  process.exit(1);
}

if (!fs.existsSync(configPath)) {
  console.error('CMS config was not found in dist. Run npm run build first.');
  process.exit(1);
}

const config = fs.readFileSync(configPath, 'utf8');
const insertionPoint = '  auth_type: pkce\n';
if (!config.includes(insertionPoint) || /^\s*app_id:/m.test(config)) {
  console.error('CMS config cannot be safely configured: expected one auth_type entry and no existing app_id.');
  process.exit(1);
}

fs.writeFileSync(configPath, config.replace(insertionPoint, `${insertionPoint}  app_id: ${clientId}\n`));
console.log('Configured the generated CMS artifact with the GitHub OAuth Client ID.');
