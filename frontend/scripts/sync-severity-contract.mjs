import { readFile, writeFile } from 'node:fs/promises';

const canonicalUrl = new URL('../../contracts/severity.v1.json', import.meta.url);
const generatedUrl = new URL('../src/generated/severity.v1.json', import.meta.url);
const canonical = JSON.parse(await readFile(canonicalUrl, 'utf8'));
const expected = `${JSON.stringify(canonical, null, 2)}\n`;

if (process.argv.includes('--check')) {
  const generated = await readFile(generatedUrl, 'utf8');
  if (generated !== expected) {
    throw new Error(
      'frontend severity contract is stale; run npm run sync:severity and commit the result',
    );
  }
} else {
  await writeFile(generatedUrl, expected, 'utf8');
}
