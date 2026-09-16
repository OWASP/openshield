import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';

// https://astro.build/config
export default defineConfig({
  site: 'https://owasp.github.io',
  base: '/openshield',
  integrations: [sitemap()],
  vite: {
    server: {
      fs: {
        // repoData.ts reads scanner/rules, playbooks and docs from the repo root
        allow: ['../..'],
      },
    },
  },
});
