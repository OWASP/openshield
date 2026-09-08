import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';

// https://astro.build/config
export default defineConfig({
  site: 'https://openshield-org.github.io',
  base: '/openshield',
  integrations: [sitemap()],
  build: {
    // Never inline hoisted <script> or bundled CSS into the HTML. The site's
    // CSP (src/layouts/Base.astro) is script-src 'self' with no 'unsafe-inline'
    // and no nonce/hash - an inlined <script> block would be silently blocked
    // by the browser on the deployed GitHub Pages site. Emitting every script
    // as a same-origin file keeps it inside 'self'. verify-site.mjs also fails
    // the build if an executable inline <script> slips into any page.
    inlineStylesheets: 'never',
    assetsInlineLimit: 0,
  },
  vite: {
    build: {
      // Same reason: stop Vite from inlining small chunks as data: URIs or
      // inline script text during Astro's client bundle step.
      assetsInlineLimit: 0,
    },
    server: {
      fs: {
        // repoData.ts reads scanner/rules, playbooks and docs from the repo root
        allow: ['../..'],
      },
    },
  },
});
