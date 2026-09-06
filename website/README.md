# OpenShield website

The project website, built with [Astro](https://astro.build) and deployed to GitHub
Pages. Every number on the site (rule count, domains, playbooks, contributors,
latest release, docs index) is extracted from the repository itself at build
time, so content stays correct without any manual editing.

## Local development

```bash
cd website
npm install
npm run dev        # http://localhost:4321/openshield/
```

Other scripts:

```bash
npm run build      # production build into dist/
npm run preview    # serve the production build locally
npm run check      # build plus content, semantics and bundle verification
```

Requires Node 20+ (CI uses Node 22). The build reads `scanner/rules/`,
`playbooks/cli/`, `docs/`, `CHANGELOG.md` and the git history, so it must run
from a clone (not a tarball without history) for the contributor count.

## Publishing a blog post

Posts live in `src/content/blog/` as Markdown with frontmatter. Do not commit
to `dev` or `main` directly; both are protected.

Via the CMS (recommended):

1. Open `/admin/` on the deployed site and sign in with GitHub.
2. Create or edit a post under "Blog posts". Drafts are kept in the
   editorial workflow and are not published until merged.
3. Saving opens a pull request from `cms/<slug>` against `dev`, signed off
   for DCO. A maintainer reviews and merges it.
4. When the pull request merges into `dev`, GitHub Actions builds and
   deploys the site automatically (about 1-2 minutes). The site follows
   `dev`; `main` only receives release merges.

## Deployment pipeline

`.github/workflows/website.yml` builds the site on every pull request targeting
`dev` or `main`. Every push to `dev` rebuilds and deploys the verified artifact
to GitHub Pages, so changes to rules, features, documentation, or site code are
published without maintaining a fragile path list. Manual runs can deploy only
from `dev`.

GitHub Pages does not support custom response headers. The document-level
content security policy covers supported directives, but hosting-level headers
such as `frame-ancestors` require a configurable hosting edge.

## One-time maintainer setup

1. In the repository settings, set Pages source to **GitHub Actions**.
2. Register a GitHub OAuth App for Decap CMS:
   - New OAuth App: https://github.com/settings/applications/new
   - Homepage URL: `https://openshield-org.github.io/openshield/admin/`
   - Authorization callback URL: `https://api.netlify.com/auth/done`
3. Add its public Client ID as an Actions repository variable named
   `DECAP_GITHUB_APP_ID`. Do not store a client secret. The build fails closed
   when this variable is absent or malformed.
4. Require the `Build site` status check in the protection rules for `dev` and
   `main`. This prevents a site-breaking repository change from being merged.

Decap uses `auth_type: pkce`, so no client secret or server-side token
exchange is needed.

## Content guidelines

- Plain, direct technical writing.
- No em dashes anywhere in site copy. Use commas, colons, or separate
  sentences instead.
- Frontmatter fields: `title`, `description`, `pubDate` (YYYY-MM-DD),
  optional `author`, `tags`, `draft`.

## Structure

```
website/
  astro.config.mjs        # site URL, base path, sitemap + RSS integrations
  src/content.config.ts   # blog collection schema
  src/content/blog/       # posts (managed by Decap CMS)
  src/layouts/Base.astro  # shared head, nav, footer
  src/components/         # one file per section of the landing page
  src/lib/repoData.ts     # build-time extraction of rules, docs, contributors
  src/lib/orbScene.ts     # hero visualization (three.js)
  src/pages/              # routes: home, architecture, evidence, rules, docs, blog, community, RSS and 404
  public/admin/           # Decap CMS (config + editor shell)
```
