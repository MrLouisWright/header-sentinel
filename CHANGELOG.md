# Changelog

## 1.1.2 - 2026-10-20

- Release workflow installs dependencies before publishing.
- Docs: README credit and support sections, blog images.
- No changes to the package code.

## 1.1.0 - 2026-10-14

- **Scoring:** Mozilla HTTP Observatory-style score, letter grade (A+ through F), and likelihood indicator on every scan; exposed in CLI JSON and `observatory` on API results.
- **Redirects & HSTS:** HTTP→HTTPS upgrade checks (redirect chain), HSTS preload-list lookup via hstspreload.org, and preload-eligibility hints on HTTPS responses.
- **Multi-URL / CI:** `--sitemap`, `--baseline` / `--update-baseline` for sitemap-driven scans and failing only on new issues vs a baseline file.
- **Package:** Dual ESM + CommonJS `exports` (`import` / `require`), generated `.d.ts` from source via `tsup`, expanded tests (including `require` + `import`), CI runs `npm ci`.
- **Scope:** Set-Cookie reduced to a presence hint pointing to [cookie-sentinel](https://github.com/MrLouisWright/cookie-sentinel); CSP remains live-header lint only (no generation).

## 1.0.4 - 2026-10-13

- CI: harden workflows (actions pinned to SHAs, least-privilege permissions, persist-credentials: false)

## 1.0.3 - 2026-10-13
- Fix: add `"./package.json"` to `exports` so `require('header-sentinel/package.json')` and `import ... with { type: 'json' }` no longer throw `ERR_PACKAGE_PATH_NOT_EXPORTED`.

## 1.0.0 - 2026-10-13
- Initial release: CLI + ESM API with TypeScript types.
- Checks: HSTS, CSP (unsafe-inline/eval, wildcards, missing directives), X-Frame-Options/frame-ancestors, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, Server/X-Powered-By leaks, cookie flags, X-XSS-Protection.
- Pretty (NO_COLOR-aware), JSON and SARIF 2.1.0 output; score & grade.
- Config file, `--fail-on`, `--timeout`, `--header`, redirect following.
- Composite GitHub Action.
