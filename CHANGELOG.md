# Changelog

## 1.0.3 - 2026-10-13
- Fix: add `"./package.json"` to `exports` so `require('header-sentinel/package.json')` and `import ... with { type: 'json' }` no longer throw `ERR_PACKAGE_PATH_NOT_EXPORTED`.

## 1.0.0 - 2026-10-13
- Initial release: CLI + ESM API with TypeScript types.
- Checks: HSTS, CSP (unsafe-inline/eval, wildcards, missing directives), X-Frame-Options/frame-ancestors, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, Server/X-Powered-By leaks, cookie flags, X-XSS-Protection.
- Pretty (NO_COLOR-aware), JSON and SARIF 2.1.0 output; score & grade.
- Config file, `--fail-on`, `--timeout`, `--header`, redirect following.
- Composite GitHub Action.
