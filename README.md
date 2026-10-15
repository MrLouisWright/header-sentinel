# header-sentinel

![npm](https://img.shields.io/npm/v/header-sentinel.svg)
![CI](https://github.com/MrLouisWright/header-sentinel/actions/workflows/ci.yml/badge.svg)
![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![node >=18](https://img.shields.io/badge/node-%3E%3D18-brightgreen)
![zero deps](https://img.shields.io/badge/dependencies-0-success)

Fail your CI when deployed URLs are missing or misconfigure HTTP security headers — with a **specific fix** (example header + Nginx/Express/Vercel/Netlify hints) for every problem. **Mozilla HTTP Observatory-style** letter grades (A+ through F), zero runtime dependencies, Node ≥ 18, JSON and SARIF (GitHub code scanning) output.

## Install

```bash
npm i -D header-sentinel        # or run ad-hoc:
npx header-sentinel https://example.com
```

## Usage

```
header-sentinel <url...> [options]

  -c, --config <file>       JSON config (default: .headerguardrc.json / .headersentinelrc.json if present)
      --fail-on <level>     error | warn | none   (default: error)
      --json                Print JSON results (includes observatory score/tests)
      --sarif [file]        Print SARIF 2.1.0 (or write to file)
      --sitemap <url>       Load URLs from sitemap.xml (repeatable)
      --baseline <file>     Only fail on findings not in baseline
      --update-baseline     Write current fingerprints to --baseline
      --no-http-upgrade     Skip HTTP→HTTPS redirect analysis
      --no-preload-check    Skip HSTS preload list / eligibility lookups
  -t, --timeout <ms>        Request timeout (default: 10000)
  -H, --header "K: V"       Extra request header (repeatable)
      --no-follow-redirects Check the first response instead of the final one (default follows)
```

Exit codes: `0` pass, `1` findings at/above `--fail-on`, `2` usage error. Colours are disabled when `NO_COLOR` is set or stdout is not a TTY (`FORCE_COLOR=1` forces them).

### Scoring (Mozilla Observatory)

Sites start at **100**. Penalties apply first; **bonuses** (for example strong CSP, Referrer-Policy, frame-ancestors, HSTS preload) apply only if the pre-bonus score is **≥ 90**. Grades use Observatory buckets: **A+** (100+), **A**, **A-**, **B+** … **F** (0–24). Each scan also reports a **likelihood indicator** (LOW/MEDIUM) derived from the grade.

Detailed header lint findings (severity error/warn) are separate from Observatory test keys; CI failure is still driven by `--fail-on` and findings, while `--json` exposes `score`, `grade`, and `observatory.tests[]`.

### Sample output

```
$ npx header-sentinel https://github.com --no-http-upgrade --no-preload-check

https://github.com/ (HTTP 200)  Grade B+ score 80/100 · MEDIUM risk
  ⚠ warn  CSP style-src allows 'unsafe-inline' [csp-unsafe-inline]
  ...
```

### Baseline (CI: fail only on new issues)

```bash
# First run on main — record accepted findings
npx header-sentinel https://example.com --baseline .header-baseline.json --update-baseline

# PR / nightly — exit 1 only if something new appears
npx header-sentinel https://example.com --baseline .header-baseline.json --fail-on error
```

### Sitemap mode

```bash
npx header-sentinel --sitemap https://example.com/sitemap.xml --baseline .header-baseline.json
```

## Checks

| id | severity | what |
| --- | --- | --- |
| `hsts` | error | `Strict-Transport-Security` on HTTPS with `max-age` ≥ 31536000 |
| `hsts-subdomains` | warn | HSTS includes `includeSubDomains` |
| `hsts-preload-eligible` | warn | Header meets preload submission requirements (not yet on preload list) |
| `redirection` | error/warn | HTTP→HTTPS upgrade / redirect chain (Observatory-aligned) |
| `csp` | error | `Content-Security-Policy` present (live header lint only; use [csp-forge](https://github.com/MrLouisWright/csp-forge) to build policies) |
| `csp-unsafe-inline` / `csp-unsafe-eval` | warn | unsafe keywords in *-src |
| `csp-wildcard` | warn | overly broad sources |
| `csp-missing-*` | warn | important directives missing |
| `frame-options` | error | `X-Frame-Options` or CSP `frame-ancestors` |
| `content-type-options` | error | `X-Content-Type-Options: nosniff` |
| `referrer-policy` | warn/error | safe Referrer-Policy |
| `permissions-policy` | warn | `Permissions-Policy` present |
| `coop` | warn | `Cross-Origin-Opener-Policy` |
| `info-leak-*` | warn | `Server` / `X-Powered-By` leaks |
| `cookies` | warn | Set-Cookie **presence only** — run [cookie-sentinel](https://github.com/MrLouisWright/cookie-sentinel) for full cookie audits |
| `x-xss-protection` | warn | deprecated header enabled |
| `fetch` | error | URL could not be fetched |

No TLS certificate or DNS checks (see **tls-sentinel** / **dns-sentinel**).

## Config

`.headerguardrc.json` (or `.headersentinelrc.json`, or `--config path`):

```json
{
  "urls": ["https://example.com"],
  "sitemap": "https://example.com/sitemap.xml",
  "baseline": ".header-baseline.json",
  "failOn": "error",
  "timeout": 10000,
  "checkHttpRedirection": true,
  "checkPreload": true,
  "headers": { "User-Agent": "my-ci" },
  "ignore": ["coop", "info-leak-server"],
  "severity": { "permissions-policy": "error", "csp-unsafe-inline": "off" }
}
```

## CI

### GitHub Actions (action)

```yaml
name: Security headers
on:
  deployment_status:
  schedule: [{ cron: '0 6 * * 1' }]
  workflow_dispatch:
permissions: { contents: read, security-events: write }
jobs:
  headers:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: MrLouisWright/header-sentinel@v1
        with:
          urls: https://example.com https://example.com/login
          fail-on: error
          sarif: header-sentinel.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: header-sentinel.sarif }
```

### GitHub Actions (npx)

```yaml
- uses: actions/setup-node@v4
  with: { node-version: 20 }
- run: npx header-sentinel@1 https://staging.example.com --json --fail-on error
```

## API

**ESM**

```js
import { scan, scanAll, analyze, shouldFail, toSarif, computeObservatoryScore } from 'header-sentinel';
```

**CommonJS**

```js
const { scan, shouldFail } = require('header-sentinel');
```

```js
const results = await scanAll(['https://example.com'], {
  timeout: 5000,
  config: { ignore: ['coop'] },
  checkHttpRedirection: true,
});
console.log(results[0].grade, results[0].observatory.tests);
if (shouldFail(results, 'error')) process.exit(1);
```

Types are generated in `dist/index.d.ts` (`import` / `require` typings via `dist/index.d.cts`).

## Support

If this project is useful to you, you can support its development with a donation: [Buy me a coffee](https://donate.stripe.com/aFa00lek3cvX4Ds2Fk9EI0b). It helps keep these tools maintained, documented and free for everyone.

## Credit (optional)

Free to use under MIT, no attribution required. If header-sentinel helps you, a link back is appreciated:

```html
<a href="https://louiswright.co.uk">Built with header-sentinel by Louis Wright</a>
```

```markdown
[![Built with header-sentinel by Louis Wright](https://img.shields.io/badge/built%20with-header--sentinel-blue)](https://louiswright.co.uk)
```

## License

MIT © Louis Wright ([Louis Wright](https://github.com/MrLouisWright))
