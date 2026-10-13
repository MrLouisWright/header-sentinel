# header-sentinel

![npm](https://img.shields.io/npm/v/header-sentinel.svg)
![CI](https://github.com/MrLouisWright/header-sentinel/actions/workflows/ci.yml/badge.svg)
![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![node >=18](https://img.shields.io/badge/node-%3E%3D18-brightgreen)
![zero deps](https://img.shields.io/badge/dependencies-0-success)

Fail your CI when deployed URLs are missing or misconfigure HTTP security headers — with a **specific fix** (example header + Nginx/Express/Vercel/Netlify hints) for every problem. Zero dependencies, Node ≥ 18, JSON and SARIF (GitHub code scanning) output.

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
      --json                Print JSON results
      --sarif [file]        Print SARIF 2.1.0 (or write to file)
  -t, --timeout <ms>        Request timeout (default: 10000)
  -H, --header "K: V"       Extra request header (repeatable)
      --no-follow-redirects Check the first response instead of the final one (default follows)
```

Exit codes: `0` pass, `1` findings at/above `--fail-on`, `2` usage error. Colours are disabled when `NO_COLOR` is set or stdout is not a TTY (`FORCE_COLOR=1` forces them).

### Sample output

```
$ npx header-sentinel https://github.com

https://github.com/ (HTTP 200)  Grade B score 80/100
  ⚠ warn  CSP style-src allows 'unsafe-inline' [csp-unsafe-inline]
          'unsafe-inline' in style-src defeats XSS protection.
          fix: Replace 'unsafe-inline' with nonces ('nonce-<random>') or hashes ('sha256-...').
  ⚠ warn  Permissions-Policy missing [permissions-policy]
          Powerful browser features (camera, geolocation...) are not restricted.
          fix: Add: Permissions-Policy: camera=(), microphone=(), geolocation=(), interest-cohort=()
            Nginx: add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
  ⚠ warn  Cross-Origin-Opener-Policy missing [coop]
          Window is not isolated from cross-origin openers (XS-Leaks/Spectre).
          fix: Add: Cross-Origin-Opener-Policy: same-origin (or same-origin-allow-popups if you rely on OAuth popups)
  ⚠ warn  Cookie "_octo" missing HttpOnly [cookies]
          Set-Cookie: _octo=GH1.1.1534189212.1791915518; expires=Wed, 13 Oct 2027 18:18:38 GMT; domain=.github.com; path=/; secure; SameSite=L
          fix: Example: Set-Cookie: _octo=...; Path=/; Secure; HttpOnly; SameSite=Lax
            Express: res.cookie(name, v, { secure: true, httpOnly: true, sameSite: "lax" })  (omit HttpOnly only if JS must read it)

1 URL(s) scanned: 0 errors, 4 warning(s)
```

Score: 100 minus 15 per error and 5 per warning → grade A+ (≥95), A (≥85), B (≥70), C (≥55), D (≥40), F.

## Checks


| id                                                                           | severity   | what                                                                                                     |
| ---------------------------------------------------------------------------- | ---------- | -------------------------------------------------------------------------------------------------------- |
| `hsts`                                                                       | error      | `Strict-Transport-Security` present on HTTPS with `max-age` ≥ 31536000                                   |
| `hsts-subdomains`                                                            | warn       | HSTS includes `includeSubDomains`                                                                        |
| `csp`                                                                        | error      | `Content-Security-Policy` present                                                                        |
| `csp-unsafe-inline` / `csp-unsafe-eval`                                      | warn       | `'unsafe-inline'` (without nonce/hash) or `'unsafe-eval'` in a *-src directive                           |
| `csp-wildcard`                                                               | warn       | `*`, `http:`, `https:` (or `data:` in script/default-src) sources                                        |
| `csp-missing-default-src` / `-object-src` / `-base-uri` / `-frame-ancestors` | warn       | important directives missing                                                                             |
| `frame-options`                                                              | error      | `X-Frame-Options: DENY/SAMEORIGIN` or CSP `frame-ancestors`                                              |
| `content-type-options`                                                       | error      | `X-Content-Type-Options: nosniff`                                                                        |
| `referrer-policy`                                                            | warn/error | present and a safe value (`unsafe-url`/invalid = error)                                                  |
| `permissions-policy`                                                         | warn       | `Permissions-Policy` present                                                                             |
| `coop`                                                                       | warn       | `Cross-Origin-Opener-Policy: same-origin` (or `-allow-popups`)                                           |
| `info-leak-server` / `info-leak-powered-by`                                  | warn       | `Server` with version, `X-Powered-By`, `X-AspNet-Version`                                                |
| `cookies`                                                                    | error/warn | `Set-Cookie` without `Secure` (error, HTTPS) / `HttpOnly` / `SameSite`; `SameSite=None` without `Secure` |
| `x-xss-protection`                                                           | warn       | deprecated header set to anything other than `0`                                                         |
| `fetch`                                                                      | error      | URL could not be fetched / timed out                                                                     |




## Config

`.headerguardrc.json` (or `.headersentinelrc.json`, or `--config path`):

```json
{
  "urls": ["https://example.com"],
  "failOn": "error",
  "timeout": 10000,
  "headers": { "User-Agent": "my-ci" },
  "ignore": ["coop", "info-leak-server"],
  "severity": { "permissions-policy": "error", "csp-unsafe-inline": "off" }
}
```

`ignore` / `severity` accept a specific id (`csp-unsafe-inline`) or a check group (`csp`, `info-leak`, `hsts`). Severity `"off"` disables it.

## CI



### GitHub Actions (action)

```yaml
# Copy to .github/workflows/security-headers.yml in your project
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
- run: npx header-sentinel@1 https://staging.example.com --fail-on error
```



### GitLab CI

```yaml
security-headers:
  image: node:20-alpine
  stage: test
  script:
    - npx header-sentinel@1 "$CI_ENVIRONMENT_URL" --json > headers.json
  artifacts:
    when: always
    paths: [headers.json]
```



## API

```js
import { scan, scanAll, analyze, shouldFail, toSarif } from 'header-sentinel';

const results = await scanAll(['https://example.com'], { timeout: 5000, config: { ignore: ['coop'] } });
if (shouldFail(results, 'error')) process.exit(1);

// offline: analyze headers you already have
analyze({ url: 'https://x.test', headers: { 'x-content-type-options': 'nosniff' } });
```

Types ship in `src/index.d.ts`.

## License

MIT © Louis Wright ([Louis Wright](https://github.com/MrLouisWright))