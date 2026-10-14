import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { CHECKS } from './checks.js';
import { toSarif } from './sarif.js';
import { evaluateObservatory } from './observatory.js';
import { analyzeHttpRedirection } from './redirect.js';
import { isDomainPreloaded } from './preload.js';
import { hstsPreloadEligible } from './preload.js';

export { CHECKS, toSarif };
export { pretty } from './format.js';
export { evaluateObservatory, evaluateObservatoryTests } from './observatory.js';
export {
  computeObservatoryScore,
  gradeFromScore,
  grade,
  SCORE_TABLE,
  describeObservatoryResult,
  MINIMUM_SCORE_FOR_EXTRA_CREDIT,
} from './scoring.js';
export { fetchSitemapUrls, parseSitemapDocument } from './sitemap.js';
export { baselineFromResults, diffAgainstBaseline, fingerprintResult } from './baseline.js';
export { followRedirectChain, analyzeHttpRedirection } from './redirect.js';
export { isDomainPreloaded, hstsPreloadEligible } from './preload.js';

function moduleDir() {
  // CJS bundle (dist/index.cjs) has __filename; ESM uses import.meta.url
  // eslint-disable-next-line no-undef
  if (typeof __filename !== 'undefined') return dirname(__filename);
  return dirname(fileURLToPath(import.meta.url));
}
const VERSION = JSON.parse(readFileSync(join(moduleDir(), '../package.json'), 'utf8')).version;

/** Apply config: { ignore: [ids], severity: { id: 'error'|'warn'|'off' } } */
export function applyConfig(findings, config = {}) {
  const ignore = new Set(config.ignore || []);
  const sev = config.severity || {};
  const out = [];
  for (const x of findings) {
    const base = x.id.split('-')[0];
    if (ignore.has(x.id) || ignore.has(base)) continue;
    const s = sev[x.id] ?? sev[base];
    if (s === 'off') continue;
    out.push(s ? { ...x, severity: s } : x);
  }
  return out;
}

export function analyze({ url, headers, setCookies }, config = {}) {
  const h = headers instanceof Headers ? headers : new Headers(headers || {});
  const cookies = setCookies ?? (typeof h.getSetCookie === 'function' ? h.getSetCookie() : []);
  const ctx = { url, headers: h, setCookies: cookies, isHttps: url.startsWith('https:') };
  let findings = [];
  for (const [name, fn] of Object.entries(CHECKS)) {
    if ((config.ignore || []).includes(name)) continue;
    findings.push(...fn(ctx));
  }
  findings = applyConfig(findings, config);
  const observatory = evaluateObservatory(ctx, {});
  return {
    url,
    findings,
    score: observatory.score,
    grade: observatory.grade,
    likelihoodIndicator: observatory.likelihoodIndicator,
    observatory,
  };
}

/**
 * @param {string} url
 * @param {import('./index.js').ScanOptions} [opts]
 */
export async function scan(url, opts = {}) {
  const {
    timeout = 10000,
    headers = {},
    followRedirects = true,
    config = {},
    checkHttpRedirection = true,
    checkPreload = true,
  } = opts;
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeout);
  try {
    const res = await fetch(url, {
      method: 'GET',
      redirect: followRedirects ? 'follow' : 'manual',
      signal: ctrl.signal,
      headers: { 'user-agent': `header-sentinel/${VERSION}`, ...headers },
    });
    res.body?.cancel?.().catch(() => {});

    const finalUrl = res.url || url;
    const h = res.headers;
    const cookies = typeof h.getSetCookie === 'function' ? h.getSetCookie() : [];
    const ctx = { url: finalUrl, headers: h, setCookies: cookies, isHttps: finalUrl.startsWith('https:') };

    let findings = [];
    for (const [name, fn] of Object.entries(CHECKS)) {
      if ((config.ignore || []).includes(name)) continue;
      findings.push(...fn(ctx));
    }

    /** @type {{ result?: string; route?: string[]; destination?: string }} */
    let redirection = {};
    if (checkHttpRedirection && ctx.isHttps) {
      redirection = await analyzeHttpRedirection(finalUrl, {
        timeout,
        headers,
        isPreloaded: checkPreload ? (host) => isDomainPreloaded(host, { timeout }) : undefined,
      });
      if (redirection.result && redirection.result !== 'redirection-not-needed-no-http') {
        findings.push(...redirectionFindings(redirection));
      }
    }

    let hstsPreloaded = false;
    if (checkPreload && ctx.isHttps) {
      try {
        hstsPreloaded = await isDomainPreloaded(new URL(finalUrl).hostname, { timeout });
      } catch { /* optional */ }
      const hsts = h.get('strict-transport-security');
      if (!hstsPreloaded && hstsPreloadEligible(hsts)) {
        findings.push({
          id: 'hsts-preload-eligible',
          severity: 'warn',
          title: 'HSTS header is eligible for preload submission',
          message: 'Header includes preload, includeSubDomains, and max-age ≥ 1 year, but the domain is not preloaded yet.',
          fix: 'Submit at https://hstspreload.org/ after verifying HTTPS on all subdomains.',
        });
      }
    }

    findings = applyConfig(findings, config);
    const observatory = evaluateObservatory(ctx, {
      redirectionResult: redirection.result,
      hstsPreloaded,
    });

    return {
      url: finalUrl,
      requestedUrl: url,
      status: res.status,
      redirectChain: followRedirects && finalUrl !== url ? [url, finalUrl] : undefined,
      redirection: redirection.result ? { result: redirection.result, route: redirection.route, destination: redirection.destination } : undefined,
      findings,
      score: observatory.score,
      grade: observatory.grade,
      likelihoodIndicator: observatory.likelihoodIndicator,
      observatory,
    };
  } catch (e) {
    const msg = e.name === 'AbortError' ? `timed out after ${timeout}ms` : (e.cause?.message || e.message);
    const observatory = evaluateObservatory(
      { url, headers: new Headers(), setCookies: [], isHttps: url.startsWith('https:') },
      {},
    );
    return {
      url,
      requestedUrl: url,
      status: 0,
      error: msg,
      score: Math.min(observatory.score, 0),
      grade: 'F',
      likelihoodIndicator: 'MEDIUM',
      observatory: { ...observatory, score: 0, grade: 'F' },
      findings: [{
        id: 'fetch',
        severity: 'error',
        title: 'Request failed',
        message: msg,
        fix: 'Check that the URL is reachable from CI and increase --timeout if needed.',
      }],
    };
  } finally {
    clearTimeout(t);
  }
}

/** @param {{ result: string; route?: string[] }} redirection */
function redirectionFindings(redirection) {
  const fix = 'Redirect http:// to https:// on the same host (301). Example:\n' +
    '  Nginx: return 301 https://$host$request_uri;\n  Express: app.use((req,res,next)=> req.secure? next(): res.redirect(301, `https://${req.headers.host}${req.url}`))';
  const map = {
    'redirection-missing': ['redirection', 'error', 'HTTP does not redirect to HTTPS', 'Plain HTTP is still served without upgrading to HTTPS.'],
    'redirection-not-to-https': ['redirection', 'error', 'HTTP redirect does not end on HTTPS', 'The HTTP redirect chain does not land on an HTTPS URL.'],
    'redirection-not-to-https-on-initial-redirection': ['redirection', 'error', 'HTTP redirect chain delays HTTPS upgrade', 'The first hop from HTTP should go directly to HTTPS.'],
    'redirection-off-host-from-http': ['redirection', 'warn', 'HTTP redirect changes host before HTTPS', 'Cross-host HTTP→HTTPS redirects prevent HSTS from covering the original hostname.'],
  };
  const row = map[redirection.result];
  if (!row) return [];
  const [, severity, title, message] = row;
  return [{ id: row[0], severity, title, message, fix }];
}

export async function scanAll(urls, opts = {}) {
  return Promise.all(urls.map((u) => scan(u, opts)));
}

export function shouldFail(results, failOn = 'error') {
  const lv = failOn === 'warn' ? ['error', 'warn'] : failOn === 'none' ? [] : ['error'];
  return results.some((r) => r.findings.some((f) => lv.includes(f.severity)));
}
