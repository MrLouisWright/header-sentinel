import { CHECKS } from './checks.js';
import { toSarif } from './sarif.js';
export { CHECKS, toSarif };

const PENALTY = { error: 15, warn: 5 };
const VERSION = '1.0.0';

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

export function grade(score) {
  return score >= 95 ? 'A+' : score >= 85 ? 'A' : score >= 70 ? 'B' : score >= 55 ? 'C' : score >= 40 ? 'D' : 'F';
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
  const score = Math.max(0, 100 - findings.reduce((s, x) => s + (PENALTY[x.severity] || 0), 0));
  return { url, findings, score, grade: grade(score) };
}

export async function scan(url, opts = {}) {
  const { timeout = 10000, headers = {}, followRedirects = true, config = {} } = opts;
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeout);
  try {
    const res = await fetch(url, {
      method: 'GET', redirect: followRedirects ? 'follow' : 'manual', signal: ctrl.signal,
      headers: { 'user-agent': `header-sentinel/${VERSION}`, ...headers },
    });
    res.body?.cancel?.().catch(() => {});
    const r = analyze({ url: res.url || url, headers: res.headers }, config);
    return { ...r, requestedUrl: url, status: res.status };
  } catch (e) {
    const msg = e.name === 'AbortError' ? `timed out after ${timeout}ms` : (e.cause?.message || e.message);
    return { url, requestedUrl: url, status: 0, error: msg, score: 0, grade: 'F',
      findings: [{ id: 'fetch', severity: 'error', title: 'Request failed', message: msg, fix: 'Check that the URL is reachable from CI and increase --timeout if needed.' }] };
  } finally { clearTimeout(t); }
}

export async function scanAll(urls, opts = {}) {
  return Promise.all(urls.map(u => scan(u, opts)));
}

export function shouldFail(results, failOn = 'error') {
  const lv = failOn === 'warn' ? ['error', 'warn'] : failOn === 'none' ? [] : ['error'];
  return results.some(r => r.findings.some(f => lv.includes(f.severity)));
}
