/** @type {Map<string, Promise<boolean>>} */
const cache = new Map();

/**
 * Query hstspreload.org for preload status (no API key; zero deps).
 * @param {string} hostname
 * @param {{ timeout?: number }} [opts]
 */
export async function isDomainPreloaded(hostname, opts = {}) {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  if (!host) return false;
  if (cache.has(host)) return cache.get(host);

  const p = (async () => {
    const timeout = opts.timeout ?? 8000;
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeout);
    try {
      const res = await fetch(`https://hstspreload.org/api/v2/status?domain=${encodeURIComponent(host)}`, {
        signal: ctrl.signal,
        headers: { accept: 'application/json', 'user-agent': 'header-sentinel/preload-check' },
      });
      if (!res.ok) return false;
      const body = /** @type {{ status?: string }} */ (await res.json());
      return body.status === 'preloaded';
    } catch {
      return false;
    } finally {
      clearTimeout(t);
    }
  })();

  cache.set(host, p);
  return p;
}

/**
 * Whether the HSTS response header meets Chromium preload submission requirements.
 * @param {string | null | undefined} hsts
 */
export function hstsPreloadEligible(hsts) {
  if (!hsts) return false;
  const m = /max-age\s*=\s*"?(\d+)/i.exec(hsts);
  const maxAge = m ? Number(m[1]) : 0;
  return maxAge >= 31536000 && /includesubdomains/i.test(hsts) && /\bpreload\b/i.test(hsts);
}
