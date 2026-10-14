/**
 * Extract absolute http(s) URLs from a sitemap or sitemap index document.
 * @param {string} xml
 * @param {string} baseUrl
 */
export function parseSitemapDocument(xml, baseUrl) {
  const urls = [];
  const locRe = /<loc>\s*([^<\s]+)\s*<\/loc>/gi;
  let m;
  while ((m = locRe.exec(xml)) !== null) {
    try {
      const href = new URL(m[1].trim(), baseUrl).href;
      if (/^https?:\/\//i.test(href)) urls.push(href);
    } catch { /* skip invalid */ }
  }
  return [...new Set(urls)];
}

/**
 * @param {string} sitemapUrl
 * @param {{ timeout?: number; headers?: Record<string, string>; maxUrls?: number }} [opts]
 */
export async function fetchSitemapUrls(sitemapUrl, opts = {}) {
  const { timeout = 15000, headers = {}, maxUrls = 500 } = opts;
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeout);
  try {
    const res = await fetch(sitemapUrl, {
      signal: ctrl.signal,
      headers: { 'user-agent': 'header-sentinel/sitemap', accept: 'application/xml,text/xml,*/*', ...headers },
    });
    const text = await res.text();
    const base = new URL(sitemapUrl).href;
    let urls = parseSitemapDocument(text, base);

    const childSitemaps = urls.filter((u) => /\.xml(\?|$)/i.test(u));
    if (/<sitemapindex/i.test(text) && childSitemaps.length) {
      urls = [];
      for (const child of childSitemaps.slice(0, 20)) {
        if (urls.length >= maxUrls) break;
        const sub = await fetchSitemapUrls(child, { ...opts, maxUrls: maxUrls - urls.length });
        urls.push(...sub);
      }
    }

    return [...new Set(urls.filter((u) => !/\.xml(\?|$)/i.test(u)))].slice(0, maxUrls);
  } finally {
    clearTimeout(t);
  }
}
