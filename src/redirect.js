/**
 * Follow redirects manually and record the chain (no TLS inspection).
 * @param {string} url
 * @param {{ timeout?: number; headers?: Record<string, string>; maxHops?: number }} opts
 */
export async function followRedirectChain(url, opts = {}) {
  const { timeout = 10000, headers = {}, maxHops = 15 } = opts;
  const route = [url];
  let current = url;
  let status = 0;
  let responseHeaders = new Headers();

  for (let hop = 0; hop < maxHops; hop++) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeout);
    try {
      const res = await fetch(current, {
        method: 'GET',
        redirect: 'manual',
        signal: ctrl.signal,
        headers: { 'user-agent': 'header-sentinel/redirect-trace', ...headers },
      });
      status = res.status;
      responseHeaders = res.headers;
      res.body?.cancel?.().catch(() => {});

      if (res.status >= 300 && res.status < 400) {
        const loc = res.headers.get('location');
        if (!loc) break;
        current = new URL(loc, current).href;
        route.push(current);
        continue;
      }
      return { finalUrl: current, route, status, headers: responseHeaders };
    } catch (e) {
      return { finalUrl: current, route, status, headers: responseHeaders, error: e instanceof Error ? e.message : String(e) };
    } finally {
      clearTimeout(t);
    }
  }
  return { finalUrl: current, route, status, headers: responseHeaders, error: 'too many redirects' };
}

/**
 * Mozilla Observatory-style HTTP→HTTPS redirection test for an HTTPS site.
 * @param {string} httpsUrl
 * @param {{ timeout?: number; headers?: Record<string, string>; isPreloaded?: (host: string) => Promise<boolean> }} opts
 */
export async function analyzeHttpRedirection(httpsUrl, opts = {}) {
  let parsed;
  try {
    parsed = new URL(httpsUrl);
  } catch {
    return { result: 'redirection-not-needed-no-http', route: [], destination: httpsUrl, pass: true };
  }
  if (parsed.protocol !== 'https:') {
    return { result: 'redirection-not-needed-no-http', route: [], destination: httpsUrl, pass: true };
  }

  const httpUrl = `http://${parsed.host}${parsed.pathname}${parsed.search}`;
  const chain = await followRedirectChain(httpUrl, opts);
  const route = chain.route.map((u) => {
    try {
      return new URL(u);
    } catch {
      return null;
    }
  }).filter(Boolean);

  if (chain.error && route.length <= 1) {
    return { result: 'redirection-not-needed-no-http', route: chain.route, destination: chain.finalUrl, pass: true };
  }

  let result = 'redirection-to-https';
  if (route.length === 1 && route[0]?.protocol === 'http:') result = 'redirection-missing';
  else if (route.length && route[route.length - 1]?.protocol !== 'https:') result = 'redirection-not-to-https';
  else if (route.length >= 2 && route[1]?.protocol === 'http:') result = 'redirection-not-to-https-on-initial-redirection';
  else if (route.length >= 2 && route[0]?.protocol === 'http:' && route[1]?.protocol === 'https:' && route[0].hostname !== route[1].hostname) {
    result = 'redirection-off-host-from-http';
  }

  if (opts.isPreloaded && route.length) {
    const hosts = [...new Set(route.map((u) => u.hostname))];
    const preloaded = await Promise.all(hosts.map((h) => opts.isPreloaded(h)));
    if (preloaded.every(Boolean)) result = 'redirection-all-redirects-preloaded';
  }

  const pass = ['redirection-to-https', 'redirection-not-needed-no-http', 'redirection-all-redirects-preloaded'].includes(result);
  return { result, route: chain.route, destination: chain.finalUrl, status: chain.status, pass };
}
