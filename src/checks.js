// Each check: (ctx) => Finding[] ; ctx = { url, headers: Headers, setCookies: string[], isHttps }
const H = (ctx, n) => ctx.headers.get(n);
const f = (id, severity, title, message, fix) => ({ id, severity, title, message, fix });

export const CHECKS = {
  hsts(ctx) {
    if (!ctx.isHttps) return [];
    const v = H(ctx, 'strict-transport-security');
    const fix = 'Add: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload\n' +
      '  Nginx:   add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;\n' +
      '  Express: app.use(helmet.hsts({ maxAge: 63072000, includeSubDomains: true, preload: true }))\n' +
      '  Vercel/Netlify: set in vercel.json "headers" / netlify.toml [[headers]]';
    if (!v) return [f('hsts', 'error', 'Strict-Transport-Security missing', 'HTTPS response has no HSTS header; browsers may be downgraded to HTTP.', fix)];
    const out = [];
    const m = /max-age\s*=\s*"?(\d+)/i.exec(v);
    if (!m || Number(m[1]) < 31536000) out.push(f('hsts', 'error', 'HSTS max-age too short', `max-age is ${m ? m[1] : 'missing'}; must be >= 31536000 (1 year).`, fix));
    if (!/includesubdomains/i.test(v)) out.push(f('hsts-subdomains', 'warn', 'HSTS without includeSubDomains', 'Subdomains are not covered by HSTS.', fix));
    return out;
  },

  csp(ctx) {
    const v = H(ctx, 'content-security-policy');
    const ex = "Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; script-src 'self'";
    const hint = `Example: ${ex}\n  Nginx:   add_header Content-Security-Policy "..." always;\n  Express: app.use(helmet.contentSecurityPolicy({ directives: {...} }))\n  Vercel/Netlify: headers config; Next.js: headers() in next.config.js`;
    if (!v) return [f('csp', 'error', 'Content-Security-Policy missing', 'No CSP header; XSS impact is not mitigated.', hint)];
    const dirs = {};
    for (const part of v.split(';')) {
      const [name, ...vals] = part.trim().split(/\s+/);
      if (name) dirs[name.toLowerCase()] = vals;
    }
    const out = [];
    const all = Object.entries(dirs);
    for (const [d, vals] of all) {
      if (d.endsWith('-src') || d === 'default-src') {
        if (vals.includes("'unsafe-inline'") && !vals.some(x => /^'(nonce-|sha(256|384|512)-|strict-dynamic)/.test(x)))
          out.push(f('csp-unsafe-inline', 'warn', `CSP ${d} allows 'unsafe-inline'`, `'unsafe-inline' in ${d} defeats XSS protection.`, "Replace 'unsafe-inline' with nonces ('nonce-<random>') or hashes ('sha256-...')."));
        if (vals.includes("'unsafe-eval'"))
          out.push(f('csp-unsafe-eval', 'warn', `CSP ${d} allows 'unsafe-eval'`, `'unsafe-eval' in ${d} allows eval()-style code execution.`, "Remove 'unsafe-eval'; refactor code that uses eval/new Function."));
        const wild = vals.filter(x => x === '*' || x === 'http:' || x === 'https:' || x === 'data:' && /script|default/.test(d));
        if (wild.length) out.push(f('csp-wildcard', 'warn', `CSP ${d} uses overly broad source ${wild.join(' ')}`, `${d} allows loading from any origin.`, `List explicit origins instead, e.g. ${d} 'self' https://cdn.example.com`));
      }
    }
    for (const d of ['default-src', 'object-src', 'base-uri', 'frame-ancestors']) {
      if (d === 'object-src' && dirs['default-src']?.includes("'none'")) continue;
      if (!dirs[d]) out.push(f(`csp-missing-${d}`, 'warn', `CSP missing ${d}`, `${d} directive is not set${d === 'base-uri' || d === 'frame-ancestors' ? ' (not covered by default-src)' : ''}.`, `Add "${d} ${d === 'object-src' ? "'none'" : "'self'"}" to your CSP.`));
    }
    return out;
  },

  'frame-options'(ctx) {
    const xfo = H(ctx, 'x-frame-options');
    const csp = H(ctx, 'content-security-policy') || '';
    if (/frame-ancestors/i.test(csp)) return [];
    const fix = "Add: X-Frame-Options: DENY (or SAMEORIGIN), or CSP frame-ancestors 'self'\n  Nginx: add_header X-Frame-Options \"DENY\" always;  Express: helmet.frameguard({ action: 'deny' })";
    if (!xfo) return [f('frame-options', 'error', 'Clickjacking protection missing', 'Neither X-Frame-Options nor CSP frame-ancestors is set.', fix)];
    if (!/^(deny|sameorigin)$/i.test(xfo.trim())) return [f('frame-options', 'error', 'Invalid X-Frame-Options', `Value "${xfo}" is not DENY or SAMEORIGIN (ALLOW-FROM is obsolete).`, fix)];
    return [];
  },

  'content-type-options'(ctx) {
    const v = H(ctx, 'x-content-type-options');
    if (v && v.trim().toLowerCase() === 'nosniff') return [];
    return [f('content-type-options', 'error', v ? 'Invalid X-Content-Type-Options' : 'X-Content-Type-Options missing', v ? `Value "${v}" must be "nosniff".` : 'MIME sniffing is not disabled.',
      'Add: X-Content-Type-Options: nosniff\n  Nginx: add_header X-Content-Type-Options "nosniff" always;  Express: helmet.noSniff()')];
  },

  'referrer-policy'(ctx) {
    const v = H(ctx, 'referrer-policy');
    const safe = ['no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin', 'origin', 'origin-when-cross-origin', 'no-referrer-when-downgrade'];
    const good = ['no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin'];
    const fix = 'Add: Referrer-Policy: strict-origin-when-cross-origin\n  Nginx: add_header Referrer-Policy "strict-origin-when-cross-origin" always;  Express: helmet.referrerPolicy({ policy: "strict-origin-when-cross-origin" })';
    if (!v) return [f('referrer-policy', 'warn', 'Referrer-Policy missing', 'Browser default applies; set an explicit policy.', fix)];
    // multiple values allowed as fallback list; last valid one wins
    const vals = v.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
    const eff = [...vals].reverse().find(x => safe.includes(x) || x === 'unsafe-url');
    if (!eff) return [f('referrer-policy', 'error', 'Invalid Referrer-Policy', `"${v}" is not a valid policy.`, fix)];
    if (!good.includes(eff)) return [f('referrer-policy', eff === 'unsafe-url' ? 'error' : 'warn', 'Weak Referrer-Policy', `"${eff}" may leak full URLs or paths to third parties.`, fix)];
    return [];
  },

  'permissions-policy'(ctx) {
    if (H(ctx, 'permissions-policy')) return [];
    return [f('permissions-policy', 'warn', 'Permissions-Policy missing', 'Powerful browser features (camera, geolocation...) are not restricted.',
      'Add: Permissions-Policy: camera=(), microphone=(), geolocation=(), interest-cohort=()\n  Nginx: add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;')];
  },

  coop(ctx) {
    const v = H(ctx, 'cross-origin-opener-policy');
    const fix = 'Add: Cross-Origin-Opener-Policy: same-origin (or same-origin-allow-popups if you rely on OAuth popups)';
    if (!v) return [f('coop', 'warn', 'Cross-Origin-Opener-Policy missing', 'Window is not isolated from cross-origin openers (XS-Leaks/Spectre).', fix)];
    if (!/^(same-origin|same-origin-allow-popups|noopener-allow-popups)$/i.test(v.trim())) return [f('coop', 'warn', 'Weak Cross-Origin-Opener-Policy', `Value "${v}" provides no isolation.`, fix)];
    return [];
  },

  'info-leak'(ctx) {
    const out = [];
    const server = H(ctx, 'server');
    if (server && /\d/.test(server)) out.push(f('info-leak-server', 'warn', 'Server header discloses version', `Server: ${server}`,
      'Hide version.\n  Nginx: server_tokens off;  Apache: ServerTokens Prod'));
    for (const n of ['x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version']) {
      const v = H(ctx, n);
      if (v) out.push(f('info-leak-powered-by', 'warn', `${n} header discloses technology`, `${n}: ${v}`,
        'Remove it.\n  Express: app.disable("x-powered-by")  PHP: expose_php = Off  Next.js: poweredByHeader: false'));
    }
    return out;
  },

  cookies(ctx) {
    const out = [];
    for (const c of ctx.setCookies) {
      const [nv, ...attrs] = c.split(';').map(s => s.trim());
      const name = nv.split('=')[0];
      const a = attrs.map(x => x.toLowerCase());
      const missing = [];
      if (ctx.isHttps && !a.includes('secure')) missing.push('Secure');
      if (!a.includes('httponly')) missing.push('HttpOnly');
      const ss = a.find(x => x.startsWith('samesite'));
      if (!ss) missing.push('SameSite');
      if (missing.length) out.push(f('cookies', missing.includes('Secure') ? 'error' : 'warn', `Cookie "${name}" missing ${missing.join(', ')}`, `Set-Cookie: ${c.slice(0, 120)}`,
        `Example: Set-Cookie: ${name}=...; Path=/; Secure; HttpOnly; SameSite=Lax\n  Express: res.cookie(name, v, { secure: true, httpOnly: true, sameSite: "lax" })  (omit HttpOnly only if JS must read it)`));
      if (ss && /samesite\s*=\s*none/.test(ss) && !a.includes('secure')) out.push(f('cookies', 'error', `Cookie "${name}" SameSite=None without Secure`, 'Browsers reject SameSite=None cookies without Secure.', 'Add the Secure attribute.'));
    }
    return out;
  },

  'x-xss-protection'(ctx) {
    const v = H(ctx, 'x-xss-protection');
    if (v == null || v.trim() === '0') return [];
    return [f('x-xss-protection', 'warn', 'Deprecated X-XSS-Protection enabled', `Value "${v}" can introduce XS-Leak vulnerabilities in legacy browsers.`,
      'Set X-XSS-Protection: 0 (or remove it) and rely on CSP.  Express: helmet.xXssProtection()')];
  },
};
