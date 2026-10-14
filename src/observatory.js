import { describeObservatoryResult, computeObservatoryScore, SCORE_TABLE } from './scoring.js';
import { hstsPreloadEligible } from './preload.js';

const H = (ctx, n) => ctx.headers.get(n);

/** @type {Record<string, boolean>} */
const SCORE_TABLE_PASS = {
  'csp-implemented-with-no-unsafe': true,
  'csp-implemented-with-no-unsafe-default-src-none': true,
  'csp-implemented-with-unsafe-inline-in-style-src-only': true,
  'csp-implemented-with-insecure-scheme-in-passive-content-only': true,
  'cookies-not-found': true,
  'cookies-present': true,
  'redirection-to-https': true,
  'redirection-not-needed-no-http': true,
  'redirection-all-redirects-preloaded': true,
  'referrer-policy-private': true,
  'referrer-policy-no-referrer-when-downgrade': true,
  'referrer-policy-not-implemented': true,
  'hsts-preloaded': true,
  'hsts-preload-ready': true,
  'hsts-implemented-max-age-at-least-six-months': true,
  'x-content-type-options-nosniff': true,
  'x-frame-options-implemented-via-csp': true,
  'x-frame-options-sameorigin-or-deny': true,
  'x-xss-protection-disabled': true,
};

/**
 * @param {import('./index.js').CheckContext} ctx
 */
function evaluateCspResult(ctx) {
  const raw = H(ctx, 'content-security-policy');
  if (!raw || raw.trim().length < 6) return 'csp-not-implemented';

  const dirs = {};
  try {
    for (const part of raw.split(';')) {
      const trimmed = part.trim();
      if (!trimmed) continue;
      const [name, ...vals] = trimmed.split(/\s+/);
      if (!name) continue;
      const key = name.toLowerCase();
      if (dirs[key]) return 'csp-header-invalid';
      dirs[key] = vals.map((v) => v.toLowerCase());
    }
  } catch {
    return 'csp-header-invalid';
  }

  const dangerous = new Set(['*', 'http:', 'https:', 'ftp:', 'http://*', 'https://*']);
  const unsafeInline = new Set(["'unsafe-inline'", 'data:']);
  const nonces = (vals) => vals.some((x) => /^'(nonce-|sha(256|384|512)-)/.test(x));

  const scriptSrc = dirs['script-src'] || dirs['default-src'] || ['*'];
  const styleSrc = dirs['style-src'] || dirs['default-src'] || ['*'];
  const objectSrc = dirs['object-src'] || dirs['default-src'] || ['*'];

  let result = null;

  const script = [...scriptSrc];
  const style = [...styleSrc];
  if (nonces(script) && script.includes("'unsafe-inline'")) script.splice(script.indexOf("'unsafe-inline'"), 1);
  if (nonces(style) && style.includes("'unsafe-inline'")) style.splice(style.indexOf("'unsafe-inline'"), 1);

  if (script.some((s) => dangerous.has(s) || unsafeInline.has(s)) || objectSrc.some((s) => dangerous.has(s))) {
    result = 'csp-implemented-with-unsafe-inline';
  }

  if (ctx.isHttps) {
    const active = Object.entries(dirs).flatMap(([d, vals]) => (d.endsWith('-src') && !['img-src', 'media-src'].includes(d) ? vals : [])).concat(script);
    if (active.some((s) => s.includes('http:') || s.includes('ftp:'))) {
      result = result ?? 'csp-implemented-with-insecure-scheme';
    }
    const passive = [...(dirs['img-src'] || dirs['default-src'] || []), ...(dirs['media-src'] || dirs['default-src'] || [])];
    if (passive.some((s) => s.includes('http:') || s.includes('ftp:'))) {
      result = result ?? 'csp-implemented-with-insecure-scheme-in-passive-content-only';
    }
  }

  if (script.includes("'unsafe-eval'") || style.includes("'unsafe-eval'")) {
    result = result ?? 'csp-implemented-with-unsafe-eval';
  }

  if (style.some((s) => dangerous.has(s) || unsafeInline.has(s))) {
    result = result ?? 'csp-implemented-with-unsafe-inline-in-style-src-only';
  }

  if (dirs['default-src']?.length === 1 && dirs['default-src'][0] === "'none'") {
    result = result ?? 'csp-implemented-with-no-unsafe-default-src-none';
  } else if (!result) {
    result = 'csp-implemented-with-no-unsafe';
  }

  return result;
}

/**
 * @param {import('./index.js').CheckContext} ctx
 */
function evaluateHstsResult(ctx) {
  if (!ctx.isHttps) return 'hsts-not-implemented-no-https';
  const v = H(ctx, 'strict-transport-security');
  if (!v) return 'hsts-not-implemented';
  const m = /max-age\s*=\s*"?(\d+)/i.exec(v);
  if (!m) return 'hsts-header-invalid';
  const age = Number(m[1]);
  if (age < 15768000) return 'hsts-implemented-max-age-less-than-six-months';
  return 'hsts-implemented-max-age-at-least-six-months';
}

/**
 * @param {import('./index.js').CheckContext} ctx
 */
function evaluateReferrerResult(ctx) {
  const v = H(ctx, 'referrer-policy');
  const safe = ['no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin'];
  const ok = ['no-referrer-when-downgrade'];
  const weak = ['origin', 'origin-when-cross-origin', 'unsafe-url'];
  if (!v) return 'referrer-policy-not-implemented';
  const vals = v.split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  const eff = [...vals].reverse().find((x) => safe.includes(x) || ok.includes(x) || weak.includes(x));
  if (!eff) return 'referrer-policy-header-invalid';
  if (safe.includes(eff)) return 'referrer-policy-private';
  if (ok.includes(eff)) return 'referrer-policy-no-referrer-when-downgrade';
  return 'referrer-policy-unsafe';
}

/**
 * @param {import('./index.js').CheckContext} ctx
 */
function evaluateFrameResult(ctx) {
  const csp = H(ctx, 'content-security-policy') || '';
  if (/frame-ancestors/i.test(csp)) return 'x-frame-options-implemented-via-csp';
  const xfo = H(ctx, 'x-frame-options');
  if (!xfo) return 'x-frame-options-not-implemented';
  if (/^(deny|sameorigin)$/i.test(xfo.trim())) return 'x-frame-options-sameorigin-or-deny';
  return 'x-frame-options-header-invalid';
}

/**
 * @param {import('./index.js').CheckContext} ctx
 */
function evaluateXContentType(ctx) {
  const v = H(ctx, 'x-content-type-options');
  if (!v) return 'x-content-type-options-not-implemented';
  if (v.trim().toLowerCase() === 'nosniff') return 'x-content-type-options-nosniff';
  return 'x-content-type-options-header-invalid';
}

/**
 * @param {import('./index.js').CheckContext} ctx
 */
function evaluateXssProtection(ctx) {
  const v = H(ctx, 'x-xss-protection');
  if (v == null || v.trim() === '' || v.trim() === '0') return 'x-xss-protection-disabled';
  if (!/^1(\s*;\s*mode=block)?$/i.test(v.trim())) return 'x-xss-protection-header-invalid';
  return 'x-xss-protection-disabled';
}

/**
 * @param {import('./index.js').CheckContext} ctx
 */
function evaluateCookiesResult(ctx) {
  if (!ctx.setCookies?.length) return 'cookies-not-found';
  return 'cookies-present';
}

/**
 * @param {import('./index.js').CheckContext} ctx
 * @param {{ redirectionResult?: string; hstsPreloaded?: boolean }} extras
 */
export function evaluateObservatoryTests(ctx, extras = {}) {
  /** @type {string[]} */
  const results = [
    evaluateCspResult(ctx),
    evaluateCookiesResult(ctx),
    evaluateReferrerResult(ctx),
    ...(ctx.isHttps ? [evaluateHstsResult(ctx)] : []),
    evaluateFrameResult(ctx),
    evaluateXContentType(ctx),
    evaluateXssProtection(ctx),
  ];

  if (extras.redirectionResult) results.push(extras.redirectionResult);
  if (extras.hstsPreloaded) results.push('hsts-preloaded');
  else if (ctx.isHttps && hstsPreloadEligible(H(ctx, 'strict-transport-security'))) results.push('hsts-preload-ready');

  return results;
}

/**
 * @param {import('./index.js').CheckContext} ctx
 * @param {{ redirectionResult?: string; hstsPreloaded?: boolean }} extras
 */
export function evaluateObservatory(ctx, extras = {}) {
  const results = evaluateObservatoryTests(ctx, extras);
  const { score, grade, likelihoodIndicator } = computeObservatoryScore(results);
  const tests = results.map((result) => {
    const scoreModifier = SCORE_TABLE[result]?.modifier ?? 0;
    return {
      result,
      pass: SCORE_TABLE_PASS[result] ?? scoreModifier >= 0,
      scoreModifier,
      description: describeObservatoryResult(result),
    };
  });
  const testsFailed = tests.filter((t) => !t.pass).length;
  return {
    score,
    grade,
    likelihoodIndicator,
    tests,
    testsPassed: tests.length - testsFailed,
    testsFailed,
    testsQuantity: tests.length,
  };
}
