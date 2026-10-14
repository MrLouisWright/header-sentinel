/** @typedef {{ id: string; pass: boolean; result: string; scoreModifier: number; description: string }} ObservatoryTest */

export const MINIMUM_SCORE_FOR_EXTRA_CREDIT = 90;

export const GRADE_CHART = {
  100: 'A+',
  95: 'A',
  90: 'A',
  85: 'A-',
  80: 'B+',
  75: 'B',
  70: 'B',
  65: 'B-',
  60: 'C+',
  55: 'C',
  50: 'C',
  45: 'C-',
  40: 'D+',
  35: 'D',
  30: 'D',
  25: 'D-',
  20: 'F',
  15: 'F',
  10: 'F',
  5: 'F',
  0: 'F',
};

export const LIKELIHOOD_INDICATOR_CHART = { A: 'LOW', B: 'MEDIUM', C: 'MEDIUM', D: 'MEDIUM', F: 'MEDIUM' };

/** Mozilla HTTP Observatory score modifiers (subset aligned with header-sentinel scope). */
export const SCORE_TABLE = {
  'csp-implemented-with-no-unsafe-default-src-none': { description: "CSP with default-src 'none' and no 'unsafe'", modifier: 10 },
  'csp-implemented-with-no-unsafe': { description: "CSP without 'unsafe-inline' or 'unsafe-eval' in active content", modifier: 5 },
  'csp-implemented-with-unsafe-inline-in-style-src-only': { description: 'CSP allows unsafe sources only in style-src', modifier: 0 },
  'csp-implemented-with-insecure-scheme-in-passive-content-only': { description: 'CSP allows HTTP in passive content only', modifier: -10 },
  'csp-implemented-with-unsafe-eval': { description: "CSP allows 'unsafe-eval'", modifier: -10 },
  'csp-implemented-with-unsafe-inline': { description: 'CSP implemented unsafely (unsafe-inline in script, broad sources, etc.)', modifier: -20 },
  'csp-implemented-with-insecure-scheme': { description: 'HTTPS site allows active content over HTTP in CSP', modifier: -20 },
  'csp-header-invalid': { description: 'CSP header cannot be parsed', modifier: -25 },
  'csp-not-implemented': { description: 'Content-Security-Policy not implemented', modifier: -25 },
  'cookies-not-found': { description: 'No cookies detected (use cookie-sentinel for Set-Cookie audits)', modifier: 0 },
  'cookies-present': { description: 'Set-Cookie present; detailed cookie scoring is not performed here', modifier: 0 },
  'redirection-all-redirects-preloaded': { description: 'All HTTP redirect hosts are HSTS preloaded', modifier: 0 },
  'redirection-to-https': { description: 'HTTP redirects to HTTPS on the same host', modifier: 0 },
  'redirection-not-needed-no-http': { description: 'Site does not accept plain HTTP', modifier: 0 },
  'redirection-off-host-from-http': { description: 'Initial HTTP redirect goes to a different host', modifier: -5 },
  'redirection-not-to-https-on-initial-redirection': { description: 'First redirect from HTTP is not to HTTPS', modifier: -10 },
  'redirection-not-to-https': { description: 'HTTP redirect chain does not end on HTTPS', modifier: -20 },
  'redirection-missing': { description: 'HTTP URL does not redirect to HTTPS', modifier: -20 },
  'referrer-policy-private': { description: 'Referrer-Policy is no-referrer, same-origin, strict-origin, or strict-origin-when-cross-origin', modifier: 5 },
  'referrer-policy-no-referrer-when-downgrade': { description: 'Referrer-Policy is no-referrer-when-downgrade', modifier: 0 },
  'referrer-policy-not-implemented': { description: 'Referrer-Policy not implemented', modifier: 0 },
  'referrer-policy-unsafe': { description: 'Referrer-Policy is origin, origin-when-cross-origin, or unsafe-url', modifier: -5 },
  'referrer-policy-header-invalid': { description: 'Referrer-Policy cannot be recognized', modifier: -5 },
  'hsts-preloaded': { description: 'Domain is on the HSTS preload list', modifier: 5 },
  'hsts-preload-ready': { description: 'HSTS header meets preload submission requirements', modifier: 0 },
  'hsts-implemented-max-age-at-least-six-months': { description: 'HSTS max-age at least six months (15768000)', modifier: 0 },
  'hsts-implemented-max-age-less-than-six-months': { description: 'HSTS max-age under six months', modifier: -10 },
  'hsts-not-implemented': { description: 'Strict-Transport-Security not implemented on HTTPS', modifier: -20 },
  'hsts-header-invalid': { description: 'HSTS header cannot be recognized', modifier: -20 },
  'hsts-not-implemented-no-https': { description: 'HSTS cannot be set without HTTPS', modifier: -20 },
  'x-content-type-options-nosniff': { description: 'X-Content-Type-Options is nosniff', modifier: 0 },
  'x-content-type-options-not-implemented': { description: 'X-Content-Type-Options not implemented', modifier: -5 },
  'x-content-type-options-header-invalid': { description: 'X-Content-Type-Options invalid', modifier: -5 },
  'x-frame-options-implemented-via-csp': { description: 'Clickjacking protection via CSP frame-ancestors', modifier: 5 },
  'x-frame-options-sameorigin-or-deny': { description: 'X-Frame-Options is SAMEORIGIN or DENY', modifier: 0 },
  'x-frame-options-not-implemented': { description: 'X-Frame-Options / frame-ancestors missing', modifier: -20 },
  'x-frame-options-header-invalid': { description: 'X-Frame-Options invalid', modifier: -20 },
  'x-xss-protection-disabled': { description: 'X-XSS-Protection disabled or absent', modifier: 0 },
  'x-xss-protection-header-invalid': { description: 'X-XSS-Protection unrecognized', modifier: -5 },
  'fetch-failed': { description: 'Could not fetch the URL', modifier: -20 },
};

/**
 * @param {number} score
 * @returns {string}
 */
export function gradeFromScore(score) {
  const s = Math.max(0, score);
  const bucket = Math.min(s - (s % 5), 100);
  return GRADE_CHART[bucket] ?? 'F';
}

/**
 * @param {string} grade
 * @returns {string}
 */
export function likelihoodFromGrade(grade) {
  return LIKELIHOOD_INDICATOR_CHART[grade[0]] ?? 'UNKNOWN';
}

/**
 * Compute Mozilla Observatory-style score from test result keys.
 * @param {string[]} results
 */
export function computeObservatoryScore(results) {
  let score = 100;
  let bonus = 0;
  for (const result of results) {
    const row = SCORE_TABLE[result];
    if (!row) continue;
    const m = row.modifier;
    if (m < 0) score += m;
    else if (m > 0) bonus += m;
  }
  if (score >= MINIMUM_SCORE_FOR_EXTRA_CREDIT) score += bonus;
  score = Math.max(0, score);
  const grade = gradeFromScore(score);
  return { score, grade, likelihoodIndicator: likelihoodFromGrade(grade) };
}

/**
 * @param {string} result
 */
export function describeObservatoryResult(result) {
  return SCORE_TABLE[result]?.description ?? result;
}

/** @deprecated use gradeFromScore */
export function grade(score) {
  return gradeFromScore(score);
}
