import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { writeFileSync, mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { scan, analyze, shouldFail, toSarif, diffAgainstBaseline, baselineFromResults, parseSitemapDocument } from '../src/index.js';

const GOOD = {
  'Content-Security-Policy': "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
};
let server, base;
const routes = {};
before(async () => {
  server = http.createServer((req, res) => {
    const r = routes[req.url] || { headers: {} };
    if (r.redirect) { res.writeHead(302, { Location: r.redirect }); return res.end(); }
    if (r.delay) return setTimeout(() => res.end('slow'), r.delay);
    for (const [k, v] of Object.entries(r.headers)) res.setHeader(k, v);
    if (req.headers['authorization'] && req.headers['authorization'] !== 'Bearer t0k') { res.statusCode = 500; }
    if (req.url === '/auth' && !req.headers['authorization']) { res.statusCode = 401; }
    res.end('ok');
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => server.close());
const route = (path, headers, extra = {}) => { routes[path] = { headers, ...extra }; return base + path; };
const ids = (r) => r.findings.map(f => f.id);
const hs = (h) => analyze({ url: 'https://x.test/', headers: h });

test('fully hardened response passes over http', async () => {
  const r = await scan(route('/good', GOOD));
  assert.deepEqual(r.findings, []); assert.equal(r.grade, 'A+'); assert.equal(shouldFail([r], 'warn'), false);
});
test('missing everything is an error', async () => {
  const r = await scan(route('/bare', {}));
  for (const id of ['csp', 'frame-options', 'content-type-options', 'referrer-policy', 'permissions-policy', 'coop']) assert.ok(ids(r).includes(id), id);
  assert.equal(shouldFail([r]), true);
  assert.ok(r.findings.every(f => f.fix && f.fix.length > 10));
});
test('HSTS: missing on https, short max-age, no includeSubDomains', () => {
  assert.ok(ids(hs(GOOD)).includes('hsts'));
  const short = hs({ ...GOOD, 'Strict-Transport-Security': 'max-age=300; includeSubDomains' });
  assert.equal(short.findings[0].id, 'hsts'); assert.match(short.findings[0].message, /300/);
  assert.deepEqual(ids(hs({ ...GOOD, 'Strict-Transport-Security': 'max-age=31536000' })), ['hsts-subdomains']);
  assert.deepEqual(ids(hs({ ...GOOD, 'Strict-Transport-Security': 'max-age=63072000; includeSubDomains' })), []);
});
test('HSTS not required on plain http', async () => {
  assert.ok(!ids(await scan(route('/h', GOOD))).includes('hsts'));
});
test('CSP: unsafe-inline, unsafe-eval, wildcard, missing directives', async () => {
  const r = await scan(route('/csp', { ...GOOD, 'Content-Security-Policy': "script-src 'self' 'unsafe-inline' 'unsafe-eval' *" }));
  for (const id of ['csp-unsafe-inline', 'csp-unsafe-eval', 'csp-wildcard', 'csp-missing-default-src', 'csp-missing-object-src', 'csp-missing-base-uri', 'csp-missing-frame-ancestors']) assert.ok(ids(r).includes(id), id);
  // frame-ancestors missing -> XFO required
  assert.ok(ids(r).includes('frame-options'));
});
test('CSP: unsafe-inline with nonce is tolerated', () => {
  const r = hs({ ...GOOD, 'Strict-Transport-Security': 'max-age=63072000; includeSubDomains', 'Content-Security-Policy': GOOD['Content-Security-Policy'] + "; script-src 'nonce-abc' 'unsafe-inline'" });
  assert.deepEqual(ids(r), []);
});
test('X-Frame-Options accepted instead of frame-ancestors; invalid value flagged', async () => {
  const csp = "default-src 'self'; object-src 'none'; base-uri 'self'";
  const ok = await scan(route('/xfo', { ...GOOD, 'Content-Security-Policy': csp, 'X-Frame-Options': 'SAMEORIGIN' }));
  assert.ok(!ids(ok).includes('frame-options'));
  const bad = await scan(route('/xfo2', { ...GOOD, 'Content-Security-Policy': csp, 'X-Frame-Options': 'ALLOW-FROM https://a' }));
  assert.ok(ids(bad).includes('frame-options'));
});
test('X-Content-Type-Options must be nosniff', async () => {
  const r = await scan(route('/xcto', { ...GOOD, 'X-Content-Type-Options': 'yes' }));
  assert.deepEqual(ids(r), ['content-type-options']);
});
test('Referrer-Policy: invalid, unsafe-url, weak', () => {
  assert.equal(hs({ ...GOOD, 'Referrer-Policy': 'bogus' }).findings.find(f => f.id === 'referrer-policy').severity, 'error');
  assert.equal(hs({ ...GOOD, 'Referrer-Policy': 'unsafe-url' }).findings.find(f => f.id === 'referrer-policy').severity, 'error');
  assert.equal(hs({ ...GOOD, 'Referrer-Policy': 'no-referrer-when-downgrade' }).findings.find(f => f.id === 'referrer-policy').severity, 'warn');
  assert.ok(!ids(hs({ ...GOOD, 'Referrer-Policy': 'no-referrer, strict-origin-when-cross-origin' })).includes('referrer-policy'));
});
test('Permissions-Policy and COOP', () => {
  const { 'Permissions-Policy': _, ...noPP } = GOOD;
  assert.ok(ids(hs(noPP)).includes('permissions-policy'));
  assert.ok(ids(hs({ ...GOOD, 'Cross-Origin-Opener-Policy': 'unsafe-none' })).includes('coop'));
});
test('information leaks: Server version and X-Powered-By', async () => {
  const r = await scan(route('/leak', { ...GOOD, Server: 'nginx/1.18.0', 'X-Powered-By': 'Express' }));
  assert.deepEqual(ids(r).sort(), ['info-leak-powered-by', 'info-leak-server']);
  assert.ok(!ids(await scan(route('/leak2', { ...GOOD, Server: 'nginx' }))).includes('info-leak-server'));
});
test('cookies: minimal presence check points to cookie-sentinel', async () => {
  const r = await scan(route('/ck', { ...GOOD, 'Set-Cookie': ['a=1; Path=/', 'b=2; HttpOnly; SameSite=Lax'] }));
  const c = r.findings.filter(f => f.id === 'cookies');
  assert.equal(c.length, 1);
  assert.match(c[0].message, /cookie-sentinel/i);
  assert.match(c[0].fix, /cookie-sentinel/i);
});
test('X-XSS-Protection deprecated unless 0', () => {
  assert.ok(ids(hs({ ...GOOD, 'X-XSS-Protection': '1; mode=block' })).includes('x-xss-protection'));
  assert.ok(!ids(hs({ ...GOOD, 'X-XSS-Protection': '0' })).includes('x-xss-protection'));
});
test('redirects followed by default, final response checked; can be disabled', async () => {
  route('/final', GOOD); const u = route('/redir', {}, { redirect: '/final' });
  const r = await scan(u);
  assert.equal(r.url, base + '/final'); assert.deepEqual(r.findings, []);
  const n = await scan(u, { followRedirects: false });
  assert.equal(n.status, 302); assert.ok(n.findings.length > 0);
});
test('timeout produces fetch error', async () => {
  const r = await scan(route('/slow', {}, { delay: 500 }), { timeout: 50 });
  assert.equal(r.findings[0].id, 'fetch'); assert.match(r.error, /timed out/);
});
test('config ignore and severity override; fail-on warn', async () => {
  const { 'Permissions-Policy': _, ...noPP } = GOOD;
  const u = route('/cfg', noPP);
  assert.equal(shouldFail([await scan(u)], 'error'), false);
  assert.equal(shouldFail([await scan(u)], 'warn'), true);
  assert.equal(shouldFail([await scan(u, { config: { ignore: ['permissions-policy'] } })], 'warn'), false);
  assert.equal((await scan(u, { config: { severity: { 'permissions-policy': 'error' } } })).findings[0].severity, 'error');
});
test('SARIF output shape', async () => {
  const s = toSarif([await scan(route('/bare', {}))]);
  assert.equal(s.version, '2.1.0'); assert.ok(s.runs[0].results.length > 0); assert.ok(s.runs[0].tool.driver.rules.length > 0);
});

const run = promisify(execFile);
const CLI = new URL('../bin/header-sentinel.js', import.meta.url).pathname;
const cli = (args, opts) => run('node', [CLI, ...args], { env: { ...process.env, NO_COLOR: '1' }, ...opts }).then(r => ({ code: 0, ...r }), e => ({ code: e.code, stdout: e.stdout, stderr: e.stderr }));
test('CLI exit codes, --json, --header, --config, --sarif file, NO_COLOR', async () => {
  const good = route('/good', GOOD), bare = route('/bare', {});
  assert.equal((await cli([good])).code, 0);
  const b = await cli([bare]); assert.equal(b.code, 1); assert.ok(!b.stdout.includes('\x1b[')); assert.match(b.stdout, /Grade [CDF]/);
  const j = await cli([good, bare, '--json']); assert.equal(j.code, 1); assert.equal(JSON.parse(j.stdout).results.length, 2);
  const dir = mkdtempSync(join(tmpdir(), 'hs-'));
  writeFileSync(join(dir, 'c.json'), JSON.stringify({ ignore: ['csp', 'frame-options', 'content-type-options', 'referrer-policy'] }));
  assert.equal((await cli([bare, '-c', join(dir, 'c.json')])).code, 0);
  assert.equal((await cli([bare, '-c', join(dir, 'c.json'), '--fail-on', 'warn'])).code, 1);
  await cli([bare, '--sarif', join(dir, 'o.sarif')]);
  assert.equal(JSON.parse(readFileSync(join(dir, 'o.sarif'), 'utf8')).version, '2.1.0');
  assert.equal((await cli(['--bogus'])).code, 2);
  const echo = await cli([good, '--json', '-H', 'Authorization: Bearer t0k']); assert.equal(echo.code, 0);
  assert.equal((await cli(['not-a-url'])).code, 2);
});
test('JSON output includes Observatory score and tests', async () => {
  const good = route('/good', GOOD);
  const j = await cli([good, '--json', '--no-http-upgrade', '--no-preload-check']);
  const body = JSON.parse(j.stdout);
  assert.ok(body.results[0].observatory);
  assert.ok(typeof body.results[0].score === 'number');
  assert.match(body.results[0].grade, /^[A-F][+-]?$/);
});

test('baseline mode only fails on new findings', async () => {
  const { 'Permissions-Policy': _, ...noPP } = GOOD;
  const u = route('/base', noPP);
  const full = await scan(u, { checkHttpRedirection: false, checkPreload: false });
  const baseline = { [full.url]: baselineFromResults([full])[full.url] };
  const diff = diffAgainstBaseline([full], baseline);
  assert.equal(diff[0].findings.length, 0);
  assert.equal(diff[0].baselineSkipped, true);
});

test('parseSitemapDocument extracts loc URLs', () => {
  const xml = '<?xml version="1.0"?><urlset><url><loc>https://example.com/a</loc></url></urlset>';
  assert.deepEqual(parseSitemapDocument(xml, 'https://example.com/sitemap.xml'), ['https://example.com/a']);
});

test('--header is sent with the request', async () => {
  const seen = [];
  const s = http.createServer((req, res) => { seen.push(req.headers['x-token']); res.end(); });
  await new Promise(r => s.listen(0, '127.0.0.1', r));
  await cli([`http://127.0.0.1:${s.address().port}/`, '--header', 'X-Token: abc']);
  s.close(); assert.deepEqual(seen, ['abc']);
});
