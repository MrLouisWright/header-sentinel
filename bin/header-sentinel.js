#!/usr/bin/env node
import { readFileSync, existsSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

async function loadApi() {
  const dist = join(__dirname, '../dist/index.js');
  if (existsSync(dist)) return import(pathToFileURL(dist).href);
  return import('../src/index.js');
}

const {
  scanAll,
  shouldFail,
  toSarif,
  pretty,
  fetchSitemapUrls,
  diffAgainstBaseline,
  baselineFromResults,
} = await loadApi();

const HELP = `header-sentinel <url...> [options]

Fetch deployed URLs and fail when HTTP security headers are missing or misconfigured.
Grades use the Mozilla HTTP Observatory scoring model (A+ through F).

Options:
  -c, --config <file>       JSON config (default: .headerguardrc.json / .headersentinelrc.json if present)
      --fail-on <level>     error | warn | none   (default: error)
      --json                Print JSON results
      --sarif [file]        Print SARIF 2.1.0 (or write to file) for GitHub code scanning
      --sitemap <url>       Fetch URLs from sitemap.xml (repeatable; merges with URL args)
      --baseline <file>     Compare findings to baseline; only report new issues
      --update-baseline     Write current fingerprints to --baseline (creates/overwrites)
      --no-http-upgrade     Skip HTTP→HTTPS redirect chain check
      --no-preload-check    Skip HSTS preload list / eligibility lookups
  -t, --timeout <ms>        Request timeout (default: 10000)
  -H, --header "K: V"       Extra request header (repeatable)
      --no-follow-redirects Check the first response instead of the final one
  -h, --help / -v, --version`;

function parse(argv) {
  const o = { urls: [], sitemaps: [], headers: {}, failOn: undefined, timeout: undefined, follow: true };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]; const next = () => { if (i + 1 >= argv.length) die(`${a} requires a value`); return argv[++i]; };
    if (a === '-h' || a === '--help') { console.log(HELP); process.exit(0); }
    else if (a === '-v' || a === '--version') { console.log(JSON.parse(readFileSync(join(__dirname, '../package.json'), 'utf8')).version); process.exit(0); }
    else if (a === '-c' || a === '--config') o.config = next();
    else if (a === '--fail-on') o.failOn = next();
    else if (a.startsWith('--fail-on=')) o.failOn = a.slice(10);
    else if (a === '--json') o.json = true;
    else if (a === '--sitemap') o.sitemaps.push(next());
    else if (a === '--baseline') o.baseline = next();
    else if (a === '--update-baseline') o.updateBaseline = true;
    else if (a === '--no-http-upgrade') o.noHttpUpgrade = true;
    else if (a === '--no-preload-check') o.noPreload = true;
    else if (a === '--sarif') { o.sarif = true; if (argv[i + 1] && !argv[i + 1].startsWith('-') && !/^https?:/.test(argv[i + 1])) o.sarifFile = argv[++i]; }
    else if (a === '-t' || a === '--timeout') o.timeout = Number(next());
    else if (a === '-H' || a === '--header') { const h = next(); const k = h.indexOf(':'); if (k < 1) die(`bad header "${h}"`); o.headers[h.slice(0, k).trim()] = h.slice(k + 1).trim(); }
    else if (a === '--follow-redirects') o.follow = true;
    else if (a === '--no-follow-redirects') o.follow = false;
    else if (a.startsWith('-')) die(`unknown option ${a}`);
    else o.urls.push(a);
  }
  return o;
}
function die(m) { console.error(`header-sentinel: ${m}\n\n${HELP}`); process.exit(2); }

const o = parse(process.argv.slice(2));
let config = {};
const cfgFile = o.config || ['.headerguardrc.json', '.headersentinelrc.json'].find(existsSync);
if (cfgFile) { try { config = JSON.parse(readFileSync(cfgFile, 'utf8')); } catch (e) { die(`cannot read config ${cfgFile}: ${e.message}`); } }

let urls = o.urls.length ? o.urls : (config.urls || []);
if (o.sitemaps.length || config.sitemap) {
  const maps = [...o.sitemaps, ...(config.sitemap ? [config.sitemap] : [])];
  const timeout = o.timeout || config.timeout || 10000;
  const headers = { ...(config.headers || {}), ...o.headers };
  for (const sm of maps) {
    try {
      urls = urls.concat(await fetchSitemapUrls(sm, { timeout, headers, maxUrls: config.maxUrls || 500 }));
    } catch (e) {
      die(`cannot read sitemap ${sm}: ${e.message}`);
    }
  }
}
urls = [...new Set(urls)];
if (!urls.length) die('no URLs given (pass URLs or --sitemap)');
for (const u of urls) if (!/^https?:\/\//.test(u)) die(`invalid URL "${u}" (must start with http:// or https://)`);
const failOn = o.failOn || config.failOn || 'error';
if (!['error', 'warn', 'none'].includes(failOn)) die('--fail-on must be error, warn or none');

const scanOpts = {
  timeout: o.timeout || config.timeout || 10000,
  headers: { ...(config.headers || {}), ...o.headers },
  followRedirects: o.follow,
  config,
  checkHttpRedirection: !o.noHttpUpgrade && config.checkHttpRedirection !== false,
  checkPreload: !o.noPreload && config.checkPreload !== false,
};

let results = await scanAll(urls, scanOpts);

if (o.baseline || config.baseline) {
  const baselinePath = o.baseline || config.baseline;
  if (o.updateBaseline) {
    writeFileSync(baselinePath, JSON.stringify({ version: 1, urls: baselineFromResults(results) }, null, 2) + '\n');
    if (!o.json && !o.sarif) console.log(`baseline written to ${baselinePath}`);
  } else if (existsSync(baselinePath)) {
    let baseline = {};
    try {
      baseline = JSON.parse(readFileSync(baselinePath, 'utf8')).urls || {};
    } catch (e) {
      die(`cannot read baseline ${baselinePath}: ${e.message}`);
    }
    results = diffAgainstBaseline(results, baseline);
  } else if (!o.updateBaseline) {
    die(`baseline file not found: ${baselinePath} (run with --update-baseline first)`);
  }
}

if (o.sarif) {
  const s = JSON.stringify(toSarif(results), null, 2);
  if (o.sarifFile) { writeFileSync(o.sarifFile, s); if (!o.json) console.log(pretty(results)); } else console.log(s);
}
if (o.json) {
  console.log(JSON.stringify({
    failOn,
    failed: shouldFail(results, failOn),
    results,
    summary: {
      urls: results.length,
      grade: results.length === 1 ? results[0].grade : undefined,
      score: results.length === 1 ? results[0].score : undefined,
    },
  }, null, 2));
} else if (!o.sarif) console.log(pretty(results));
process.exitCode = shouldFail(results, failOn) ? 1 : 0;
