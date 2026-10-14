import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';

const require = createRequire(import.meta.url);
const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

test('package.json is exported', () => {
  assert.equal(pkg.exports['./package.json'], './package.json');
});

test('require("header-sentinel/package.json") resolves via self-reference', () => {
  const p = require('header-sentinel/package.json');
  assert.equal(p.name, 'header-sentinel');
  assert.equal(p.version, pkg.version);
});

test('import("header-sentinel/package.json") with JSON attributes', async () => {
  const resolved = import.meta.resolve('header-sentinel/package.json');
  assert.match(resolved, /package\.json$/);
  const m = await import(resolved, { with: { type: 'json' } }).catch(() => import(resolved, { assert: { type: 'json' } }));
  assert.equal(m.default.name, 'header-sentinel');
});

test('require("header-sentinel") loads CJS build', () => {
  const mod = require('header-sentinel');
  assert.equal(typeof mod.scan, 'function');
  assert.equal(typeof mod.computeObservatoryScore, 'function');
  assert.equal(typeof mod.gradeFromScore, 'function');
});

test('import("header-sentinel") loads ESM build', async () => {
  const mod = await import('header-sentinel');
  assert.equal(typeof mod.scanAll, 'function');
  assert.equal(typeof mod.evaluateObservatory, 'function');
});
