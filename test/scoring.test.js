import test from 'node:test';
import assert from 'node:assert/strict';
import { computeObservatoryScore, gradeFromScore, MINIMUM_SCORE_FOR_EXTRA_CREDIT } from '../dist/index.js';

test('Mozilla Observatory grade chart (rounded down to nearest 5)', () => {
  assert.equal(gradeFromScore(100), 'A+');
  assert.equal(gradeFromScore(97), 'A');
  assert.equal(gradeFromScore(92), 'A');
  assert.equal(gradeFromScore(87), 'A-');
  assert.equal(gradeFromScore(82), 'B+');
  assert.equal(gradeFromScore(24), 'F');
});

test('bonuses apply only when pre-bonus score is at least 90', () => {
  const failing = computeObservatoryScore(['csp-not-implemented']);
  assert.ok(failing.score < MINIMUM_SCORE_FOR_EXTRA_CREDIT);
  assert.equal(failing.grade, 'B');

  const strong = computeObservatoryScore([
    'csp-implemented-with-no-unsafe',
    'referrer-policy-private',
    'x-frame-options-implemented-via-csp',
    'hsts-implemented-max-age-at-least-six-months',
    'x-content-type-options-nosniff',
    'cookies-not-found',
    'x-xss-protection-disabled',
    'redirection-to-https',
  ]);
  assert.ok(strong.score >= 100);
  assert.equal(strong.grade, 'A+');
});
