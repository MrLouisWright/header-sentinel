/**
 * Stable fingerprint for a finding (for baseline diff).
 * @param {{ url: string; findings: { id: string; severity: string; title: string }[] }} result
 */
export function fingerprintResult(result) {
  return result.findings
    .map((f) => `${f.id}|${f.severity}|${f.title}`)
    .sort()
    .join('\n');
}

/**
 * @param {import('./index.js').Result[]} results
 * @param {Record<string, string>} baseline url -> fingerprint
 */
export function diffAgainstBaseline(results, baseline) {
  /** @type {import('./index.js').Result[]} */
  const withNew = [];
  for (const r of results) {
    const key = r.url;
    const prev = baseline[key];
    const fp = fingerprintResult(r);
    if (prev === fp) {
      withNew.push({ ...r, findings: [], baselineSkipped: true });
      continue;
    }
    if (prev == null) {
      withNew.push({ ...r, baselineNewUrl: true });
      continue;
    }
    const prevSet = new Set(prev.split('\n').filter(Boolean));
    const newFindings = r.findings.filter((f) => !prevSet.has(`${f.id}|${f.severity}|${f.title}`));
    withNew.push({ ...r, findings: newFindings, baselineRegressed: newFindings.length > 0 });
  }
  return withNew;
}

/**
 * @param {import('./index.js').Result[]} results
 */
export function baselineFromResults(results) {
  /** @type {Record<string, string>} */
  const out = {};
  for (const r of results) out[r.url] = fingerprintResult(r);
  return out;
}
