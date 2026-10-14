const useColor = (stream) => !('NO_COLOR' in process.env) && (process.env.FORCE_COLOR || stream?.isTTY);
export function pretty(results, { color = useColor(process.stdout) } = {}) {
  const c = (code) => (s) => color ? `\x1b[${code}m${s}\x1b[0m` : String(s);
  const red = c(31), yellow = c(33), green = c(32), dim = c(2), bold = c(1), cyan = c(36);
  const lines = [];
  for (const r of results) {
    const gc = r.grade.startsWith('A') ? green : r.grade === 'B' || r.grade === 'C' ? yellow : red;
    const li = r.likelihoodIndicator ? dim(` · ${r.likelihoodIndicator} risk`) : '';
    lines.push('', bold(r.url) + (r.status ? dim(` (HTTP ${r.status})`) : '') + '  ' + gc(bold(`Grade ${r.grade}`)) + dim(` score ${r.score}/100`) + li);
    if (r.requestedUrl && new URL(r.requestedUrl).href !== new URL(r.url).href) lines.push(dim(`  redirected from ${r.requestedUrl}`));
    if (r.redirection?.result) lines.push(dim(`  HTTP upgrade: ${r.redirection.result}`));
    if (r.baselineSkipped) lines.push(dim('  baseline: unchanged (no new issues)'));
    if (r.baselineNewUrl) lines.push(dim('  baseline: new URL (all findings count)'));
    if (!r.findings.length) lines.push(green('  ✔ all checks passed'));
    for (const f of r.findings) {
      const tag = f.severity === 'error' ? red('✖ error') : yellow('⚠ warn ');
      lines.push(`  ${tag} ${bold(f.title)} ${dim('[' + f.id + ']')}`, `          ${f.message}`);
      if (f.fix) lines.push(...f.fix.split('\n').map((l, i) => `          ${i ? '' : cyan('fix: ')}${dim(l)}`));
    }
    if (r.observatory?.tests?.length && process.env.HEADER_SENTINEL_VERBOSE) {
      lines.push(dim('  Observatory tests:'));
      for (const t of r.observatory.tests) {
        lines.push(dim(`    ${t.pass ? '✔' : '✗'} ${t.result} (${t.scoreModifier >= 0 ? '+' : ''}${t.scoreModifier})`));
      }
    }
  }
  const e = results.reduce((s, r) => s + r.findings.filter(f => f.severity === 'error').length, 0);
  const w = results.reduce((s, r) => s + r.findings.filter(f => f.severity === 'warn').length, 0);
  lines.push('', `${results.length} URL(s) scanned: ${e ? red(e + ' error(s)') : green('0 errors')}, ${w ? yellow(w + ' warning(s)') : '0 warnings'}`);
  return lines.join('\n');
}
