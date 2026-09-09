// Converts the JSON report of "guarddog <ecosystem> scan" into SARIF, so that
// findings in first-party code can be uploaded to GitHub code scanning.
// "guarddog verify" already speaks SARIF, "guarddog scan" does not.

/**
 * "capability-*" rules describe what code is able to do (read files, open
 * sockets). That is normal for most projects, so they are reported as notes.
 * Everything else describes actual malicious behaviour and is reported as an
 * error.
 */
function levelFor(ruleId) {
  return ruleId.startsWith('capability-') ? 'note' : 'error';
}

/** True for the values GuardDog uses to say "this rule ran and found nothing". */
function isEmpty(value) {
  if (!value) return true;
  if (typeof value === 'object') return Object.keys(value).length === 0;
  return false;
}

/** Splits "src/setup.js:4" into a path and an optional line number. */
function parseLocation(location) {
  const match = /^(.*?):(\d+)$/.exec(location ?? '');
  return match ? {uri: match[1], line: Number(match[2])} : {uri: location || 'package.json'};
}

export function toSarif(report, {scanRoot = ''} = {}) {
  const rules = new Map();
  const results = [];

  for (const [ruleId, value] of Object.entries(report?.results ?? {})) {
    // Source rules yield arrays, metadata rules yield a single object or string.
    // A rule that ran without finding anything yields an empty array or object.
    const findings = Array.isArray(value) ? value : isEmpty(value) ? [] : [value];
    for (const finding of findings) {
      const text = (typeof finding === 'string' ? finding : finding.message) || ruleId;
      const {uri, line} = parseLocation(typeof finding === 'string' ? '' : finding.location);
      rules.set(ruleId, {
        id: ruleId,
        name: ruleId,
        shortDescription: {text: ruleId},
        defaultConfiguration: {level: levelFor(ruleId)},
      });
      results.push({
        ruleId,
        level: levelFor(ruleId),
        message: {text},
        locations: [
          {
            physicalLocation: {
              artifactLocation: {uri: uri.startsWith(scanRoot) ? uri.slice(scanRoot.length).replace(/^\/+/, '') : uri},
              ...(line ? {region: {startLine: line}} : {}),
            },
          },
        ],
      });
    }
  }

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {name: 'GuardDog', informationUri: 'https://github.com/DataDog/guarddog', rules: [...rules.values()]},
        },
        results,
      },
    ],
  };
}

// CLI: node guarddog-sarif.js <guarddog-report.json> [scan-root] > results.sarif
if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) {
  const {readFileSync} = await import('node:fs');
  const [reportPath, scanRoot = ''] = process.argv.slice(2);
  const report = JSON.parse(readFileSync(reportPath, 'utf8'));
  process.stdout.write(JSON.stringify(toSarif(report, {scanRoot}), null, 2));
}
