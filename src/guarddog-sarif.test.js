import assert from 'node:assert';
import {describe, it} from 'node:test';
import {toSarif} from './guarddog-sarif.js';

describe('toSarif', () => {
  it('reports a clean scan as valid, empty SARIF', () => {
    const sarif = toSarif({results: {}, issues: 0});
    assert.strictEqual(sarif.version, '2.1.0');
    assert.deepStrictEqual(sarif.runs[0].results, []);
  });

  it('converts a finding into a located result', () => {
    const sarif = toSarif({
      results: {'threat-network-exfil-sysinfo': [{location: 'setup.js:4', message: 'Exfiltrates system info'}]},
    });
    const [result] = sarif.runs[0].results;
    assert.strictEqual(result.ruleId, 'threat-network-exfil-sysinfo');
    assert.strictEqual(result.message.text, 'Exfiltrates system info');
    assert.strictEqual(result.locations[0].physicalLocation.artifactLocation.uri, 'setup.js');
    assert.strictEqual(result.locations[0].physicalLocation.region.startLine, 4);
  });

  it('ranks capability rules below threat rules', () => {
    const sarif = toSarif({
      results: {
        'capability-filesystem-read': [{location: 'a.js:1', message: 'reads files'}],
        'threat-runtime-obfuscation': [{location: 'b.js:2', message: 'obfuscated'}],
      },
    });
    const level = id => sarif.runs[0].results.find(r => r.ruleId === id).level;
    assert.strictEqual(level('capability-filesystem-read'), 'note');
    assert.strictEqual(level('threat-runtime-obfuscation'), 'error');
  });

  it('handles a location without a line number', () => {
    const sarif = toSarif({results: {typosquatting: [{location: '', message: 'looks like another package'}]}});
    const {physicalLocation} = sarif.runs[0].results[0].locations[0];
    assert.strictEqual(physicalLocation.artifactLocation.uri, 'package.json');
    assert.strictEqual(physicalLocation.region, undefined);
  });

  it('accepts metadata rules that yield a single object instead of an array', () => {
    const sarif = toSarif({results: {deceptive_author: {location: 'package.json:1', message: 'suspicious author'}}});
    assert.strictEqual(sarif.runs[0].results.length, 1);
  });

  it('strips the scan root so paths stay relative to the repository', () => {
    const sarif = toSarif(
      {results: {'threat-runtime-obfuscation': [{location: '/tmp/scan/src/a.js:7', message: 'x'}]}},
      {scanRoot: '/tmp/scan'}
    );
    assert.strictEqual(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, 'src/a.js');
  });

  it('ignores rules that ran without finding anything', () => {
    // GuardDog emits an empty object for every rule that produced no finding.
    const sarif = toSarif({
      results: {
        'capability-network-lolbas': {},
        'threat-process-hooks': [],
        'threat-runtime-obfuscation': [{location: 'a.js:1', message: 'obfuscated'}],
      },
      issues: 1,
    });
    assert.strictEqual(sarif.runs[0].results.length, 1);
    assert.strictEqual(sarif.runs[0].tool.driver.rules.length, 1);
  });
});
