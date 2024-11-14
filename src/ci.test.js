import assert from 'node:assert';
import {describe, it} from 'node:test';
import {identity} from './ci.js';

describe('Functional Test', () => {
  it('executes without issues', () => {
    const actual = identity(1);
    const expected = 1;
    assert.strictEqual(actual, expected);
  });
});
