// Small dashboard behaviours that used to fail silently or leave the UI in a wrong state
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const app = fs.readFileSync(path.join(__dirname, '..', 'public', 'app.js'), 'utf8');
const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');

test('every clipboard write handles a refusal', () => {
    const calls = app.split('navigator.clipboard.writeText(').slice(1);
    assert.ok(calls.length >= 4);
    calls.forEach((rest, i) => {
        const statement = rest.slice(0, rest.indexOf(';\n', rest.indexOf('})') > 0 ? rest.indexOf('})') : 0) + 2);
        assert.match(statement, /\.catch\(/, `clipboard call #${i + 1} has no catch`);
    });
});
