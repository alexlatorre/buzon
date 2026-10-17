// The runtime must stay on a Node line that still gets security fixes (Node 20 ended 30 Apr 2026)
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const read = file => fs.readFileSync(path.join(__dirname, '..', file), 'utf8');
const MIN_MAJOR = 22;

test('the Docker image uses a supported Node LTS', () => {
    const from = read('Dockerfile').match(/^FROM node:(\d+)-alpine/m);
    assert.ok(from, 'Dockerfile must build FROM node:<major>-alpine');
    const major = Number(from[1]);
    assert.ok(major >= 24 && major % 2 === 0, `node:${major} is not a current LTS line`);
});

test('package.json declares the supported engines and the tests run on one', () => {
    const { engines } = JSON.parse(read('package.json'));
    assert.equal(engines && engines.node, `>=${MIN_MAJOR}`);
    assert.ok(Number(process.versions.node.split('.')[0]) >= MIN_MAJOR);
});
