// The image must not ship compilers, must report its health and must stop cleanly
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const dockerfile = fs.readFileSync(path.join(__dirname, '..', 'Dockerfile'), 'utf8');
const runtime = dockerfile.slice(dockerfile.lastIndexOf('\nFROM '));

test('the runtime stage has no build toolchain and runs unprivileged', () => {
    assert.match(dockerfile, /FROM node:\d+-alpine AS build/);
    assert.doesNotMatch(runtime, /apk add/);
    assert.doesNotMatch(runtime, /npm (ci|install)/);
    assert.match(runtime, /COPY --from=build \/app\/node_modules/);
    assert.match(runtime, /\nUSER node\n/);
});

test('the image has a health check and an exec-form command', () => {
    assert.match(runtime, /HEALTHCHECK [^\n]*scripts\/healthcheck\.js/);
    assert.match(runtime, /\nCMD \["node", "server\.js"\]/);
});

test('the server shuts down gracefully on SIGTERM', () => {
    const server = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
    assert.match(server, /process\.on\('SIGTERM'/);
    assert.match(server, /httpServer\.close\(/);
});
