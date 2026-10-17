// TLS must fail closed: certificates that are found but unusable stop the server instead of letting
// it serve plain HTTP on the port the operator thinks is HTTPS. TLS=off is the only way to plain HTTP.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { startServerCopy } = require('./helpers');

const BROKEN_CERTS = { 'cert.pem': 'not a certificate', 'key.pem': 'not a key' };

test('unusable certificates stop the server', async () => {
    const server = await startServerCopy({}, BROKEN_CERTS);
    try {
        assert.equal(server.started, false, 'the server must not start');
        assert.notEqual(await server.exited, 0);
        assert.match(server.output(), /TLS=off/);
        assert.doesNotMatch(server.output(), /HTTP server running/);
    } finally {
        await server.stop();
    }
});

test('TLS=off serves plain HTTP on purpose, whatever certificate files are around', async () => {
    const server = await startServerCopy({ TLS: 'off' }, BROKEN_CERTS);
    try {
        assert.equal(server.started, true, server.output());
        assert.equal((await fetch(`${server.base}/api/integrity`)).status, 200);
    } finally {
        await server.stop();
    }
});
