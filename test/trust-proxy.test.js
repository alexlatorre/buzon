// X-Forwarded-For decides the client IP the rate limiters see. It must only be trusted when the
// operator says a proxy is in front (TRUST_PROXY, or TLS=off, the documented proxy mode).
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { startServerCopy: startCopy } = require('./helpers');

// Three requests from three spoofed addresses with a limit of 2: was the third one limited?
async function spoofingDodgesLimit(base) {
    const statuses = [];
    for (const ip of ['203.0.113.1', '203.0.113.2', '203.0.113.3']) {
        statuses.push((await fetch(`${base}/api/auth/salt/someone`, { headers: { 'X-Forwarded-For': ip } })).status);
    }
    return statuses[2] !== 429;
}

test('by default, without a proxy setting, X-Forwarded-For is ignored', async () => {
    const server = await startCopy({ AUTH_RATE_LIMIT: '2' });
    try {
        assert.ok(server.started, server.output());
        assert.ok(server.output().includes('HTTP server'), 'expected plain HTTP: no certificates in the copy');
        assert.equal(await spoofingDodgesLimit(server.base), false);
    } finally {
        await server.stop();
    }
});

test('TLS=off (behind a TLS-terminating proxy) trusts exactly one proxy hop', async () => {
    const server = await startCopy({ AUTH_RATE_LIMIT: '2', TLS: 'off' });
    try {
        assert.equal(await spoofingDodgesLimit(server.base), true);
    } finally {
        await server.stop();
    }
});

test('TRUST_PROXY=false wins over TLS=off', async () => {
    const server = await startCopy({ AUTH_RATE_LIMIT: '2', TLS: 'off', TRUST_PROXY: 'false' });
    try {
        assert.equal(await spoofingDodgesLimit(server.base), false);
    } finally {
        await server.stop();
    }
});

test('TRUST_PROXY=true is refused at startup', async () => {
    const server = await startCopy({ TRUST_PROXY: 'true' });
    try {
        assert.equal(server.started, false);
        assert.notEqual(await server.exited, 0);
        assert.match(server.output(), /TRUST_PROXY/);
    } finally {
        await server.stop();
    }
});
