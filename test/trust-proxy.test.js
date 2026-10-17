// X-Forwarded-For decides the client IP the rate limiters see. It must only be trusted when the
// operator says a proxy is in front (TRUST_PROXY, or TLS=off, the documented proxy mode).
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { startServerCopy: startCopy } = require('./helpers');

// A throw-away self-signed certificate: without TLS=off the server only starts with one. Needs the
// openssl command (the test is skipped without it).
function selfSigned() {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'buzon-cert-'));
    try {
        execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
            '-keyout', path.join(dir, 'key.pem'), '-out', path.join(dir, 'cert.pem'), '-days', '1', '-subj', '/CN=localhost'], { stdio: 'ignore' });
        return { 'cert.pem': fs.readFileSync(path.join(dir, 'cert.pem')), 'key.pem': fs.readFileSync(path.join(dir, 'key.pem')) };
    } catch {
        return null;
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
}
const certs = selfSigned();

// Three requests from three spoofed addresses with a limit of 2: was the third one limited?
async function spoofingDodgesLimit(base) {
    const statuses = [];
    for (const ip of ['203.0.113.1', '203.0.113.2', '203.0.113.3']) {
        statuses.push((await fetch(`${base}/api/auth/salt/someone`, { headers: { 'X-Forwarded-For': ip } })).status);
    }
    return statuses[2] !== 429;
}

test('by default, without a proxy setting, X-Forwarded-For is ignored', { skip: certs ? false : 'openssl not available' }, async () => {
    const server = await startCopy({ AUTH_RATE_LIMIT: '2' }, certs);
    // The certificate is self-signed: accept it for this test process only
    const previous = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
    try {
        assert.ok(server.started, server.output());
        assert.ok(server.output().includes('HTTPS server'), server.output());
        assert.equal(await spoofingDodgesLimit(server.base.replace('http:', 'https:')), false);
    } finally {
        if (previous === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
        else process.env.NODE_TLS_REJECT_UNAUTHORIZED = previous;
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
    const server = await startCopy({ TLS: 'off', TRUST_PROXY: 'true' });
    try {
        assert.equal(server.started, false);
        assert.notEqual(await server.exited, 0);
        assert.match(server.output(), /TRUST_PROXY/);
    } finally {
        await server.stop();
    }
});
