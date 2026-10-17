const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { startServer } = require('./helpers');

let server;

before(async () => {
    server = await startServer({ AUTH_RATE_LIMIT: '3' });
});

after(async () => {
    await server.stop();
});

test('security headers are set', async () => {
    const res = await fetch(`${server.base}/`);
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-security-policy'), /script-src 'self'/);
    assert.match(res.headers.get('content-security-policy'), /frame-ancestors 'none'/);
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(res.headers.get('x-frame-options'), 'DENY');
    assert.equal(res.headers.get('referrer-policy'), 'no-referrer');
    assert.equal(res.headers.get('access-control-allow-origin'), null);
});

test('integrity endpoint lists the 10 frontend files', async () => {
    const { files } = await (await fetch(`${server.base}/api/integrity`)).json();
    assert.equal(Object.keys(files).length, 10);
    for (const hash of Object.values(files)) assert.match(hash, /^[0-9a-f]{64}$/);
});

test('auth endpoints are rate limited', async () => {
    const statuses = [];
    for (let i = 0; i < 5; i++) statuses.push((await fetch(`${server.base}/api/auth/salt/someone`)).status);
    assert.deepEqual(statuses.slice(0, 3), [200, 200, 200]);
    assert.equal(statuses[4], 429);
});

test('with TRUST_PROXY=false a spoofed X-Forwarded-For does not dodge the limit', async () => {
    const direct = await startServer({ AUTH_RATE_LIMIT: '2', TRUST_PROXY: 'false' });
    try {
        const get = ip => fetch(`${direct.base}/api/auth/salt/someone`, { headers: { 'X-Forwarded-For': ip } }).then(r => r.status);
        assert.equal(await get('203.0.113.1'), 200);
        assert.equal(await get('203.0.113.2'), 200);
        assert.equal(await get('203.0.113.3'), 429);
    } finally {
        await direct.stop();
    }
});

test('README trusted hashes match the files being served', async () => {
    const fs = require('fs');
    const path = require('path');
    const readme = fs.readFileSync(path.join(__dirname, '..', 'README.md'), 'utf8');
    const documented = Object.fromEntries([...readme.matchAll(/^\| `([\w.]+)` \| `([0-9a-f]{64})` \|$/gm)].map(m => [m[1], m[2]]));
    const { files } = await (await fetch(`${server.base}/api/integrity`)).json();
    assert.deepEqual(documented, files);
});

test('using the API does not use up the login allowance', async () => {
    const limited = await startServer({ API_RATE_LIMIT: '3', AUTH_RATE_LIMIT: '100' });
    try {
        const statuses = [];
        for (let i = 0; i < 4; i++) statuses.push((await fetch(`${limited.base}/api/integrity`)).status);
        assert.deepEqual(statuses, [200, 200, 200, 429]);
        assert.equal((await fetch(`${limited.base}/api/auth/salt/someone`)).status, 200);
    } finally {
        await limited.stop();
    }
});

test('every response carries the security headers, errors and 429s included', async () => {
    const limited = await startServer({ AUTH_RATE_LIMIT: '1' });
    try {
        await fetch(`${limited.base}/api/auth/salt/a`);
        const tooMany = await fetch(`${limited.base}/api/auth/salt/a`);
        const badJson = await fetch(`${limited.base}/api/user/x/config`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"broken' });
        const notFound = await fetch(`${limited.base}/nope`);
        for (const [label, res] of Object.entries({ tooMany, badJson, notFound })) {
            assert.match(res.headers.get('content-security-policy') || '', /default-src 'self'/, label);
            assert.equal(res.headers.get('x-content-type-options'), 'nosniff', label);
            assert.equal(res.headers.get('x-powered-by'), null, label);
        }
        assert.equal(tooMany.status, 429);
    } finally {
        await limited.stop();
    }
});

test('cross-origin isolation headers are set', async () => {
    const res = await fetch(`${server.base}/`);
    assert.equal(res.headers.get('cross-origin-opener-policy'), 'same-origin');
    assert.equal(res.headers.get('cross-origin-resource-policy'), 'same-origin');
    assert.equal(res.headers.get('x-permitted-cross-domain-policies'), 'none');
    assert.equal(res.headers.get('x-powered-by'), null);
});

test('malformed or missing JSON bodies get 400 as JSON, not 500', async () => {
    const own = await startServer();
    try {
        const malformed = await fetch(`${own.base}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"username": ' });
        assert.equal(malformed.status, 400);
        assert.ok((await malformed.json()).error);
        assert.doesNotMatch(own.logs(), /"username": /, 'the raw body must not be logged');
        const noBody = await fetch(`${own.base}/api/auth/login`, { method: 'POST' });
        assert.equal(noBody.status, 400);
        const register = await fetch(`${own.base}/api/auth/register`, { method: 'POST' });
        assert.equal(register.status, 400);
    } finally {
        await own.stop();
    }
});

test('the three copies of the checked-file list agree', () => {
    const fs = require('fs');
    const path = require('path');
    const read = f => fs.readFileSync(path.join(__dirname, '..', f), 'utf8');
    // The array literal right after the name, as a sorted list of its quoted entries
    const list = (file, name) => {
        const text = read(file);
        const at = text.indexOf(name);
        assert.ok(at >= 0, `${name} not found in ${file}`);
        const open = text.indexOf('[', at);
        const close = text.indexOf(']', open);
        return text.slice(open + 1, close).split(',').map(x => x.trim().replace(/'/g, '')).filter(Boolean).sort();
    };
    const server = list('server.js', 'INTEGRITY_FILES');
    assert.deepEqual(list('public/integrity.js', 'CRITICAL_FILES'), server);
    assert.deepEqual(list('scripts/update-hashes.js', 'FILES'), server);
});

test('changing a public file without a restart updates the served hash', async () => {
    const { startServerCopy } = require('./helpers');
    const fs = require('fs');
    const path = require('path');
    const copy = await startServerCopy({ TLS: 'off' });
    try {
        const before = (await (await fetch(`${copy.base}/api/integrity`)).json()).files['style.css'];
        const cssPath = path.join(copy.dir, 'public', 'style.css');
        fs.appendFileSync(cssPath, '\n/* deployed without a restart */\n');
        const served = Buffer.from(await (await fetch(`${copy.base}/style.css`)).arrayBuffer());
        const after = (await (await fetch(`${copy.base}/api/integrity`)).json()).files['style.css'];
        assert.notEqual(after, before);
        assert.equal(after, require('crypto').createHash('sha256').update(served).digest('hex'));
    } finally {
        await copy.stop();
    }
});
