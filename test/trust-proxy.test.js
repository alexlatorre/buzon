// X-Forwarded-For decides the client IP the rate limiters see. It must only be trusted when the
// operator says a proxy is in front (TRUST_PROXY, or TLS=off, the documented proxy mode).
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('child_process');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');

const REPO = path.join(__dirname, '..');

const freePort = () => new Promise(resolve => {
    const srv = net.createServer().listen(0, () => { const { port } = srv.address(); srv.close(() => resolve(port)); });
});

// Runs server.js from a copy outside the repo, so local certificates there are not picked up
async function startCopy(env) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'buzon-proxy-'));
    for (const item of ['server.js', 'config.js', 'db.js', 'db', 'public']) {
        fs.cpSync(path.join(REPO, item), path.join(dir, item), { recursive: true });
    }
    const port = await freePort();
    const childEnv = { ...process.env, PORT: String(port), DATA_DIR: path.join(dir, 'data'), NODE_PATH: path.join(REPO, 'node_modules'), DB_ENGINE: 'sqlite', ...env };
    for (const key of ['TLS', 'TRUST_PROXY']) if (!(key in env)) delete childEnv[key];
    const proc = spawn(process.execPath, ['server.js'], { cwd: dir, env: childEnv, stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '';
    const exited = new Promise(resolve => proc.on('exit', code => resolve(code)));
    const started = await new Promise(resolve => {
        const onData = chunk => { output += chunk; if (output.includes('server running at')) resolve(true); };
        proc.stdout.on('data', onData);
        proc.stderr.on('data', onData);
        exited.then(() => resolve(false));
    });
    return {
        started, exited, output: () => output, base: `http://localhost:${port}`,
        async stop() {
            if (started) { proc.kill(); await exited; }
            fs.rmSync(dir, { recursive: true, force: true });
        }
    };
}

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
