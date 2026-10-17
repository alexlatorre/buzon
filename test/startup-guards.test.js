// Startup must not quietly do the wrong thing: no certificates means no start unless TLS=off (never
// cleartext on the port the operator believes is HTTPS), and a missing database next to the files of
// an earlier install means no start (never an empty database that hides every account).
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { startServerCopy } = require('./helpers');

const dataDir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'buzon-startup-'));

async function start(env) {
    const server = await startServerCopy(env);
    const output = server.output();
    await server.stop();
    return { started: server.started, output };
}

test('without certificates and without TLS=off the server does not start', async () => {
    const server = await startServerCopy({});
    try {
        assert.equal(server.started, false, 'the server must not start');
        assert.notEqual(await server.exited, 0);
        assert.match(server.output(), /No TLS certificates found/);
        assert.match(server.output(), /TLS=off/);
        assert.doesNotMatch(server.output(), /server running/);
    } finally {
        await server.stop();
    }
});

test('a first start creates the database and says so; later starts do not', async () => {
    const dir = dataDir();
    const first = await start({ TLS: 'off', DATA_DIR: dir });
    assert.equal(first.started, true, first.output);
    assert.match(first.output, /Created a new, empty database/);
    const second = await start({ TLS: 'off', DATA_DIR: dir });
    assert.equal(second.started, true, second.output);
    assert.doesNotMatch(second.output, /Created a new, empty database/);
    fs.rmSync(dir, { recursive: true, force: true });
});

test('a missing database next to files of an earlier install stops the server', async () => {
    const cases = {
        'salt secret': dir => fs.writeFileSync(path.join(dir, '.salt_secret'), 'x'),
        'write-ahead log': dir => fs.writeFileSync(path.join(dir, 'buzon.db-wal'), 'x'),
        'uploaded drop file': dir => { fs.mkdirSync(path.join(dir, 'drop')); fs.writeFileSync(path.join(dir, 'drop', 'p_f'), 'x'); },
        'uploaded share': dir => { fs.mkdirSync(path.join(dir, 'shares')); fs.writeFileSync(path.join(dir, 'shares', 't.enc'), 'x'); }
    };
    for (const [label, leave] of Object.entries(cases)) {
        const dir = dataDir();
        leave(dir);
        const res = await start({ TLS: 'off', DATA_DIR: dir });
        assert.equal(res.started, false, label);
        assert.match(res.output, /from an earlier install/, label);
        assert.equal(fs.existsSync(path.join(dir, 'buzon.db')), false, `${label}: no empty database left behind`);
        fs.rmSync(dir, { recursive: true, force: true });
    }
});

test('empty upload folders alone are not taken for an earlier install', async () => {
    const dir = dataDir();
    fs.mkdirSync(path.join(dir, 'drop'));
    fs.mkdirSync(path.join(dir, 'shares'));
    const res = await start({ TLS: 'off', DATA_DIR: dir });
    assert.equal(res.started, true, res.output);
    fs.rmSync(dir, { recursive: true, force: true });
});
