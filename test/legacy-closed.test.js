// With the migration closed (the default) a legacy account gives nothing away: no encrypted private
// key, no challenge, the same answer as a wrong password. LEGACY_MIGRATION=open reopens it.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const Database = require('better-sqlite3');
const { startServer, client } = require('./helpers');

let server, api, db, legacy;

before(async () => {
    server = await startServer();
    api = client(server.base);
    db = new Database(path.join(server.dataDir, 'buzon.db'));
    legacy = (await api.register('oldtimer', 'old pass')).user;
    db.prepare("UPDATE users SET server_auth_hash = 'LEGACY_MIGRATION_REQUIRED' WHERE id = ?").run(legacy.id);
    await api.register('regular', 'regular pass');
});

after(async () => {
    db.close();
    await server.stop();
});

test('a legacy account hands out nothing while the migration is closed', async () => {
    const res = await api.json('POST', '/api/auth/login', { username: 'oldtimer', serverAuthHash: 'anything' });
    assert.equal(res.status, 401);
    assert.equal(res.data.encryptedPrivateKey, undefined);
    assert.equal(res.data.challenge, undefined);
    assert.equal(res.data.migrationRequired, undefined);
});

test('it answers exactly like a wrong password or an unknown user', async () => {
    const legacyRes = await api.json('POST', '/api/auth/login', { username: 'oldtimer', serverAuthHash: 'x' });
    const wrongPassword = await api.json('POST', '/api/auth/login', { username: 'regular', serverAuthHash: 'x' });
    const unknown = await api.json('POST', '/api/auth/login', { username: 'nobody', serverAuthHash: 'x' });
    assert.deepEqual([legacyRes.status, legacyRes.data], [wrongPassword.status, wrongPassword.data]);
    assert.deepEqual([legacyRes.status, legacyRes.data], [unknown.status, unknown.data]);
});

test('even the right password does not log in until the migration is reopened', async () => {
    const res = await api.login('oldtimer', 'old pass');
    assert.equal(res.status, 401);
    assert.equal(db.prepare('SELECT server_auth_hash FROM users WHERE id = ?').get(legacy.id).server_auth_hash, 'LEGACY_MIGRATION_REQUIRED');
});

test('LEGACY_MIGRATION=open lets the owner migrate', async () => {
    const open = await startServer({ LEGACY_MIGRATION: 'open' });
    try {
        const openApi = client(open.base);
        const { user } = await openApi.register('oldtimer2', 'old pass 2');
        const openDb = new Database(path.join(open.dataDir, 'buzon.db'));
        openDb.prepare("UPDATE users SET server_auth_hash = 'LEGACY_MIGRATION_REQUIRED' WHERE id = ?").run(user.id);
        openDb.close();
        const res = await openApi.login('oldtimer2', 'old pass 2');
        assert.equal(res.status, 200);
        assert.ok(res.data.sessionToken);
    } finally {
        await open.stop();
    }
});
