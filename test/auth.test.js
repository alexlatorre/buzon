const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const Database = require('better-sqlite3');
const { startServer, client, b64 } = require('./helpers');

let server, api, db;

before(async () => {
    server = await startServer();
    api = client(server.base);
    db = new Database(path.join(server.dataDir, 'buzon.db'));
});

after(async () => {
    db.close();
    await server.stop();
});

const storedAuthHash = id => db.prepare('SELECT server_auth_hash FROM users WHERE id = ?').get(id).server_auth_hash;

test('register stores a hash of the auth token, never the token itself', async () => {
    const { res, user } = await api.register('alice', 'correct horse battery');
    assert.equal(res.status, 200);
    const stored = storedAuthHash(user.id);
    assert.match(stored, /^sha256:[0-9a-f]{64}$/);
    assert.notEqual(stored, user.serverAuthHash);
});

test('register rejects duplicates and bad usernames', async () => {
    assert.equal((await api.register('alice', 'x')).res.status, 409);
    assert.equal((await api.register('a!', 'x')).res.status, 400);
});

test('login returns a session; wrong password is rejected', async () => {
    const ok = await api.login('alice', 'correct horse battery');
    assert.equal(ok.status, 200);
    assert.ok(ok.data.sessionToken);
    const bad = await api.login('alice', 'wrong password');
    assert.equal(bad.status, 401);
    assert.equal(bad.data.sessionToken, undefined);
});

test('rows stored before hashing still log in and are upgraded', async () => {
    const { user } = await api.register('rawhash', 'raw pass');
    db.prepare('UPDATE users SET server_auth_hash = ? WHERE id = ?').run(user.serverAuthHash, user.id);
    const res = await api.login('rawhash', 'raw pass');
    assert.equal(res.status, 200);
    assert.match(storedAuthHash(user.id), /^sha256:/);
});

test('legacy account cannot be claimed without the private key', async () => {
    const { user } = await api.register('legacy', 'legacy pass');
    db.prepare("UPDATE users SET server_auth_hash = 'LEGACY_MIGRATION_REQUIRED' WHERE id = ?").run(user.id);

    const first = await api.json('POST', '/api/auth/login', { username: 'legacy', serverAuthHash: 'attacker' });
    assert.equal(first.status, 200);
    assert.equal(first.data.migrationRequired, true);
    assert.equal(first.data.sessionToken, undefined);

    const forged = await api.json('POST', '/api/auth/login', {
        username: 'legacy', serverAuthHash: 'attacker', challengeResponse: b64(new Uint8Array(32))
    });
    assert.equal(forged.status, 401);
    assert.equal(storedAuthHash(user.id), 'LEGACY_MIGRATION_REQUIRED');
});

test('legacy account owner migrates by answering the challenge', async () => {
    const res = await api.login('legacy', 'legacy pass');
    assert.equal(res.status, 200);
    assert.ok(res.data.sessionToken);
    const id = db.prepare("SELECT id FROM users WHERE username = 'legacy'").get().id;
    assert.match(storedAuthHash(id), /^sha256:/);
    assert.equal((await api.login('legacy', 'legacy pass')).status, 200);
});

test('unknown users get a well-formed, stable fake salt', async () => {
    const a = await api.json('GET', '/api/auth/salt/nobody_here');
    const b = await api.json('GET', '/api/auth/salt/nobody_here');
    const c = await api.json('GET', '/api/auth/salt/someone_else');
    assert.match(a.data.salt, /^[A-Za-z0-9+/]+=*$/);
    assert.equal(Buffer.from(a.data.salt, 'base64').length, 16);
    assert.equal(a.data.salt, b.data.salt);
    assert.notEqual(a.data.salt, c.data.salt);
});

test('protected endpoints require a valid session for the same user', async () => {
    const alice = (await api.login('alice', 'correct horse battery')).data;
    const legacy = (await api.login('legacy', 'legacy pass')).data;
    assert.equal((await api.json('GET', `/api/packages/${alice.id}`)).status, 401);
    assert.equal((await api.json('GET', `/api/packages/${alice.id}`, null, 'not-a-token')).status, 401);
    assert.equal((await api.json('GET', `/api/packages/${alice.id}`, null, legacy.sessionToken)).status, 403);
    assert.equal((await api.json('GET', `/api/packages/${alice.id}`, null, alice.sessionToken)).status, 200);
});

test('logout invalidates the session', async () => {
    const alice = (await api.login('alice', 'correct horse battery')).data;
    assert.equal((await api.json('POST', '/api/auth/logout', null, alice.sessionToken)).status, 200);
    assert.equal((await api.json('GET', `/api/packages/${alice.id}`, null, alice.sessionToken)).status, 401);
});
