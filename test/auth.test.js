const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const Database = require('better-sqlite3');
const { startServer, client, b64 } = require('./helpers');
const { loadCryptoUtils } = require('./browser-crypto');

const CryptoUtils = loadCryptoUtils();

let server, api, db;

before(async () => {
    server = await startServer({ LEGACY_MIGRATION: 'open' });
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

test('registration refuses malformed key material', async () => {
    const randomB64 = bytes => b64(globalThis.crypto.getRandomValues(new Uint8Array(bytes)));
    const keyPair = await globalThis.crypto.subtle.generateKey(
        { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']
    );
    const valid = {
        salt: randomB64(16),
        publicKey: b64(await globalThis.crypto.subtle.exportKey('spki', keyPair.publicKey)),
        encryptedPrivateKey: randomB64(1700),
        iv: randomB64(12),
        serverAuthHash: randomB64(32)
    };
    const cases = {
        'salt wrong size': { salt: randomB64(4) },
        'salt not base64': { salt: 'not base64!!' },
        'public key not a key': { publicKey: randomB64(294) },
        'public key huge': { publicKey: randomB64(5000) },
        'private key not base64': { encryptedPrivateKey: '***' },
        'private key too big': { encryptedPrivateKey: randomB64(20000) },
        'IV wrong size': { iv: randomB64(16) },
        'auth hash wrong size': { serverAuthHash: randomB64(20) }
    };
    for (const [label, override] of Object.entries(cases)) {
        const res = await api.json('POST', '/api/auth/register', { username: `bad_${Object.keys(cases).indexOf(label)}`, ...valid, ...override });
        assert.equal(res.status, 400, label);
    }
    const ok = await api.json('POST', '/api/auth/register', { username: 'goodkeys', ...valid });
    assert.equal(ok.status, 200);
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
        username: 'legacy', serverAuthHash: 'attacker', challengeId: first.data.challengeId, challengeResponse: b64(new Uint8Array(32))
    });
    assert.equal(forged.status, 401);
    assert.equal(storedAuthHash(user.id), 'LEGACY_MIGRATION_REQUIRED');
});

test('the server challenge is labelled and only a hash of the nonce is accepted', async () => {
    const { user } = await api.register('legacyraw', 'raw nonce pass');
    db.prepare("UPDATE users SET server_auth_hash = 'LEGACY_MIGRATION_REQUIRED' WHERE id = ?").run(user.id);
    const { challenge, challengeId } = (await api.json('POST', '/api/auth/login', { username: 'legacyraw', serverAuthHash: 'x' })).data;
    const ciphertext = Buffer.from(challenge, 'base64');

    // Without the label the challenge does not decrypt: it lives in its own domain
    await assert.rejects(globalThis.crypto.subtle.decrypt({ name: 'RSA-OAEP' }, user.privateKey, ciphertext));

    // Echoing the decrypted nonce (the old protocol) is rejected
    const label = new TextEncoder().encode('shadowdrop/migration-challenge/v1');
    const nonce = await globalThis.crypto.subtle.decrypt({ name: 'RSA-OAEP', label }, user.privateKey, ciphertext);
    const raw = await api.json('POST', '/api/auth/login', { username: 'legacyraw', serverAuthHash: 'x', challengeId, challengeResponse: b64(nonce) });
    assert.equal(raw.status, 401);
    assert.equal(storedAuthHash(user.id), 'LEGACY_MIGRATION_REQUIRED');
});

test('a non-string challenge answer never opens a session', async () => {
    const { user } = await api.register('legacytype', 'type pass');
    db.prepare("UPDATE users SET server_auth_hash = 'LEGACY_MIGRATION_REQUIRED' WHERE id = ?").run(user.id);
    await api.json('POST', '/api/auth/login', { username: 'legacytype', serverAuthHash: 'x' });
    for (const challengeResponse of [123, null, [], {}, true]) {
        const res = await api.json('POST', '/api/auth/login', { username: 'legacytype', serverAuthHash: 'x', challengeResponse });
        assert.equal(res.status, 200);
        assert.equal(res.data.migrationRequired, true);
        assert.equal(res.data.sessionToken, undefined);
    }
});

test('a correct challenge answer works only once', async () => {
    const { user } = await api.register('legacyonce', 'once pass');
    const setLegacy = () => db.prepare("UPDATE users SET server_auth_hash = 'LEGACY_MIGRATION_REQUIRED' WHERE id = ?").run(user.id);
    setLegacy();
    const { challenge, challengeId } = (await api.json('POST', '/api/auth/login', { username: 'legacyonce', serverAuthHash: 'x' })).data;
    const challengeResponse = await CryptoUtils.answerMigrationChallenge(user.privateKey, challenge);
    const first = await api.json('POST', '/api/auth/login', { username: 'legacyonce', serverAuthHash: user.serverAuthHash, challengeId, challengeResponse });
    assert.equal(first.status, 200);
    assert.ok(first.data.sessionToken);

    // Replaying the same answer later must not be accepted again, even if the account is legacy again
    setLegacy();
    const replay = await api.json('POST', '/api/auth/login', { username: 'legacyonce', serverAuthHash: 'attacker', challengeId, challengeResponse });
    assert.equal(replay.data.sessionToken, undefined);
    assert.equal(storedAuthHash(user.id), 'LEGACY_MIGRATION_REQUIRED');
});

test('a stranger asking for challenges cannot block the owner from migrating', async () => {
    const { user } = await api.register('legacyrace', 'race pass');
    db.prepare("UPDATE users SET server_auth_hash = 'LEGACY_MIGRATION_REQUIRED' WHERE id = ?").run(user.id);
    const step1 = () => api.json('POST', '/api/auth/login', { username: 'legacyrace', serverAuthHash: 'x' });

    const owner = (await step1()).data;
    const stranger = (await step1()).data;
    // The stranger burns their own challenge with a wrong answer
    const wrong = await api.json('POST', '/api/auth/login', {
        username: 'legacyrace', serverAuthHash: 'x', challengeId: stranger.challengeId, challengeResponse: b64(new Uint8Array(32))
    });
    assert.equal(wrong.status, 401);

    const challengeResponse = await CryptoUtils.answerMigrationChallenge(user.privateKey, owner.challenge);
    const res = await api.json('POST', '/api/auth/login', {
        username: 'legacyrace', serverAuthHash: user.serverAuthHash, challengeId: owner.challengeId, challengeResponse
    });
    assert.equal(res.status, 200);
    assert.ok(res.data.sessionToken);
});

test("a challenge issued for one account cannot be answered for another", async () => {
    const { user: a } = await api.register('legacya', 'a pass');
    const { user: b } = await api.register('legacyb', 'b pass');
    db.prepare("UPDATE users SET server_auth_hash = 'LEGACY_MIGRATION_REQUIRED' WHERE id IN (?, ?)").run(a.id, b.id);
    const forA = (await api.json('POST', '/api/auth/login', { username: 'legacya', serverAuthHash: 'x' })).data;
    const challengeResponse = await CryptoUtils.answerMigrationChallenge(a.privateKey, forA.challenge);
    const res = await api.json('POST', '/api/auth/login', { username: 'legacyb', serverAuthHash: 'x', challengeId: forA.challengeId, challengeResponse });
    assert.equal(res.data.sessionToken, undefined);
    assert.equal(storedAuthHash(b.id), 'LEGACY_MIGRATION_REQUIRED');
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
    await api.register('mallory', 'mallory pass');
    const legacy = (await api.login('mallory', 'mallory pass')).data;
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
