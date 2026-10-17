// Contracts of the database driver that the API relies on for atomicity. HTTP-level concurrency tests
// cannot catch a check-then-set version on SQLite (calls are synchronous), so pin them here.
const { test, before } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

let db, userId;

before(async () => {
    process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'buzon-driver-'));
    db = require('../db/sqlite');
    userId = await db.createUser('driver', 'c2FsdA==', 'pub', 'priv', 'iv', 'sha256:x');
});

test('consumeToken succeeds exactly once', async () => {
    const token = await db.generateOneTimeLink(userId);
    assert.equal(await db.consumeToken(token), true);
    assert.equal(await db.consumeToken(token), false);
    assert.equal(await db.getUserByToken(token), null);
});

test('incrementShareDownloads stops at max_downloads and refunds give one back', async () => {
    await db.createShare(userId, 'tok-1', 'k', 'iv', 's', 'fiv', 'n', 'm', 10, null, null, 1, null, null);
    assert.equal(await db.incrementShareDownloads('tok-1'), true);
    assert.equal(await db.incrementShareDownloads('tok-1'), false);
    await db.refundShareDownload('tok-1');
    assert.equal(await db.incrementShareDownloads('tok-1'), true);
    await db.refundShareDownload('tok-1');
    await db.refundShareDownload('tok-1');
    assert.equal((await db.getShareByToken('tok-1')).download_count, 0, 'never below zero');
});

test('unlimited shares (max 0) always count', async () => {
    await db.createShare(userId, 'tok-2', 'k', 'iv', 's', 'fiv', 'n', 'm', 10, null, null, 0, null, null);
    for (let i = 0; i < 5; i++) assert.equal(await db.incrementShareDownloads('tok-2'), true);
});

test('the guards are in the SQL itself', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'db', 'sqlite.js'), 'utf8');
    assert.match(src, /UPDATE one_time_links SET is_used = 1 WHERE token = \? AND is_used = 0/);
    assert.match(src, /download_count < max_downloads/);
});

test('updateVault only writes while the auth hash is the one checked', async () => {
    const id = await db.createUser('vault', 'c2FsdA==', 'pub', 'priv', 'iv', 'sha256:old');
    assert.equal(await db.updateVault(id, 'sha256:old', 's2', 'pbkdf2-sha256:600000', 'priv2', 'iv2', 'sha256:new'), true);
    // A second change that read the vault before the first one wrote it
    assert.equal(await db.updateVault(id, 'sha256:old', 's3', 'pbkdf2-sha256:600000', 'priv3', 'iv3', 'sha256:other'), false);
    const user = await db.getUserById(id);
    assert.equal(user.server_auth_hash, 'sha256:new');
    assert.equal(user.salt, 's2');
});

test('rotateKeys writes everything or nothing', async () => {
    const id = await db.createUser('rotor', 'c2FsdA==', 'pub', 'priv', 'iv', 'sha256:old');
    const pkg = await db.createPackage(id, 'x', 'key-old', 'msg', 'miv', 2);
    const pkg2 = await db.createPackage(id, 'y', 'key2-old', 'msg', 'miv', 1);
    await db.createShare(id, 'tok-r', 'k', 'iv', 's', 'fiv', 'enc2:a:b', 'm', 10, null, null, 0, null, null, 2, 'owner-old');
    await db.createShare(id, 'tok-r1', 'k', 'iv', 's', 'fiv', 'n', 'm', 10, null, null, 0, null, null); // format 1: not in the lists
    const vault = { publicKey: 'pub2', salt: 's2', kdf: 'pbkdf2-sha256:600000', encryptedPrivateKey: 'priv2', iv: 'iv2', serverAuthHash: 'sha256:new' };
    const share = ownerKey => [{ token: 'tok-r', ownerKey }];
    const unchanged = async () => {
        assert.equal((await db.getUserById(id)).public_key, 'pub');
        assert.equal((await db.getUserById(id)).server_auth_hash, 'sha256:old');
        assert.equal((await db.getPackageById(pkg)).encrypted_session_key, 'key-old');
        assert.equal((await db.getPackageById(pkg2)).encrypted_session_key, 'key2-old');
        assert.equal((await db.getShareByToken('tok-r')).owner_key, 'owner-old');
    };
    // The vault is written first: a list that does not match rolls it back too
    assert.equal(await db.rotateKeys(id, 'sha256:old', vault, [{ id: pkg, encryptedSessionKey: 'k' }], share('owner-new')), 'lists');
    await unchanged();
    assert.equal(await db.rotateKeys(id, 'sha256:old', vault, [{ id: pkg, encryptedSessionKey: 'k' }, { id: pkg, encryptedSessionKey: 'k' }], share(null)), 'lists');
    assert.equal(await db.rotateKeys(id, 'sha256:old', vault, [{ id: pkg, encryptedSessionKey: 'k' }, { id: pkg2, encryptedSessionKey: 'k' }], [...share(null), { token: 'tok-r1', ownerKey: null }]), 'lists');
    await unchanged();
    assert.equal(await db.rotateKeys(id, 'sha256:other', vault, [{ id: pkg, encryptedSessionKey: 'key-new' }, { id: pkg2, encryptedSessionKey: 'key2-new' }], share('owner-new')), 'vault');
    await unchanged();
    // A write that fails halfway (a value SQLite cannot store) undoes the vault and the key written before it
    await assert.rejects(db.rotateKeys(id, 'sha256:old', vault, [{ id: pkg, encryptedSessionKey: 'key-new' }, { id: pkg2, encryptedSessionKey: {} }], share('owner-new')));
    await unchanged();
    // null leaves a key as it is
    assert.equal(await db.rotateKeys(id, 'sha256:old', vault, [{ id: pkg, encryptedSessionKey: 'key-new' }, { id: pkg2, encryptedSessionKey: null }], share(null)), 'ok');
    const user = await db.getUserById(id);
    assert.deepEqual([user.public_key, user.salt, user.encrypted_private_key, user.iv, user.server_auth_hash], ['pub2', 's2', 'priv2', 'iv2', 'sha256:new']);
    assert.equal((await db.getPackageById(pkg)).encrypted_session_key, 'key-new');
    assert.equal((await db.getPackageById(pkg2)).encrypted_session_key, 'key2-old');
    assert.equal((await db.getShareByToken('tok-r')).owner_key, 'owner-old');
});
