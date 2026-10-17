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
