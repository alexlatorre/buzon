// Files on disk that no DB row points to (aborted uploads, failed inserts, crashes) must be removed
// once they are older than the grace period, while live files and fresh uploads are kept.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { startServer, client } = require('./helpers');

const HOUSEKEEPING_DELAY_MS = 4000;
let server, api, alice, planted, live;

const hoursAgo = h => (Date.now() - h * 3600000) / 1000;
function plant(dir, name, ageHours) {
    fs.mkdirSync(dir, { recursive: true });
    const file = path.join(dir, name);
    fs.writeFileSync(file, 'orphan');
    if (ageHours) fs.utimesSync(file, hoursAgo(ageHours), hoursAgo(ageHours));
    return file;
}

before(async () => {
    server = await startServer({ HOUSEKEEPING_DELAY_MS: String(HOUSEKEEPING_DELAY_MS), ORPHAN_GRACE_MS: String(60 * 60 * 1000) });
    api = client(server.base);
    const drop = path.join(server.dataDir, 'drop');
    const shares = path.join(server.dataDir, 'shares');
    planted = {
        oldUpload: plant(drop, `${crypto.randomUUID()}.upload`, 3),
        oldDropFile: plant(drop, `${crypto.randomUUID()}_${crypto.randomUUID()}`, 3),
        oldShareFile: plant(shares, `${crypto.randomUUID()}.enc`, 3),
        freshUpload: plant(drop, `${crypto.randomUUID()}.upload`, 0),
        freshShareFile: plant(shares, `${crypto.randomUUID()}.enc`, 0),
        unrelated: plant(drop, 'README.txt', 3)
    };

    // Real files that rows point to, made old so only the DB link protects them
    const { user } = await api.register('alice', 'alice password');
    user.token = (await api.login('alice', 'alice password')).data.sessionToken;
    alice = user;
    const { data } = await api.drop(alice.id, alice.publicKey, [{ name: 'a.txt', content: 'keep me' }]);
    const pkg = (await api.json('GET', `/api/packages/${alice.id}`, null, alice.token)).data.find(p => p.id === data.packageId);
    const share = (await api.share(alice.id, alice.token)).data;
    live = {
        dropFile: path.join(drop, `${pkg.id}_${pkg.files[0].id}`),
        shareFile: path.join(shares, `${share.token}.enc`)
    };
    for (const file of Object.values(live)) fs.utimesSync(file, hoursAgo(3), hoursAgo(3));

    // Let the first housekeeping run happen
    await new Promise(r => setTimeout(r, HOUSEKEEPING_DELAY_MS + 1500));
});

after(async () => {
    await server.stop();
});

test('old orphan files are removed', () => {
    for (const key of ['oldUpload', 'oldDropFile', 'oldShareFile']) {
        assert.equal(fs.existsSync(planted[key]), false, key);
    }
});

test('fresh files are kept, they may belong to an upload in progress', () => {
    assert.equal(fs.existsSync(planted.freshUpload), true);
    assert.equal(fs.existsSync(planted.freshShareFile), true);
});

test('files with a DB row are kept, however old', () => {
    assert.equal(fs.existsSync(live.dropFile), true);
    assert.equal(fs.existsSync(live.shareFile), true);
});

test('files that do not follow the storage naming are left alone', () => {
    assert.equal(fs.existsSync(planted.unrelated), true);
});
