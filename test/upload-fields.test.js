// Upload text fields must be validated before anything is stored: repeated fields (which multer turns
// into arrays), wrong sizes and oversized metadata used to break inserts, leave orphan files and grow
// the database outside the quota.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const { startServer, client, b64 } = require('./helpers');

let server, api, db, alice;

before(async () => {
    server = await startServer();
    api = client(server.base);
    db = new Database(path.join(server.dataDir, 'buzon.db'));
    const { user } = await api.register('alice', 'alice password');
    user.token = (await api.login('alice', 'alice password')).data.sessionToken;
    alice = user;
});

after(async () => {
    db.close();
    await server.stop();
});

// getRandomValues fills at most 64 KB per call
const random = bytes => {
    const out = new Uint8Array(bytes);
    for (let i = 0; i < bytes; i += 65536) globalThis.crypto.getRandomValues(out.subarray(i, Math.min(bytes, i + 65536)));
    return b64(out);
};
const listDir = dir => (fs.existsSync(dir) ? fs.readdirSync(dir) : []);
const dropDir = () => path.join(server.dataDir, 'drop');
const shareDir = () => path.join(server.dataDir, 'shares');
const countPackages = () => db.prepare('SELECT COUNT(*) AS n FROM packages').get().n;

// A drop body with valid-looking fields (RSA-2048 key, 12-byte IV, small message); override any of them
function dropForm(override = {}, { files = 1, extra = [], bodySize } = {}) {
    const fields = { senderName: 'Bob', encryptedSessionKey: random(256), encryptedMessage: random(32), messageIv: random(12), ...override };
    const form = new FormData();
    for (const [k, v] of Object.entries(fields)) if (v !== undefined) form.append(k, v);
    for (const [k, v] of extra) form.append(k, v);
    for (let i = 0; i < files; i++) form.append('files', new Blob([bodySize === undefined ? random(60) : new Uint8Array(bodySize)]), 'encrypted.bin');
    return form;
}

const postDrop = async (linkId, form) => {
    const res = await fetch(`${server.base}/api/drop/${linkId}`, { method: 'POST', body: form });
    return { status: res.status, data: await res.json().catch(() => null) };
};

test('a well-formed drop is accepted', async () => {
    assert.equal((await postDrop(alice.id, dropForm())).status, 200);
});

test('drops with malformed crypto fields are refused and leave nothing behind', async () => {
    const cases = {
        'repeated session key': [{}, { extra: [['encryptedSessionKey', random(256)]] }],
        'session key not base64': [{ encryptedSessionKey: '!!!not-base64!!!' }],
        'session key wrong size': [{ encryptedSessionKey: random(100) }],
        'missing session key': [{ encryptedSessionKey: undefined }],
        'IV wrong size': [{ messageIv: random(16) }],
        'message not base64': [{ encryptedMessage: 'hello world' }],
        'sender name repeated': [{}, { extra: [['senderName', 'Eve']] }],
        'unknown package format': [{ format: '3' }],
        'format repeated': [{ format: '2' }, { extra: [['format', '2']] }],
        'format 2 body shorter than IV and tag': [{ format: '2' }, { bodySize: 27 }]
    };
    const packagesBefore = countPackages();
    const filesBefore = listDir(dropDir()).length;
    for (const [label, [override, opts]] of Object.entries(cases)) {
        const res = await postDrop(alice.id, dropForm(override, opts));
        assert.equal(res.status, 400, label);
    }
    assert.equal(countPackages(), packagesBefore);
    assert.equal(listDir(dropDir()).length, filesBefore);
});

test('format 2 drops are stored as format 2, down to an empty file (IV and tag only)', async () => {
    const res = await postDrop(alice.id, dropForm({ format: '2' }, { bodySize: 28 }));
    assert.equal(res.status, 200);
    assert.equal(db.prepare('SELECT format FROM packages WHERE id = ?').get(res.data.packageId).format, 2);
    const plain = await postDrop(alice.id, dropForm());
    assert.equal(db.prepare('SELECT format FROM packages WHERE id = ?').get(plain.data.packageId).format, 1);
});

test('a drop with neither files nor a message is refused', async () => {
    // An empty message still carries the 16-byte GCM tag, so it decodes to 16 bytes
    assert.equal((await postDrop(alice.id, dropForm({ encryptedMessage: random(16) }, { files: 0 }))).status, 400);
});

test('an oversized message is refused', async () => {
    const res = await postDrop(alice.id, dropForm({ encryptedMessage: random(600 * 1024) }, { files: 0 }));
    assert.ok([400, 413].includes(res.status), `status ${res.status}`);
});

test('a malformed drop does not use up a one-time link', async () => {
    db.prepare('UPDATE users SET public_link_enabled = 0 WHERE id = ?').run(alice.id);
    try {
        const token = (await api.json('POST', `/api/user/${alice.id}/one-time-link`, null, alice.token)).data.token;
        assert.equal((await postDrop(token, dropForm({ messageIv: random(3) }))).status, 400);
        assert.equal((await postDrop(token, dropForm())).status, 200);
    } finally {
        db.prepare('UPDATE users SET public_link_enabled = 1 WHERE id = ?').run(alice.id);
    }
});

test('message-only packages count towards the quota', async () => {
    const before = (await api.json('GET', `/api/user/${alice.id}/config`, null, alice.token)).data.usage;
    const message = random(40 * 1024);
    assert.equal((await postDrop(alice.id, dropForm({ encryptedMessage: message }, { files: 0 }))).status, 200);
    const after = (await api.json('GET', `/api/user/${alice.id}/config`, null, alice.token)).data.usage;
    assert.ok(after - before >= message.length, `usage grew by ${after - before}`);
});

test('a share with a repeated field is refused and leaves no orphan file', async () => {
    const filesBefore = listDir(shareDir()).length;
    const res = await api.share(alice.id, alice.token, { size: 2000, extra: [['originalName', 'twice.bin']] });
    assert.equal(res.status, 400);
    assert.equal(listDir(shareDir()).length, filesBefore);
});

test('shares with malformed fields are refused and leave nothing behind', async () => {
    const cases = {
        'file key wrong size': { encryptedFileKey: random(32) },
        'key IV wrong size': { keyIv: random(16) },
        'file IV not base64': { fileIv: '***' },
        'salt wrong size': { salt: random(4) },
        'missing name': { originalName: undefined },
        'name too long': { originalName: 'x'.repeat(300) },
        'negative downloads': { maxDownloads: '-1' },
        'too many downloads': { maxDownloads: '5000' },
        'downloads not a number': { maxDownloads: 'many' },
        'expiry too long': { expiresIn: '999999' },
        'message without IV': { encryptedMessage: random(40) }
    };
    const sharesBefore = db.prepare('SELECT COUNT(*) AS n FROM shares').get().n;
    const filesBefore = listDir(shareDir()).length;
    for (const [label, fields] of Object.entries(cases)) {
        assert.equal((await api.share(alice.id, alice.token, { fields })).status, 400, label);
    }
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM shares').get().n, sharesBefore);
    assert.equal(listDir(shareDir()).length, filesBefore);
});

test('the share options offered by the dashboard are accepted', async () => {
    for (const maxDownloads of ['0', '1', '5', '10', '25']) {
        for (const expiresIn of ['0', '1', '24', '168', '720']) {
            assert.equal((await api.share(alice.id, alice.token, { maxDownloads, expiresIn })).status, 200, `${maxDownloads}/${expiresIn}`);
        }
    }
    const withNote = await api.share(alice.id, alice.token, { fields: { encryptedMessage: random(40), messageIv: random(12) } });
    assert.equal(withNote.status, 200);
});
