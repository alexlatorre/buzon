const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const { startServer, client } = require('./helpers');
const { loadCryptoUtils } = require('./browser-crypto');

const CryptoUtils = loadCryptoUtils();

let server, api, db, alice, bob;

before(async () => {
    server = await startServer();
    api = client(server.base);
    db = new Database(path.join(server.dataDir, 'buzon.db'));
    for (const name of ['alice', 'bob']) {
        const { user } = await api.register(name, `${name} password`);
        user.token = (await api.login(name, `${name} password`)).data.sessionToken;
        if (name === 'alice') alice = user; else bob = user;
    }
});

after(async () => {
    db.close();
    await server.stop();
});

const dropDir = () => path.join(server.dataDir, 'drop');
const filesOnDisk = () => fs.readdirSync(dropDir()).length;

test('drop stores the package with encrypted file names', async () => {
    const drop = await api.drop(alice.id, alice.publicKey, [{ name: 'secreto.txt', content: 'top secret' }], '  <b>Bob</b>\u0007 ');
    assert.equal(drop.status, 200);

    const pkgs = await api.json('GET', `/api/packages/${alice.id}`, null, alice.token);
    const pkg = pkgs.data[0];
    assert.equal(pkg.sender_name, '<b>Bob</b>');
    const stored = pkg.files[0].original_name;
    assert.match(stored, /^enc:/);
    assert.ok(!stored.includes('secreto'));
    assert.equal(await CryptoUtils.decryptDropName(drop.sessionKey, stored), 'secreto.txt');

    // Neither the file on disk nor the DB row carries the name or a real type in clear text
    const onDisk = fs.readFileSync(path.join(dropDir(), `${pkg.id}_${pkg.files[0].id}`), 'utf8');
    assert.ok(!onDisk.includes('secreto'), 'stored file leaks the name');
    assert.ok(!onDisk.includes('text/plain'), 'stored file leaks the type');
    assert.deepEqual(Object.keys(JSON.parse(onDisk)).sort(), ['ciphertext', 'iv']);
    assert.equal(pkg.files[0].mime_type, 'application/octet-stream');
});

test('a plaintext multipart filename is never stored', async () => {
    // An old or hand-made client that sends the real name and type and no encrypted names
    const form = new FormData();
    form.append('senderName', 'old client');
    form.append('encryptedSessionKey', 'AAAA');
    form.append('encryptedMessage', 'AAAA');
    form.append('messageIv', 'AAAAAAAAAAAAAAAA');
    form.append('files', new Blob(['x'], { type: 'text/plain' }), 'informe-confidencial.txt');
    const res = await fetch(`${server.base}/api/drop/${alice.id}`, { method: 'POST', body: form });
    assert.equal(res.status, 200);
    const { packageId } = await res.json();

    const row = db.prepare('SELECT original_name, mime_type FROM package_files WHERE package_id = ?').get(packageId);
    assert.equal(row.original_name, 'file');
    assert.equal(row.mime_type, 'application/octet-stream');
    await api.json('DELETE', `/api/package/${packageId}`, null, alice.token);
});

test('only the owner can download a package file', async () => {
    const pkg = (await api.json('GET', `/api/packages/${alice.id}`, null, alice.token)).data[0];
    const url = `${server.base}/api/package/${pkg.id}/file/${pkg.files[0].id}`;
    assert.equal((await fetch(url, { headers: { Authorization: `Bearer ${alice.token}` } })).status, 200);
    assert.equal((await fetch(url, { headers: { Authorization: `Bearer ${bob.token}` } })).status, 404);
    assert.equal((await fetch(url)).status, 401);
});

test('only the owner can delete a package', async () => {
    const pkg = (await api.json('GET', `/api/packages/${alice.id}`, null, alice.token)).data[0];
    assert.equal((await api.json('DELETE', `/api/package/${pkg.id}`, null, bob.token)).status, 403);
    assert.equal((await api.json('GET', `/api/packages/${alice.id}`, null, alice.token)).data.length, 1);
});

test('invalid or unknown links write nothing to disk', async () => {
    const before = filesOnDisk();
    assert.equal((await api.drop('not-a-uuid', alice.publicKey, [{ name: 'a', content: 'x' }])).status, 400);
    assert.equal((await api.drop('00000000-0000-4000-8000-000000000000', alice.publicKey, [{ name: 'a', content: 'x' }])).status, 404);
    assert.equal(filesOnDisk(), before);
});

test('more than 20 files is rejected as JSON and cleaned up', async () => {
    const before = filesOnDisk();
    const files = Array.from({ length: 21 }, (_, i) => ({ name: `f${i}`, content: 'x' }));
    const drop = await api.drop(alice.id, alice.publicKey, files);
    assert.equal(drop.status, 413);
    assert.match(drop.data.error, /Too many files/);
    await new Promise(r => setTimeout(r, 200));
    assert.equal(filesOnDisk(), before);
});

test('drops over the remaining quota are refused before upload', async () => {
    const before = filesOnDisk();
    db.prepare('UPDATE users SET mailbox_quota = 2000 WHERE id = ?').run(alice.id);
    try {
        const drop = await api.drop(alice.id, alice.publicKey, [{ name: 'big', content: 'x'.repeat(50000) }]);
        assert.equal(drop.status, 413);
        assert.equal(filesOnDisk(), before);
    } finally {
        db.prepare('UPDATE users SET mailbox_quota = 524288000 WHERE id = ?').run(alice.id);
    }
});

test('disabled public link refuses drops', async () => {
    await api.json('POST', `/api/user/${alice.id}/config`, { public_link_enabled: false }, alice.token);
    try {
        assert.equal((await api.drop(alice.id, alice.publicKey, [{ name: 'a', content: 'x' }])).status, 404);
    } finally {
        await api.json('POST', `/api/user/${alice.id}/config`, { public_link_enabled: true }, alice.token);
    }
});

test('a one-time link works exactly once, even under concurrency', async () => {
    const token = (await api.json('POST', `/api/user/${alice.id}/one-time-link`, null, alice.token)).data.token;
    const results = await Promise.all([1, 2, 3].map(() => api.drop(token, alice.publicKey, [{ name: 'n', content: 'y' }])));
    assert.equal(results.filter(r => r.status === 200).length, 1, results.map(r => r.status).join(','));
    assert.equal((await api.drop(token, alice.publicKey, [{ name: 'n', content: 'y' }])).status, 404);
});

test('quota endpoint reports a numeric usage', async () => {
    const q = await api.json('GET', `/api/user/${alice.id}/quota`);
    assert.equal(q.status, 200);
    assert.equal(typeof q.data.usage, 'number');
    assert.ok(q.data.usage > 0);
    assert.equal(q.data.remaining, q.data.quota - q.data.usage);
});
