const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const { startServer, client } = require('./helpers');

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

test('share is created and its metadata is public', async () => {
    const created = await api.share(alice.id, alice.token);
    assert.equal(created.status, 200);
    const meta = await api.json('GET', `/api/share/${created.data.token}/meta`);
    assert.equal(meta.status, 200);
    assert.equal(meta.data.size, 100);
});

test('users cannot create shares for someone else', async () => {
    assert.equal((await api.share(alice.id, bob.token)).status, 403);
});

test('max_downloads is honoured under concurrent downloads', async () => {
    const { data } = await api.share(alice.id, alice.token, { maxDownloads: 1 });
    const statuses = await Promise.all([1, 2, 3, 4].map(() =>
        fetch(`${server.base}/api/share/${data.token}/download`).then(r => r.status)
    ));
    assert.equal(statuses.filter(s => s === 200).length, 1, statuses.join(','));
});

test('expired shares return 410', async () => {
    const { data } = await api.share(alice.id, alice.token);
    db.prepare('UPDATE shares SET expires_at = ? WHERE token = ?').run(new Date(Date.now() - 1000).toISOString(), data.token);
    assert.equal((await api.json('GET', `/api/share/${data.token}/meta`)).status, 410);
    assert.equal((await fetch(`${server.base}/api/share/${data.token}/download`)).status, 410);
});

test('shares count towards the storage quota', async () => {
    const q = await api.json('GET', `/api/user/${alice.id}/quota`);
    assert.ok(q.data.usage >= 300, `usage ${q.data.usage}`);
    db.prepare('UPDATE users SET mailbox_quota = ? WHERE id = ?').run(q.data.usage + 50, alice.id);
    try {
        assert.equal((await api.share(alice.id, alice.token, { size: 100 })).status, 413);
    } finally {
        db.prepare('UPDATE users SET mailbox_quota = 524288000 WHERE id = ?').run(alice.id);
    }
});

test('only the owner can delete a share', async () => {
    const { data } = await api.share(alice.id, alice.token);
    assert.equal((await api.json('DELETE', `/api/share/${data.token}`, null, bob.token)).status, 403);
    assert.equal((await api.json('DELETE', `/api/share/${data.token}`, null, alice.token)).status, 200);
    assert.equal(fs.existsSync(path.join(server.dataDir, 'shares', `${data.token}.enc`)), false);
});

test('uploading two files to a share is rejected as JSON', async () => {
    const form = new FormData();
    form.append('file', new Blob(['a']), 'a');
    form.append('file', new Blob(['b']), 'b');
    const res = await fetch(`${server.base}/api/share/${alice.id}`, { method: 'POST', headers: { Authorization: `Bearer ${alice.token}` }, body: form });
    assert.equal(res.status, 413);
    assert.ok((await res.json()).error);
});
