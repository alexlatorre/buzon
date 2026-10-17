// Quota is check-then-insert. With a network database (MySQL) every query yields to the event loop,
// so concurrent uploads for one user used to all pass the check. DB_TEST_LATENCY_MS makes SQLite
// behave the same way.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const Database = require('better-sqlite3');
const { startServer, client } = require('./helpers');

let server, api, db, alice;

before(async () => {
    server = await startServer({ DB_TEST_LATENCY_MS: '15' });
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

const usage = async () => (await api.json('GET', `/api/user/${alice.id}/config`, null, alice.token)).data.usage;

test('concurrent shares cannot go over the quota together', async () => {
    db.prepare('UPDATE users SET mailbox_quota = ? WHERE id = ?').run((await usage()) + 1500, alice.id);
    try {
        const results = await Promise.all(Array.from({ length: 6 }, () => api.share(alice.id, alice.token, { size: 1000 })));
        assert.equal(results.filter(r => r.status === 200).length, 1, results.map(r => r.status).join(','));
        assert.ok((await usage()) <= db.prepare('SELECT mailbox_quota FROM users WHERE id = ?').get(alice.id).mailbox_quota);
    } finally {
        db.prepare('UPDATE users SET mailbox_quota = 524288000 WHERE id = ?').run(alice.id);
    }
});

test('concurrent drops cannot go over the quota together', async () => {
    db.prepare('UPDATE users SET mailbox_quota = ? WHERE id = ?').run((await usage()) + 3000, alice.id);
    try {
        const files = [{ name: 'a.bin', content: 'x'.repeat(1200) }];
        const results = await Promise.all(Array.from({ length: 6 }, () => api.drop(alice.id, alice.publicKey, files)));
        const ok = results.filter(r => r.status === 200).length;
        assert.ok(ok >= 1 && ok <= 2, results.map(r => r.status).join(','));
        assert.ok((await usage()) <= db.prepare('SELECT mailbox_quota FROM users WHERE id = ?').get(alice.id).mailbox_quota);
    } finally {
        db.prepare('UPDATE users SET mailbox_quota = 524288000 WHERE id = ?').run(alice.id);
    }
});
