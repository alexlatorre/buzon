// Pending packages expire (PACKAGE_RETENTION_DAYS, default 30) so nobody can fill a mailbox forever
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const { startServer, client } = require('./helpers');

// Two packages, one backdated by `ageDays`; returns what is left after the first housekeeping run
async function runWith(env, ageDays) {
    const server = await startServer({ HOUSEKEEPING_DELAY_MS: '3000', ...env });
    try {
        const api = client(server.base);
        const { user } = await api.register('alice', 'alice password');
        const token = (await api.login('alice', 'alice password')).data.sessionToken;
        const oldId = (await api.drop(user.id, user.publicKey, [{ name: 'old.txt', content: 'old' }])).data.packageId;
        const newId = (await api.drop(user.id, user.publicKey, [{ name: 'new.txt', content: 'new' }])).data.packageId;
        const db = new Database(path.join(server.dataDir, 'buzon.db'));
        db.prepare(`UPDATE packages SET created_at = datetime('now', '-${ageDays} days') WHERE id = ?`).run(oldId);
        const oldFiles = db.prepare('SELECT id FROM package_files WHERE package_id = ?').all(oldId).map(f => path.join(server.dataDir, 'drop', `${oldId}_${f.id}`));
        db.close();
        await new Promise(r => setTimeout(r, 4500));
        const ids = (await api.json('GET', `/api/packages/${user.id}`, null, token)).data.map(p => p.id);
        return { oldKept: ids.includes(oldId), newKept: ids.includes(newId), oldFilesLeft: oldFiles.filter(f => fs.existsSync(f)).length };
    } finally {
        await server.stop();
    }
}

test('packages older than 30 days are removed with their files by default', async () => {
    const r = await runWith({}, 31);
    assert.deepEqual(r, { oldKept: false, newKept: true, oldFilesLeft: 0 });
});

test('younger packages are kept', async () => {
    const r = await runWith({}, 29);
    assert.deepEqual(r, { oldKept: true, newKept: true, oldFilesLeft: 1 });
});

test('PACKAGE_RETENTION_DAYS=0 keeps packages forever, other values change the limit', async () => {
    assert.equal((await runWith({ PACKAGE_RETENTION_DAYS: '0' }, 400)).oldKept, true);
    assert.equal((await runWith({ PACKAGE_RETENTION_DAYS: '7' }, 8)).oldKept, false);
});
