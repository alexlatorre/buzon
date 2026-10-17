// Backups must contain everything a restore needs, including rows still in the WAL, and a lost salt
// secret must be reported instead of silently replaced
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const Database = require('better-sqlite3');
const { startServer, client } = require('./helpers');
const { backup } = require('../scripts/backup');

test('a backup taken while the server runs has the database, files and salt secret', async () => {
    const server = await startServer();
    const destination = fs.mkdtempSync(path.join(os.tmpdir(), 'buzon-backup-'));
    fs.rmSync(destination, { recursive: true });
    try {
        const api = client(server.base);
        const { user } = await api.register('alice', 'alice password');
        const { packageId } = (await api.drop(user.id, user.publicKey, [{ name: 'a.txt', content: 'keep me' }])).data;

        await backup(server.dataDir, destination);

        const db = new Database(path.join(destination, 'buzon.db'), { readonly: true });
        const files = db.prepare('SELECT id FROM package_files WHERE package_id = ?').all(packageId);
        assert.equal(db.prepare('SELECT username FROM users WHERE id = ?').get(user.id).username, 'alice');
        db.close();
        assert.equal(files.length, 1);
        assert.ok(fs.existsSync(path.join(destination, 'drop', `${packageId}_${files[0].id}`)));
        assert.deepEqual(fs.readFileSync(path.join(destination, '.salt_secret')), fs.readFileSync(path.join(server.dataDir, '.salt_secret')));
    } finally {
        await server.stop();
        fs.rmSync(destination, { recursive: true, force: true });
    }
});

test('starting with a database but no salt secret is reported', async () => {
    const first = await startServer();
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'buzon-restore-'));
    try {
        await client(first.base).register('alice', 'alice password');
        await backup(first.dataDir, path.join(dataDir, 'restored'));
        fs.rmSync(path.join(dataDir, 'restored', '.salt_secret'));
    } finally {
        await first.stop();
    }
    const restored = await startServer({ DATA_DIR: path.join(dataDir, 'restored') });
    try {
        await new Promise(r => setTimeout(r, 500)); // the check runs right after startup
        assert.match(restored.logs(), /\.salt_secret.*missing/i);
    } finally {
        await restored.stop();
        fs.rmSync(dataDir, { recursive: true, force: true });
    }
});
