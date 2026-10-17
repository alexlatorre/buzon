// Used one-time links disappear from the dashboard on refresh and are purged from the database
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const { startServer, client } = require('./helpers');

test('used one-time links are deleted by housekeeping, unused ones stay', async () => {
    const server = await startServer({ HOUSEKEEPING_DELAY_MS: '3000' });
    try {
        const api = client(server.base);
        const { user } = await api.register('alice', 'alice password');
        const token = (await api.login('alice', 'alice password')).data.sessionToken;
        const used = (await api.json('POST', `/api/user/${user.id}/one-time-link`, null, token)).data.token;
        const unused = (await api.json('POST', `/api/user/${user.id}/one-time-link`, null, token)).data.token;
        const db = new Database(path.join(server.dataDir, 'buzon.db'));
        db.prepare('UPDATE users SET public_link_enabled = 0 WHERE id = ?').run(user.id);
        assert.equal((await api.drop(used, user.publicKey, [{ name: 'a', content: 'x' }])).status, 200);
        await new Promise(r => setTimeout(r, 4000));
        const rows = db.prepare('SELECT token FROM one_time_links').all().map(r => r.token);
        db.close();
        assert.deepEqual(rows, [unused]);
    } finally {
        await server.stop();
    }
});

test('refreshing the inbox also refreshes the one-time link list', () => {
    const app = fs.readFileSync(path.join(__dirname, '..', 'public', 'app.js'), 'utf8');
    const fetchPackages = app.slice(app.indexOf('async function fetchPackages('), app.indexOf('function renderPackages('));
    assert.match(fetchPackages, /fetchOneTimeLinks\(\)/);
});
