// The security page must not promise more than the code does, and deleted rows must not stay
// readable in the SQLite file
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { startServer, client } = require('./helpers');

const about = fs.readFileSync(path.join(__dirname, '..', 'public', 'about.html'), 'utf8');

test('about.html makes no claim the server cannot keep', () => {
    assert.doesNotMatch(about, /no possibility of recovery/);
    assert.doesNotMatch(about, /would only find unintelligible binary data/);
    assert.match(about, /What the server does see/);
});

test('deleted package data does not stay readable in the database file', async () => {
    const server = await startServer({ HOUSEKEEPING_DELAY_MS: '2500' });
    try {
        const api = client(server.base);
        const { user } = await api.register('alice', 'alice password');
        const token = (await api.login('alice', 'alice password')).data.sessionToken;
        const marker = 'SENDER-MARKER-' + Date.now();
        const { packageId } = (await api.drop(user.id, user.publicKey, [{ name: 'a', content: 'x' }], marker)).data;
        await api.json('DELETE', `/api/package/${packageId}`, null, token);
        await new Promise(r => setTimeout(r, 3500)); // housekeeping checkpoints the WAL
        for (const file of fs.readdirSync(server.dataDir).filter(f => f.startsWith('buzon.db'))) {
            const bytes = fs.readFileSync(path.join(server.dataDir, file));
            assert.equal(bytes.includes(Buffer.from(marker)), false, `${file} still contains the deleted sender name`);
        }
    } finally {
        await server.stop();
    }
});
