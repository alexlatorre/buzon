// The largest share file is SHARE_MAX_FILE_MB (200 by default): the server enforces it, /api/config tells
// the dashboard, which refuses a larger file before encrypting it and warns past 50 MB (both browsers
// hold the whole file in memory)
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { startServer, client } = require('./helpers');
const { loadAppPage } = require('./app-page');

const MB = 1024 * 1024;
let server, api, alice;

before(async () => {
    server = await startServer({ SHARE_MAX_FILE_MB: '1' });
    api = client(server.base);
    const { user } = await api.register('alice', 'alice password');
    alice = { ...user, token: (await api.login('alice', 'alice password')).data.sessionToken };
});

after(() => server.stop());

test('the limit is configurable, counts the file (not its GCM tag) and is in the config', async () => {
    assert.deepEqual((await api.json('GET', '/api/config')).data, { registrationOpen: true, shareMaxFileBytes: MB });
    assert.equal((await api.share(alice.id, alice.token, { size: MB + 16 })).status, 200);
    const over = await api.share(alice.id, alice.token, { size: MB + 17 });
    assert.equal(over.status, 413);
});

test('the default is 200 MB, and an invalid value stops the server', async () => {
    const plain = await startServer();
    try {
        assert.equal((await client(plain.base).json('GET', '/api/config')).data.shareMaxFileBytes, 200 * MB);
    } finally {
        await plain.stop();
    }
    for (const bad of ['0', '1.5', 'lots', '2000']) {
        await assert.rejects(startServer({ SHARE_MAX_FILE_MB: bad }), /SHARE_MAX_FILE_MB must be/, bad);
    }
});

test('the dashboard refuses a file over the limit and warns about one over 50 MB', async () => {
    const requests = [];
    const page = loadAppPage({
        fetch: async (url, options) => {
            requests.push(url);
            return globalThis.fetch(server.base + url, options);
        }
    });
    for (let i = 0; i < 50 && !requests.includes('/api/config'); i++) await new Promise(r => setTimeout(r, 10));
    await new Promise(r => setTimeout(r, 50));
    page.el('username').value = 'alice';
    page.el('password').value = 'alice password';
    await page.page.handleLogin();

    const pick = size => {
        page.el('share-file').files = [{ name: 'big.bin', size, arrayBuffer: async () => new ArrayBuffer(0) }];
        page.el('share-file').listeners.change[0]();
        return !page.el('share-size-warning').classList.contains('hidden');
    };
    // This server allows 1 MB: a larger file is an error, not a warning, and nothing is uploaded
    assert.equal(pick(2 * MB), false);
    assert.match(page.el('share-upload-msg').textContent, /shares accept up to 1 MB/);
    page.el('share-pw').value = 'correct horse battery';
    page.el('btn-share-upload').disabled = false;
    const before = requests.length;
    await page.page.handleShareUpload();
    assert.equal(requests.slice(before).some(u => u.startsWith('/api/share/')), false);
    assert.match(page.el('share-upload-msg').textContent, /shares accept up to 1 MB/);
    assert.equal(pick(1000), false);
    assert.equal(page.el('share-upload-msg').textContent, '');
});

test('past 50 MB the dashboard and the link page warn about memory', () => {
    const app = fs.readFileSync(path.join(__dirname, '..', 'public', 'app.js'), 'utf8');
    const share = fs.readFileSync(path.join(__dirname, '..', 'public', 'share.js'), 'utf8');
    assert.match(app, /const LARGE_SHARE_BYTES = 50 \* 1024 \* 1024;/);
    assert.match(app, /shareSizeWarning\.classList\.toggle\('hidden', Boolean\(tooLarge\) \|\| file\.size <= LARGE_SHARE_BYTES\)/);
    assert.match(share, /const LARGE_SHARE_BYTES = 50 \* 1024 \* 1024;/);
    assert.match(share, /if \(data\.size > LARGE_SHARE_BYTES\) sizeWarningEl\.classList\.remove\('hidden'\);/);
});
