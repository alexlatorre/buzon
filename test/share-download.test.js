// Holding a share link must not be enough to use up its downloads: only someone who unwrapped the
// file key with the password can send the download proof. Aborted transfers give the download back.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const path = require('path');
const Database = require('better-sqlite3');
const { startServer, client, b64 } = require('./helpers');
const { loadCryptoUtils } = require('./browser-crypto');

const CryptoUtils = loadCryptoUtils();
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

// A share made the way the dashboard makes it: random file key, proof derived from it
async function proofShare({ size = 100, maxDownloads = 1 } = {}) {
    const rawKey = crypto.randomBytes(32);
    const downloadProof = await CryptoUtils.shareDownloadProof(rawKey);
    const { data } = await api.share(alice.id, alice.token, { size, maxDownloads, fields: { downloadProof } });
    return { token: data.token, downloadProof };
}
const downloads = token => db.prepare('SELECT download_count FROM shares WHERE token = ?').get(token).download_count;
const get = (token, headers = {}) => fetch(`${server.base}/api/share/${token}/download`, { headers });

test('the proof is a domain-separated hash of the file key', async () => {
    const rawKey = crypto.randomBytes(32);
    const expected = crypto.createHash('sha256').update('shadowdrop/share-download/v1').update(rawKey).digest('base64');
    assert.equal(await CryptoUtils.shareDownloadProof(rawKey), expected);
});

test('without the proof a link holder cannot download or use up the limit', async () => {
    const share = await proofShare();
    assert.equal((await get(share.token)).status, 403);
    assert.equal((await get(share.token, { 'X-Download-Proof': b64(crypto.randomBytes(32)) })).status, 403);
    assert.equal(downloads(share.token), 0);
    assert.equal((await api.json('GET', `/api/share/${share.token}/meta`)).status, 200);

    const res = await get(share.token, { 'X-Download-Proof': share.downloadProof });
    assert.equal(res.status, 200);
    await res.arrayBuffer();
    assert.equal(downloads(share.token), 1);
    assert.equal((await get(share.token, { 'X-Download-Proof': share.downloadProof })).status, 410);
});

test('a HEAD request does not count as a download', async () => {
    const share = await proofShare();
    const res = await fetch(`${server.base}/api/share/${share.token}/download`, { method: 'HEAD', headers: { 'X-Download-Proof': share.downloadProof } });
    assert.notEqual(res.status, 200);
    assert.equal(downloads(share.token), 0);
});

test('an interrupted transfer gives the download back', async () => {
    const share = await proofShare({ size: 8 * 1024 * 1024 });
    const port = Number(new URL(server.base).port);
    await new Promise(resolve => {
        const socket = net.connect(port, 'localhost', () => {
            socket.write(`GET /api/share/${share.token}/download HTTP/1.1\r\nHost: localhost\r\nX-Download-Proof: ${share.downloadProof}\r\n\r\n`);
        });
        let received = 0;
        socket.on('data', chunk => {
            received += chunk.length;
            if (received > 64 * 1024) { socket.destroy(); resolve(); }
        });
        socket.on('error', () => {});
    });
    await new Promise(r => setTimeout(r, 500));
    assert.equal(downloads(share.token), 0);
    const res = await get(share.token, { 'X-Download-Proof': share.downloadProof });
    assert.equal(res.status, 200);
});

test('the dashboard creates proofs and the share page sends them', () => {
    const read = f => fs.readFileSync(path.join(__dirname, '..', 'public', f), 'utf8');
    assert.match(read('app.js'), /formData\.append\('downloadProof', await CryptoUtils\.shareDownloadProof\(rawKey\)\)/);
    assert.match(read('share.js'), /'X-Download-Proof': await CryptoUtils\.shareDownloadProof\(fileKeyRaw\)/);
});
