// Uploads must be refused before anything is written to disk when they cannot fit the quota.
// Raw sockets let the test send headers and part of a body, then look at the upload directory
// while the request is still open.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const net = require('net');
const path = require('path');
const Database = require('better-sqlite3');
const { startServer, client } = require('./helpers');

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

const BOUNDARY = 'xBoundary7MA4YWxk';
const partHeader = (field, filename) =>
    `--${BOUNDARY}\r\nContent-Disposition: form-data; name="${field}"; filename="${filename}"\r\nContent-Type: application/octet-stream\r\n\r\n`;
const listDir = dir => (fs.existsSync(dir) ? fs.readdirSync(dir) : []);

// Sends the headers and the first piece of a multipart body, keeps the socket open for a while,
// records what appears in `watchDir`, and returns the status line the server answered with
function openUpload({ urlPath, headers, firstChunk, watchDir, holdMs = 400 }) {
    return new Promise((resolve, reject) => {
        const port = Number(new URL(server.base).port);
        const socket = net.connect(port, 'localhost');
        const before = new Set(listDir(watchDir));
        const seen = new Set();
        let response = '';
        const watch = setInterval(() => listDir(watchDir).forEach(f => !before.has(f) && seen.add(f)), 20);
        socket.on('data', chunk => { response += chunk; });
        socket.on('error', () => {});
        socket.on('connect', () => {
            const lines = [`POST ${urlPath} HTTP/1.1`, `Host: localhost:${port}`, `Content-Type: multipart/form-data; boundary=${BOUNDARY}`, ...headers];
            socket.write(lines.join('\r\n') + '\r\n\r\n');
            socket.write(firstChunk);
            setTimeout(() => {
                clearInterval(watch);
                socket.destroy();
                const status = Number((response.match(/^HTTP\/1\.1 (\d{3})/) || [])[1]) || null;
                resolve({ status, written: [...seen] });
            }, holdMs);
        });
        setTimeout(() => reject(new Error('timeout')), 10000);
    });
}

const chunked = data => `${Buffer.byteLength(data).toString(16)}\r\n${data}\r\n`;

test('a drop without Content-Length is refused before anything is written', async () => {
    const res = await openUpload({
        urlPath: `/api/drop/${alice.id}`,
        headers: ['Transfer-Encoding: chunked'],
        firstChunk: chunked(partHeader('files', 'encrypted.bin') + 'x'.repeat(200000)),
        watchDir: path.join(server.dataDir, 'drop')
    });
    assert.equal(res.status, 411);
    assert.deepEqual(res.written, []);
});

test('a drop that declares more than the free quota is refused before anything is written', async () => {
    db.prepare('UPDATE users SET mailbox_quota = 100000 WHERE id = ?').run(alice.id);
    try {
        const res = await openUpload({
            urlPath: `/api/drop/${alice.id}`,
            headers: ['Content-Length: 3000000'],
            firstChunk: partHeader('files', 'encrypted.bin') + 'x'.repeat(200000),
            watchDir: path.join(server.dataDir, 'drop')
        });
        assert.equal(res.status, 413);
        assert.deepEqual(res.written, []);
    } finally {
        db.prepare('UPDATE users SET mailbox_quota = 524288000 WHERE id = ?').run(alice.id);
    }
});

test('a share without Content-Length is refused before anything is written', async () => {
    const res = await openUpload({
        urlPath: `/api/share/${alice.id}`,
        headers: ['Transfer-Encoding: chunked', `Authorization: Bearer ${alice.token}`],
        firstChunk: chunked(partHeader('file', 'encrypted.bin') + 'x'.repeat(200000)),
        watchDir: path.join(server.dataDir, 'shares')
    });
    assert.equal(res.status, 411);
    assert.deepEqual(res.written, []);
});

test('a share that declares more than the free quota is refused before anything is written', async () => {
    db.prepare('UPDATE users SET mailbox_quota = 100000 WHERE id = ?').run(alice.id);
    try {
        const res = await openUpload({
            urlPath: `/api/share/${alice.id}`,
            headers: ['Content-Length: 3000000', `Authorization: Bearer ${alice.token}`],
            firstChunk: partHeader('file', 'encrypted.bin') + 'x'.repeat(200000),
            watchDir: path.join(server.dataDir, 'shares')
        });
        assert.equal(res.status, 413);
        assert.deepEqual(res.written, []);
    } finally {
        db.prepare('UPDATE users SET mailbox_quota = 524288000 WHERE id = ?').run(alice.id);
    }
});

test('a share for another user is refused before anything is written', async () => {
    const { user: bob } = await api.register('bob', 'bob password');
    const res = await openUpload({
        urlPath: `/api/share/${bob.id}`,
        headers: ['Content-Length: 300000', `Authorization: Bearer ${alice.token}`],
        firstChunk: partHeader('file', 'encrypted.bin') + 'x'.repeat(200000),
        watchDir: path.join(server.dataDir, 'shares')
    });
    assert.equal(res.status, 403);
    assert.deepEqual(res.written, []);
});

test('normal drops and shares still work', async () => {
    assert.equal((await api.drop(alice.id, alice.publicKey, [{ name: 'a.txt', content: 'hello' }])).status, 200);
    assert.equal((await api.share(alice.id, alice.token)).status, 200);
});
