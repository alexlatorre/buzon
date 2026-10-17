// Upload requests get a deliberate time budget (REQUEST_TIMEOUT_MS), and a request cut off half way
// must not leave its temp file behind.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const net = require('net');
const path = require('path');
const { startServer, client } = require('./helpers');

let server, api, alice;

before(async () => {
    server = await startServer({ REQUEST_TIMEOUT_MS: '1500' });
    api = client(server.base);
    alice = (await api.register('alice', 'alice password')).user;
});

after(async () => {
    await server.stop();
});

const BOUNDARY = 'xBoundaryTimeout';

test('a stalled upload is cut off at the configured timeout and leaves no temp file', async () => {
    const dropDir = path.join(server.dataDir, 'drop');
    const port = Number(new URL(server.base).port);
    const socket = net.connect(port, 'localhost');
    const started = Date.now();
    const closedAfter = await new Promise(resolve => {
        socket.on('connect', () => {
            socket.write([
                `POST /api/drop/${alice.id} HTTP/1.1`, `Host: localhost:${port}`,
                `Content-Type: multipart/form-data; boundary=${BOUNDARY}`, 'Content-Length: 5000000', '', ''
            ].join('\r\n'));
            socket.write(`--${BOUNDARY}\r\nContent-Disposition: form-data; name="files"; filename="encrypted.bin"\r\n\r\n` + 'x'.repeat(100000));
            // ...and then never send the rest
        });
        socket.on('data', () => {}); // keep reading, or the close is never seen
        socket.on('error', () => {});
        socket.on('close', () => resolve(Date.now() - started));
        setTimeout(() => { socket.destroy(); resolve(null); }, 8000);
    });
    assert.ok(closedAfter !== null, 'server never closed the stalled request');
    assert.ok(closedAfter >= 1000 && closedAfter < 6000, `closed after ${closedAfter} ms`);

    await new Promise(r => setTimeout(r, 500));
    assert.deepEqual(fs.readdirSync(dropDir).filter(f => f.endsWith('.upload')), []);
});

test('normal requests are unaffected', async () => {
    assert.equal((await fetch(`${server.base}/api/integrity`)).status, 200);
});
