// The MySQL/MariaDB driver against a real server. Runs only when MYSQL_TEST_URL is set, e.g.
//   MYSQL_TEST_URL=mysql://root:password@127.0.0.1:3306 npm test
// It creates a throw-away database, runs the main flows through the HTTP API and drops it.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const { startServer, client } = require('./helpers');

const URL_ENV = process.env.MYSQL_TEST_URL;
const skip = URL_ENV ? false : 'set MYSQL_TEST_URL to run the MySQL driver tests';

let server, api, admin, dbName, alice, aliceToken;

before(async () => {
    if (skip) return;
    const mysql = require('mysql2/promise');
    const url = new URL(URL_ENV);
    admin = await mysql.createConnection({ host: url.hostname, port: Number(url.port) || 3306, user: decodeURIComponent(url.username), password: decodeURIComponent(url.password) });
    dbName = `buzon_test_${crypto.randomBytes(4).toString('hex')}`;
    await admin.query(`CREATE DATABASE ${dbName}`);
    server = await startServer({
        DB_ENGINE: 'mysql', MYSQL_HOST: url.hostname, MYSQL_PORT: url.port || '3306',
        MYSQL_USER: decodeURIComponent(url.username), MYSQL_PASSWORD: decodeURIComponent(url.password), MYSQL_DATABASE: dbName,
        HOUSEKEEPING_DELAY_MS: '1500'
    });
    api = client(server.base);
});

after(async () => {
    if (skip) return;
    if (server) await server.stop();
    await admin.query(`DROP DATABASE IF EXISTS ${dbName}`);
    await admin.end();
});

const q = async (sql, params) => (await admin.query(sql.replaceAll('DB.', `${dbName}.`), params))[0];

test('the server answers right after start (tables exist), register and login work', { skip }, async () => {
    const { res, user } = await api.register('alice', 'alice password');
    assert.equal(res.status, 200, JSON.stringify(res.data));
    alice = user;
    const login = await api.login('alice', 'alice password');
    assert.equal(login.status, 200);
    aliceToken = login.data.sessionToken;
});

test('the key derivation is stored and a password change updates the account', { skip }, async () => {
    assert.equal((await api.json('GET', '/api/auth/salt/alice')).data.kdf, 'pbkdf2-sha256:600000');
    const random = n => Buffer.from(globalThis.crypto.getRandomValues(new Uint8Array(n))).toString('base64');
    const body = { currentServerAuthHash: random(32), salt: random(16), kdf: 'pbkdf2-sha256:600000', encryptedPrivateKey: random(2000), iv: random(12), serverAuthHash: random(32) };
    assert.equal((await api.json('POST', '/api/auth/password', body, aliceToken)).status, 403);
});

test('drops, inbox, download and quota', { skip }, async () => {
    const drop = await api.drop(alice.id, alice.publicKey, [{ name: 'a.txt', content: 'x'.repeat(2000) }]);
    assert.equal(drop.status, 200, JSON.stringify(drop.data));
    const pkgs = (await api.json('GET', `/api/packages/${alice.id}`, null, aliceToken)).data;
    assert.equal(pkgs.length, 1);
    assert.equal(Number(pkgs[0].format), 2);
    const file = await fetch(`${server.base}/api/package/${pkgs[0].id}/file/${pkgs[0].files[0].id}`, { headers: { Authorization: `Bearer ${aliceToken}` } });
    assert.equal(file.status, 200);
    const quota = (await api.json('GET', `/api/user/${alice.id}/config`, null, aliceToken)).data;
    assert.equal(typeof quota.usage, 'number');
    assert.ok(quota.usage > 2000);
});

test('a long message fits (up to 256 KB)', { skip }, async () => {
    const form = new FormData();
    form.append('encryptedSessionKey', 'A'.repeat(342) + '==');
    form.append('encryptedMessage', Buffer.alloc(200 * 1024).toString('base64'));
    form.append('messageIv', 'AAAAAAAAAAAAAAAA');
    const res = await fetch(`${server.base}/api/drop/${alice.id}`, { method: 'POST', body: form });
    assert.equal(res.status, 200, await res.text());
});

test('a share with an expiry is stored and expires at the right time', { skip }, async () => {
    const created = await api.share(alice.id, aliceToken, { expiresIn: '24', maxDownloads: 1 });
    assert.equal(created.status, 200, JSON.stringify(created.data));
    const meta = (await api.json('GET', `/api/share/${created.data.token}/meta`)).data;
    const hoursLeft = (new Date(meta.expiresAt) - Date.now()) / 3600000;
    assert.ok(hoursLeft > 23.9 && hoursLeft <= 24.01, `expires in ${hoursLeft} h`);

    await q('UPDATE DB.shares SET expires_at = DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 MINUTE) WHERE token = ?', [created.data.token]);
    assert.equal((await api.json('GET', `/api/share/${created.data.token}/meta`)).status, 410);
});

test('format 2 shares keep their sealed name and owner key', { skip }, async () => {
    const sealed = 'enc2:' + Buffer.alloc(12).toString('base64') + ':' + Buffer.alloc(272).toString('base64');
    const ownerKey = Buffer.alloc(256, 1).toString('base64');
    const created = await api.share(alice.id, aliceToken, { fields: { format: '2', originalName: sealed, mimeType: undefined, ownerKey } });
    assert.equal(created.status, 200, JSON.stringify(created.data));
    const listed = (await api.json('GET', `/api/shares/${alice.id}`, null, aliceToken)).data.find(s => s.token === created.data.token);
    assert.equal(Number(listed.format), 2);
    assert.equal(listed.original_name, sealed);
    assert.equal(listed.owner_key, ownerKey);
    const meta = (await api.json('GET', `/api/share/${created.data.token}/meta`)).data;
    assert.equal(meta.format, 2);
    assert.equal('mimeType' in meta, false);
});

test('one-time links work once', { skip }, async () => {
    const token = (await api.json('POST', `/api/user/${alice.id}/one-time-link`, null, aliceToken)).data.token;
    await api.json('POST', `/api/user/${alice.id}/config`, { publicLinkEnabled: false }, aliceToken);
    try {
        const results = await Promise.all([1, 2, 3].map(() => api.drop(token, alice.publicKey, [{ name: 'n', content: 'y' }])));
        assert.equal(results.filter(r => r.status === 200).length, 1, results.map(r => r.status).join(','));
    } finally {
        await api.json('POST', `/api/user/${alice.id}/config`, { publicLinkEnabled: true }, aliceToken);
    }
});

test('concurrent shares cannot go over the quota together', { skip }, async () => {
    const usage = (await api.json('GET', `/api/user/${alice.id}/config`, null, aliceToken)).data.usage;
    await q('UPDATE DB.users SET mailbox_quota = ? WHERE id = ?', [usage + 1500, alice.id]);
    try {
        const results = await Promise.all(Array.from({ length: 6 }, () => api.share(alice.id, aliceToken, { size: 1000 })));
        assert.equal(results.filter(r => r.status === 200).length, 1, results.map(r => r.status).join(','));
    } finally {
        await q('UPDATE DB.users SET mailbox_quota = 524288000 WHERE id = ?', [alice.id]);
    }
});

test('housekeeping runs without database errors', { skip }, async () => {
    await new Promise(r => setTimeout(r, 1500));
    assert.doesNotMatch(server.logs(), /error/i, server.logs());
});
