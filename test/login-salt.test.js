// The login page (real app.js) checks the salt the server returns before using the password with it:
// a malformed salt is refused, and a salt that changed since the last login in this browser needs
// the user's confirmation, so a malicious server cannot quietly collect hashes under a salt it chose
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const { startServer, client } = require('./helpers');
const { loadCryptoUtils } = require('./browser-crypto');
const { loadAppPage } = require('./app-page');

const CryptoUtils = loadCryptoUtils();
let server, api;

before(async () => {
    server = await startServer();
    api = client(server.base);
    assert.equal((await api.register('carol', 'carol password')).res.status, 200);
});

after(() => server.stop());

// Runs handleLogin in a page whose requests reach the test server; `salt` can replace the salt it
// returns. Records the requests made and the confirmation dialogs shown.
async function loginPage(username, password, { storage = new Map(), salt, confirmAnswer = true, brokenStorage = false } = {}) {
    const requests = [];
    const confirms = [];
    const fetch = async (url, options) => {
        requests.push(url);
        const res = await globalThis.fetch(server.base + url, options);
        if (salt !== undefined && url.startsWith('/api/auth/salt/')) return new Response(JSON.stringify({ salt }), { status: 200 });
        return res;
    };
    const ui = loadAppPage({ fetch, storage, confirm: msg => (confirms.push(msg), confirmAnswer) });
    if (brokenStorage) ui.window.localStorage = { getItem() { throw new Error('blocked'); }, setItem() { throw new Error('blocked'); } };
    ui.el('username').value = username;
    ui.el('password').value = password;
    await ui.page.handleLogin();
    return { ...ui, requests, confirms, loggedIn: Boolean(ui.page.user.sessionToken), message: ui.el('auth-msg').textContent };
}

const loginPosts = requests => requests.filter(u => u === '/api/auth/login').length;

test('only a canonical 16-byte base64 salt is accepted', () => {
    for (let i = 0; i < 200; i++) {
        const salt = CryptoUtils.generateSalt();
        assert.equal(CryptoUtils.checkLoginSalt(salt).byteLength, 16, salt);
        // Fake salts for unknown usernames are built the same way on the server
        const fake = crypto.createHmac('sha256', String(i)).update('x').digest().subarray(0, 16).toString('base64');
        assert.equal(CryptoUtils.checkLoginSalt(fake).byteLength, 16, fake);
    }
    const bad = ['', 'AAAA', 'AAAAAAAAAAAAAAAAAAAAAA==', '/////////////////////w==', 'AAAAAAAAAAAAAAAAAAAAAA', 'AAAAAAAAAAAAAAAAAAAAAB==', 'AAAAAAAAAAAAAAAAAAAAAA==\n',
        Buffer.alloc(15).toString('base64'), Buffer.alloc(32).toString('base64'), 'AAAAAAAAAAAAAAAAAAAA-A==', null, 16, ['AAAAAAAAAAAAAAAAAAAAAA==']];
    for (const salt of bad) assert.throws(() => CryptoUtils.checkLoginSalt(salt), /invalid login salt/, JSON.stringify(salt));
});

test('the first login in a browser remembers the salt, and the next one does not ask', async () => {
    const storage = new Map();
    const first = await loginPage('carol', 'carol password', { storage });
    assert.equal(first.loggedIn, true, first.message);
    assert.equal(storage.size, 1);
    assert.equal([...storage.keys()][0].includes('carol'), false, 'the username is not stored in clear');
    const second = await loginPage('carol', 'carol password', { storage });
    assert.equal(second.loggedIn, true);
    assert.deepEqual(second.confirms, []);
});

test('a changed salt is not used unless the user confirms', async () => {
    const storage = new Map();
    await loginPage('carol', 'carol password', { storage });
    const pin = new Map(storage);
    const other = CryptoUtils.generateSalt();

    const cancelled = await loginPage('carol', 'carol password', { storage, salt: other, confirmAnswer: false });
    assert.equal(cancelled.confirms.length, 1);
    assert.match(cancelled.confirms[0], /different login parameters/);
    assert.equal(loginPosts(cancelled.requests), 0, 'nothing derived from the password was sent');
    assert.equal(cancelled.loggedIn, false);
    assert.match(cancelled.message, /Login cancelled/);

    // Confirmed: the hash under the wrong salt does not log in, and the pin stays the real one
    const confirmed = await loginPage('carol', 'carol password', { storage, salt: other, confirmAnswer: true });
    assert.equal(confirmed.confirms.length, 1);
    assert.equal(confirmed.loggedIn, false);
    assert.deepEqual(storage, pin);
});

test('a malformed salt stops the login before the password is used', async () => {
    for (const salt of ['', 'AAAA', Buffer.alloc(32).toString('base64'), 12345, null]) {
        const res = await loginPage('carol', 'carol password', { salt });
        assert.equal(loginPosts(res.requests), 0, JSON.stringify(salt));
        assert.equal(res.loggedIn, false);
        assert.match(res.message, /invalid login salt/);
    }
});

test('the pin does not depend on the case of the username', async () => {
    const storage = new Map();
    await CryptoUtils.pinLogin({ setItem: (k, v) => storage.set(k, v) }, 'Carol', 'x');
    assert.equal(await CryptoUtils.pinnedLogin({ getItem: k => storage.get(k) }, 'carol'), 'x');
});

test('a failed login remembers nothing', async () => {
    const storage = new Map();
    assert.equal((await loginPage('nobody_here', 'some password', { storage })).loggedIn, false);
    assert.equal((await loginPage('carol', 'wrong password', { storage })).loggedIn, false);
    assert.equal(storage.size, 0);
});

test('login still works when the browser blocks storage', async () => {
    const res = await loginPage('carol', 'carol password', { brokenStorage: true });
    assert.equal(res.loggedIn, true, res.message);
});

test('registering in a browser remembers the new account\'s salt', async () => {
    const storage = new Map();
    const ui = loadAppPage({ fetch: (url, options) => globalThis.fetch(server.base + url, options), storage });
    ui.el('username').value = 'dave';
    ui.el('password').value = 'dave password long';
    await ui.page.handleRegister();
    assert.match(ui.el('auth-msg').textContent, /Vault created/);
    const salt = (await api.json('GET', '/api/auth/salt/dave')).data.salt;
    assert.deepEqual([...storage.values()], [`pbkdf2-sha256:600000|${salt}`]);
});
