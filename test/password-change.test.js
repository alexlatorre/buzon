// Per-account key derivation and password change. The browser refuses a key derivation weaker than the
// minimum (so a malicious server cannot ask for a cheap hash), honours a stronger one stored with the
// account, and a password change re-encrypts the same private key: packages, shares and the drop link
// keep working, a stolen session token alone cannot change it, and other sessions end.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const { startServer, client, b64 } = require('./helpers');
const { loadCryptoUtils } = require('./browser-crypto');
const { loadAppPage } = require('./app-page');

const CryptoUtils = loadCryptoUtils();
const subtle = globalThis.crypto.subtle;
let server, api;

before(async () => {
    server = await startServer();
    api = client(server.base);
});

after(() => server.stop());

const toServer = salt => (url, options) => {
    if (salt && url.startsWith('/api/auth/salt/')) return salt(url);
    return globalThis.fetch(server.base + url, options);
};

// Logs in through the real page; returns the page and what it showed
async function loginPage(username, password, { storage = new Map(), fetch, confirm } = {}) {
    const requests = [];
    const base = fetch || toServer();
    const ui = loadAppPage({ fetch: (url, options) => (requests.push(url), base(url, options)), storage, confirm });
    ui.el('username').value = username;
    ui.el('password').value = password;
    await ui.page.handleLogin();
    return { ...ui, requests, loggedIn: Boolean(ui.page.user.sessionToken), message: ui.el('auth-msg').textContent };
}

async function changePassword(ui, current, next, repeat = next) {
    ui.el('pw-current').value = current;
    ui.el('pw-new').value = next;
    ui.el('pw-confirm').value = repeat;
    await ui.page.handleChangePassword();
    return ui.el('pw-msg').textContent;
}

// An account registered the way app.js does, with a chosen key derivation (RSA-2048 for speed)
async function registerWithKdf(username, password, kdf, iterations = CryptoUtils.parseKdf(kdf)) {
    const salt = CryptoUtils.generateSalt();
    const masterKey = await CryptoUtils.deriveMasterKey(password, CryptoUtils.base64ToBuffer(salt), true, iterations);
    const pair = await subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']);
    const pkcs8 = b64(await subtle.exportKey('pkcs8', pair.privateKey));
    const enc = await CryptoUtils.encryptSymmetric(masterKey, new TextEncoder().encode(pkcs8));
    return api.json('POST', '/api/auth/register', {
        username, salt, kdf, publicKey: b64(await subtle.exportKey('spki', pair.publicKey)),
        encryptedPrivateKey: enc.ciphertext, iv: enc.iv, serverAuthHash: await CryptoUtils.computeServerAuthHash(masterKey)
    });
}

test('only PBKDF2-SHA256 descriptors between the minimum and the maximum are accepted', () => {
    assert.equal(CryptoUtils.parseKdf(CryptoUtils.KDF_DEFAULT), 600000);
    assert.equal(CryptoUtils.parseKdf('pbkdf2-sha256:1000000'), 1000000);
    assert.equal(CryptoUtils.parseKdf('pbkdf2-sha256:10000000'), 10000000);
    for (const bad of ['pbkdf2-sha256:1000', 'pbkdf2-sha256:599999', 'pbkdf2-sha256:10000001', 'pbkdf2-sha256:0600000',
        'pbkdf2-sha1:600000', 'argon2id:600000', 'pbkdf2-sha256:600000 ', '', undefined, null, 600000]) {
        assert.throws(() => CryptoUtils.parseKdf(bad), /unsupported key derivation/, String(bad));
    }
    // Pins written before the key derivation was stored hold the salt alone
    assert.equal(CryptoUtils.sameLoginParams('c2FsdHNhbHRzYWx0c2FsdA==', 'pbkdf2-sha256:600000|c2FsdHNhbHRzYWx0c2FsdA=='), true);
    assert.equal(CryptoUtils.sameLoginParams('c2FsdHNhbHRzYWx0c2FsdA==', 'pbkdf2-sha256:900000|c2FsdHNhbHRzYWx0c2FsdA=='), false);
});

test('the server stores and returns the key derivation, and refuses weak ones', async () => {
    assert.equal((await registerWithKdf('weak_kdf', 'password one', 'pbkdf2-sha256:600000')).status, 200);
    // Otherwise valid registrations that declare a weak or unknown key derivation
    // Stronger ones too: an account must not stand out from the answers for unknown usernames
    for (const kdf of ['pbkdf2-sha256:1000', 'pbkdf2-sha256:1000000', 'argon2id:1', 42]) {
        const weak = await registerWithKdf('weaker', 'password one', kdf, 1000);
        assert.equal(weak.status, 400, String(kdf));
        assert.equal(weak.data.error, 'Invalid key derivation');
    }
    assert.equal((await api.json('GET', '/api/auth/salt/weak_kdf')).data.kdf, 'pbkdf2-sha256:600000');
    // Unknown usernames look the same
    assert.equal((await api.json('GET', '/api/auth/salt/nobody_at_all')).data.kdf, 'pbkdf2-sha256:600000');
});

test('the browser and the server agree on the default key derivation', () => {
    const server = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
    assert.equal(/const DEFAULT_KDF = '([^']+)';/.exec(server)[1], CryptoUtils.KDF_DEFAULT);
});

test('an account with a stronger key derivation logs in with it', async () => {
    // As an account created before the default was raised would look: stored with its own derivation
    const registered = await registerWithKdf('strong_kdf', 'strong password', CryptoUtils.KDF_DEFAULT, 1000000);
    assert.equal(registered.status, 200);
    const db = new Database(path.join(server.dataDir, 'buzon.db'));
    db.prepare("UPDATE users SET kdf = 'pbkdf2-sha256:1000000' WHERE username = 'strong_kdf'").run();
    db.close();
    assert.equal((await api.json('GET', '/api/auth/salt/strong_kdf')).data.kdf, 'pbkdf2-sha256:1000000');
    const res = await loginPage('strong_kdf', 'strong password');
    assert.equal(res.loggedIn, true, res.message);
});

test('a key derivation weaker than the minimum is refused before the password is used', async () => {
    await api.register('frank', 'frank password');
    const fake = kdf => async url => {
        const real = await (await globalThis.fetch(server.base + url)).json();
        return new Response(JSON.stringify({ ...real, kdf }), { status: 200 });
    };
    for (const kdf of ['pbkdf2-sha256:1', 'pbkdf2-sha256:100000', 'md5:1', null]) {
        const res = await loginPage('frank', 'frank password', { fetch: toServer(fake(kdf)) });
        assert.equal(res.loggedIn, false);
        assert.equal(res.requests.includes('/api/auth/login'), false, String(kdf));
        assert.match(res.message, /unsupported key derivation/);
    }
    // A stronger one the account does not have: asked about (it differs from the pin), and not accepted
    const storage = new Map();
    await loginPage('frank', 'frank password', { storage });
    const confirms = [];
    const res = await loginPage('frank', 'frank password', { storage, fetch: toServer(fake('pbkdf2-sha256:700000')), confirm: m => (confirms.push(m), false) });
    assert.equal(confirms.length, 1);
    assert.equal(res.loggedIn, false);
});

test('changing the password keeps the keys, ends other sessions and needs the current password', async () => {
    await api.register('grace', 'grace old password');
    const other = (await api.login('grace', 'grace old password')).data.sessionToken;
    const storage = new Map();
    const ui = await loginPage('grace', 'grace old password', { storage });
    assert.equal(ui.loggedIn, true);
    const fingerprint = ui.page.user.keyFingerprint;
    const drop = await api.drop(ui.page.user.id, (await api.json('GET', `/api/user/${ui.page.user.id}/public-key`)).data.publicKey, [{ name: 'a.txt', content: 'before' }]);
    assert.equal(drop.status, 200);

    // Checks in the page before anything is sent
    assert.match(await changePassword(ui, 'grace old password', 'short'), /at least 8/);
    assert.match(await changePassword(ui, 'grace old password', 'new password one', 'new password two'), /do not match/);
    assert.match(await changePassword(ui, 'grace old password', 'grace old password'), /same as the current/);

    // Wrong current password: refused, and the session is not thrown away
    assert.match(await changePassword(ui, 'not my password', 'grace new password'), /current password is wrong/);
    assert.ok(ui.page.user.sessionToken);

    assert.match(await changePassword(ui, 'grace old password', 'grace new password'), /Password changed/);
    assert.equal(ui.el('pw-current').value, '');
    assert.equal(ui.el('pw-new').value, '');

    // The old password no longer works, the new one does, with the same key pair and the same packages
    assert.equal((await api.login('grace', 'grace old password')).status, 401);
    const again = await loginPage('grace', 'grace new password', { storage, confirm: () => assert.fail('no prompt: the pin was updated') });
    assert.equal(again.loggedIn, true, again.message);
    assert.equal(again.page.user.keyFingerprint, fingerprint);
    const pkgs = (await api.json('GET', `/api/packages/${again.page.user.id}`, null, again.page.user.sessionToken)).data;
    assert.equal(pkgs.length, 1);
    again.page.packages = pkgs;
    await again.page.openPackage(pkgs[0].id);
    assert.equal(again.el('modal-message').textContent, 'hello');

    // The other session ended; the one that changed the password still works
    assert.equal((await api.json('GET', `/api/packages/${ui.page.user.id}`, null, other)).status, 401);
    assert.equal((await api.json('GET', `/api/packages/${ui.page.user.id}`, null, ui.page.user.sessionToken)).status, 200);
});

test('a session token alone cannot change the password', async () => {
    await api.register('heidi', 'heidi password');
    const token = (await api.login('heidi', 'heidi password')).data.sessionToken;
    const random = n => b64(globalThis.crypto.getRandomValues(new Uint8Array(n)));
    const body = {
        currentServerAuthHash: random(32), salt: random(16), kdf: 'pbkdf2-sha256:600000',
        encryptedPrivateKey: random(2000), iv: random(12), serverAuthHash: random(32)
    };
    assert.equal((await api.json('POST', '/api/auth/password', body, token)).status, 403);
    assert.equal((await api.json('POST', '/api/auth/password', body)).status, 401);
    assert.equal((await api.json('POST', '/api/auth/password', { ...body, kdf: 'pbkdf2-sha256:1000' }, token)).status, 400);
    assert.equal((await api.json('POST', '/api/auth/password', { ...body, kdf: 'pbkdf2-sha256:1000000' }, token)).status, 400);
    assert.equal((await api.json('POST', '/api/auth/password', { ...body, salt: 'AAAA' }, token)).status, 400);
    assert.equal((await api.login('heidi', 'heidi password')).status, 200);
});

test('logging out while the change is answered does not leak into the next session', async () => {
    await api.register('ivan', 'ivan old password');
    const storage = new Map();
    const holder = {};
    // The boss key pressed after the server applied the change, before the page got the answer
    const fetch = async (url, options) => {
        const res = await globalThis.fetch(server.base + url, options);
        if (url === '/api/auth/password') holder.ui.page.logout();
        return res;
    };
    const ui = holder.ui = await loginPage('ivan', 'ivan old password', { storage, fetch });
    await changePassword(ui, 'ivan old password', 'ivan new password');
    assert.equal(ui.page.user.sessionToken, null);
    assert.equal(ui.page.user.encryptedPrivateKey, undefined);
    assert.equal(ui.el('pw-msg').textContent.includes('Password changed'), false);
    // The change went through and the pin follows it: the next login does not ask
    const again = await loginPage('ivan', 'ivan new password', { storage, confirm: () => assert.fail('no prompt') });
    assert.equal(again.loggedIn, true, again.message);
});
