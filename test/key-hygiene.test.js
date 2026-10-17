// Keys the page keeps after login must not be exportable, the master password must not linger in the
// form, and the boss key / logout must clear decrypted content from the page, not just the variables.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { loadCryptoUtils } = require('./browser-crypto');

const CryptoUtils = loadCryptoUtils();
const subtle = globalThis.crypto.subtle;
const app = fs.readFileSync(path.join(__dirname, '..', 'public', 'app.js'), 'utf8');
const between = (from, to) => app.slice(app.indexOf(from), app.indexOf(to, app.indexOf(from) + from.length));

test('imported private and session keys cannot be exported', async () => {
    const pair = await subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']);
    const pkcs8 = CryptoUtils.bufferToBase64(await subtle.exportKey('pkcs8', pair.privateKey));
    assert.equal((await CryptoUtils.importPrivateKey(pkcs8)).extractable, false);
    const raw = CryptoUtils.bufferToBase64(globalThis.crypto.getRandomValues(new Uint8Array(32)));
    assert.equal((await CryptoUtils.importSessionKey(raw)).extractable, false);
});

test('a share password key is not exportable, the login master key still is', async () => {
    const salt = globalThis.crypto.getRandomValues(new Uint8Array(16));
    assert.equal((await CryptoUtils.deriveMasterKey('share password long', salt, false)).extractable, false);
    // Login needs the raw master key once, to derive the server auth hash
    assert.equal((await CryptoUtils.deriveMasterKey('master password', salt)).extractable, true);
    assert.match(app, /deriveMasterKey\(password, saltBuffer, false\)/);
});

test('the master key and password are not kept after login', () => {
    const state = between('currentUser = {\n            id: data.id', '};');
    assert.doesNotMatch(state, /masterKey/);
    const login = between('async function handleLogin(', 'function secureLogout(');
    assert.match(login, /document\.getElementById\('password'\)\.value = '';/);
});

test('logout clears decrypted content and links from the page', () => {
    const logout = between('function secureLogout(', '\n}\n');
    for (const pattern of [
        /getElementById\('modal-message'\)\.textContent = ''/,
        /getElementById\('modal-sender'\)\.textContent = ''/,
        /getElementById\('modal-files'\)\.replaceChildren\(\)/,
        /pkgList\.replaceChildren\(\)/,
        /otlListUI\.replaceChildren\(\)/,
        /dropLink\.textContent = ''/,
        /getElementById\('share-note'\)\.value = ''/,
        /shareResultLink\.value = ''/
    ]) {
        assert.match(logout, pattern);
    }
});
