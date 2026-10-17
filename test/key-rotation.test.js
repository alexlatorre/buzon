// Key rotation: a new key pair replaces the old one and only the small keys move (package session
// keys, share owner name keys), wrapped again under the same label. Packages and shares keep opening
// with the new key, an old copy of the encrypted private key opens none of the keys stored now, lists
// that leave something out are refused, a stolen session token is not enough, and a drop encrypted for
// the old key is refused. Runs the real app.js and drop.js against a test server.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const { startServer, client, b64 } = require('./helpers');
const { loadCryptoUtils } = require('./browser-crypto');
const { loadAppPage, fakeElement } = require('./app-page');

const CryptoUtils = loadCryptoUtils();
const subtle = globalThis.crypto.subtle;
const read = f => fs.readFileSync(path.join(__dirname, '..', 'public', f), 'utf8');
const enc = s => new TextEncoder().encode(s);
const unb64 = s => Buffer.from(s, 'base64');
const randomB64 = n => b64(globalThis.crypto.getRandomValues(new Uint8Array(n)));
const settle = () => new Promise(r => setTimeout(r, 30));
const SHARE_PASSWORD = 'correct horse battery';

let server, api;

before(async () => {
    server = await startServer();
    api = client(server.base);
});

after(() => server.stop());

const toServer = (url, options) => globalThis.fetch(server.base + url, options);

// Logs in through the real page
async function loginPage(username, password, { storage = new Map(), fetch = toServer, confirm } = {}) {
    const ui = loadAppPage({ fetch, storage, confirm });
    ui.el('username').value = username;
    ui.el('password').value = password;
    await ui.page.handleLogin();
    assert.ok(ui.page.user.sessionToken, ui.el('auth-msg').textContent);
    return ui;
}

async function rotate(ui, password) {
    ui.el('rotate-pw').value = password;
    await ui.page.handleRotateKeys();
    return ui.el('rotate-msg').textContent;
}

const publicKeyOf = async id => (await api.json('GET', `/api/user/${id}/public-key`)).data.publicKey;
const fingerprint = spki => CryptoUtils.publicKeyFingerprint(spki);

function rows(sql, ...params) {
    const db = new Database(path.join(server.dataDir, 'buzon.db'), { readonly: true });
    try {
        return db.prepare(sql).all(...params);
    } finally {
        db.close();
    }
}

// Everything a rotation must not touch, and the keys it must move
const snapshot = userId => ({
    user: rows('SELECT public_key, salt, encrypted_private_key, iv FROM users WHERE id = ?', userId)[0],
    packages: rows('SELECT id, format, encrypted_session_key, encrypted_message, message_iv, sender_name FROM packages WHERE user_id = ? ORDER BY id', userId),
    files: rows('SELECT pf.id, pf.original_name, pf.size FROM package_files pf JOIN packages p ON pf.package_id = p.id WHERE p.user_id = ? ORDER BY pf.id', userId),
    shares: rows('SELECT token, format, owner_key, original_name, encrypted_file_key, key_iv, salt, file_iv FROM shares WHERE user_id = ? ORDER BY token', userId)
});

// A package built the way drop.js did before format 2: unlabelled RSA wrap, no AAD, JSON body, "enc:" name
async function dropFormat1(linkId, publicKeyB64, text, name, content) {
    const sessionKey = await CryptoUtils.generateSessionKey();
    const raw = await subtle.exportKey('raw', sessionKey);
    const message = await CryptoUtils.encryptSymmetric(sessionKey, enc(text));
    const sealedName = await CryptoUtils.encryptSymmetric(sessionKey, CryptoUtils.padTo256(enc(name)));
    const body = await CryptoUtils.encryptSymmetric(sessionKey, enc(content));
    const form = new FormData();
    form.append('encryptedSessionKey', await CryptoUtils.encryptAsymmetric(await CryptoUtils.importPublicKey(publicKeyB64), raw));
    form.append('encryptedMessage', message.ciphertext);
    form.append('messageIv', message.iv);
    form.append('files', new Blob([JSON.stringify(body)]), 'encrypted.bin');
    form.append('fileNames', JSON.stringify([`enc:${sealedName.iv}:${sealedName.ciphertext}`]));
    const res = await fetch(`${server.base}/api/drop/${linkId}`, { method: 'POST', body: form });
    assert.equal(res.status, 200, await res.text());
}

// Uploads a share through the real page (format 2); returns its token
async function uploadShare(ui, name, content) {
    ui.el('share-file').files = [{ name, type: 'text/plain', size: content.length, arrayBuffer: async () => enc(content).buffer }];
    ui.el('share-pw').value = SHARE_PASSWORD;
    ui.el('share-note').value = '';
    ui.el('share-expiry').value = '0';
    ui.el('share-max-dl').value = '0';
    ui.el('share-result-link').value = '';
    ui.el('btn-share-upload').disabled = false;
    await ui.page.handleShareUpload();
    const link = ui.el('share-result-link').value;
    assert.match(link, /share\.html\?token=/, ui.el('share-upload-msg').textContent);
    return new URL(link).searchParams.get('token');
}

// Opens every pending package in the page; returns the messages and the saved file contents
async function openAll(ui) {
    const pkgs = (await api.json('GET', `/api/packages/${ui.page.user.id}`, null, ui.page.user.sessionToken)).data;
    ui.page.packages = pkgs;
    const messages = [];
    const contents = [];
    for (const pkg of pkgs) {
        await ui.page.openPackage(pkg.id);
        messages.push(ui.el('modal-message').textContent);
        for (const f of pkg.files) {
            assert.equal(await ui.page.downloadFile(f), true, `file of ${pkg.id}`);
            contents.push(Buffer.from(await ui.saved.at(-1).arrayBuffer()).toString());
        }
    }
    return { messages: messages.sort(), contents: contents.sort() };
}

// Format 2 names show '…' until they are decrypted
async function shareNames(ui) {
    await ui.page.fetchShares();
    const names = () => ui.el('share-list').children.map(item => item.children[0].children[0].textContent).sort();
    for (let i = 0; i < 200 && names().includes('…'); i++) await settle();
    return names();
}

// The private key an attacker gets from a copy of the vault row and the password it was under
async function keyFromVault(row, password) {
    const masterKey = await CryptoUtils.deriveMasterKey(password, CryptoUtils.base64ToBuffer(row.salt), true, 600000);
    const pkcs8 = new TextDecoder().decode(await CryptoUtils.decryptSymmetric(masterKey, row.encrypted_private_key, row.iv));
    return CryptoUtils.importPrivateKey(pkcs8);
}

const opens = (params, key, wrapped) => subtle.decrypt(params, key, unb64(wrapped)).then(() => true, () => false);

test('rotating keys moves package and share keys to a new pair; an old copy of the vault opens none of them', async () => {
    const { user } = await api.register('kate', 'kate password');
    const otherSession = (await api.login('kate', 'kate password')).data.sessionToken;
    const storage = new Map();
    const ui = await loginPage('kate', 'kate password', { storage });
    const oldFingerprint = ui.page.user.keyFingerprint;
    const oldPublicKey = await publicKeyOf(user.id);

    assert.equal((await api.drop(user.id, oldPublicKey, [{ name: 'v2.txt', content: 'cuerpo v2' }])).status, 200);
    await dropFormat1(user.id, oldPublicKey, 'mensaje v1', 'v1.txt', 'cuerpo v1');
    // No rotation starts while a share is uploading (its owner key is for the current key)
    const uploading = uploadShare(ui, 'compartido.pdf', 'contenido');
    assert.match(await rotate(ui, 'kate password'), /Wait until your share upload finishes/);
    await uploading;
    // Built the way app.js did before format 2: no owner key, nothing wrapped for the account
    const oldShare = await api.share(user.id, ui.page.user.sessionToken);
    assert.equal(oldShare.status, 200);
    const before = snapshot(user.id);
    assert.equal(before.packages.length, 2);
    assert.equal(before.shares.length, 2);
    const inDatabaseFiles = value => fs.readdirSync(server.dataDir).filter(f => f.startsWith('buzon.db'))
        .some(file => fs.readFileSync(path.join(server.dataDir, file)).includes(Buffer.from(value)));
    assert.equal(inDatabaseFiles(before.user.encrypted_private_key), true);

    // Checked in the page before anything is sent
    assert.match(await rotate(ui, ''), /Enter your password/);
    assert.match(await rotate(ui, 'not my password'), /password is wrong/);
    assert.equal(ui.page.user.keyFingerprint, oldFingerprint);

    // No share can start while the rotation runs (its owner key would be wrapped for the old key)
    ui.el('rotate-pw').value = 'kate password';
    const rotation = ui.page.handleRotateKeys();
    ui.el('share-file').files = [{ name: 'x', size: 1, arrayBuffer: async () => enc('x').buffer }];
    ui.el('share-pw').value = SHARE_PASSWORD;
    await ui.page.handleShareUpload();
    assert.match(ui.el('share-upload-msg').textContent, /key rotation/);
    await rotation;
    assert.match(ui.el('rotate-msg').textContent, /Keys rotated/);
    assert.equal(ui.el('rotate-pw').value, '');

    // The session uses the new key and shows the new link
    const newFingerprint = ui.page.user.keyFingerprint;
    assert.notEqual(newFingerprint, oldFingerprint);
    assert.equal(await fingerprint(await publicKeyOf(user.id)), newFingerprint);
    const link = CryptoUtils.dropLink('https://box.test', user.id, newFingerprint);
    assert.equal(ui.el('drop-link').textContent, link);
    assert.equal(ui.el('rotate-new-link').value, link);
    assert.equal(ui.el('rotate-result').classList.contains('hidden'), false);

    // Only the wrapped keys and the vault changed: bodies, names, messages and share keys did not
    const after = snapshot(user.id);
    assert.notEqual(after.user.public_key, before.user.public_key);
    assert.notEqual(after.user.salt, before.user.salt);
    assert.notEqual(after.user.encrypted_private_key, before.user.encrypted_private_key);
    assert.deepEqual(after.files, before.files);
    after.packages.forEach((pkg, i) => {
        assert.notEqual(pkg.encrypted_session_key, before.packages[i].encrypted_session_key);
        assert.deepEqual({ ...pkg, encrypted_session_key: null }, { ...before.packages[i], encrypted_session_key: null });
    });
    after.shares.forEach((share, i) => {
        if (share.format === 2) assert.notEqual(share.owner_key, before.shares[i].owner_key);
        else assert.equal(share.owner_key, null);
        assert.deepEqual({ ...share, owner_key: null }, { ...before.shares[i], owner_key: null });
    });
    // The old values are gone from the database files too (WAL checkpointed, secure_delete on)
    const oldValues = [before.user.encrypted_private_key, ...before.packages.map(p => p.encrypted_session_key),
        ...before.shares.filter(s => s.owner_key).map(s => s.owner_key)];
    oldValues.forEach((old, i) => assert.equal(inDatabaseFiles(old), false, `old value #${i} is still in the database files`));

    // A copy of the old vault with the password it was under: it opened the old keys, it opens none now
    const stolen = await keyFromVault(before.user, 'kate password');
    const current = await keyFromVault(after.user, 'kate password');
    for (const [i, pkg] of after.packages.entries()) {
        const params = CryptoUtils.dropKeyParams(pkg.format);
        assert.equal(await opens(params, stolen, before.packages[i].encrypted_session_key), true);
        assert.equal(await opens(params, stolen, pkg.encrypted_session_key), false, `format ${pkg.format} package`);
        assert.equal(await opens(params, current, pkg.encrypted_session_key), true);
    }
    const sealedShare = after.shares.find(s => s.format === 2);
    assert.equal(await opens(CryptoUtils.ownerKeyParams(), stolen, sealedShare.owner_key), false);
    assert.equal(await opens(CryptoUtils.ownerKeyParams(), current, sealedShare.owner_key), true);

    // Both packages and the shares open with the new key, in this session...
    const expected = { messages: ['hello', 'mensaje v1'], contents: ['cuerpo v1', 'cuerpo v2'] };
    assert.deepEqual(await openAll(ui), expected);
    assert.deepEqual(await shareNames(ui), ['compartido.pdf', 'x.bin']);
    // ...and after logging in again, with the same password and no prompt (the pin follows the new salt)
    const again = await loginPage('kate', 'kate password', { storage, confirm: () => assert.fail('no prompt: the pin was updated') });
    assert.equal(again.page.user.keyFingerprint, newFingerprint);
    assert.deepEqual(await openAll(again), expected);
    assert.deepEqual(await shareNames(again), ['compartido.pdf', 'x.bin']);

    // A package sent to the new key opens; the other session ended, this one did not
    assert.equal((await api.drop(user.id, await publicKeyOf(user.id), [{ name: 'new.txt', content: 'nuevo' }])).status, 200);
    assert.ok((await openAll(again)).contents.includes('nuevo'));
    assert.equal((await api.json('GET', `/api/packages/${user.id}`, null, otherSession)).status, 401);
    assert.equal((await api.json('GET', `/api/packages/${user.id}`, null, ui.page.user.sessionToken)).status, 200);
});

test('lists that leave out a package or share, or name one that is not the account\'s, change nothing', async () => {
    const { user } = await api.register('leo', 'leo password');
    const token = (await api.login('leo', 'leo password')).data.sessionToken;
    for (const n of [1, 2]) assert.equal((await api.drop(user.id, user.publicKey, [{ name: `${n}.txt`, content: 'x' }])).status, 200);
    const rawFileKey = globalThis.crypto.getRandomValues(new Uint8Array(32)).buffer;
    const ownerKey = await CryptoUtils.wrapShareNameKeyForOwner(await CryptoUtils.importPublicKey(user.publicKey), rawFileKey);
    const sealed = await CryptoUtils.sealShareName(rawFileKey, 'x');
    assert.equal((await api.share(user.id, token, { fields: { format: '2', originalName: sealed, mimeType: undefined, ownerKey } })).status, 200);
    const { user: mallory } = await api.register('mallory', 'mallory password');
    const foreign = (await api.drop(mallory.id, mallory.publicKey, [{ name: 'm', content: 'm' }])).data.packageId;

    const { body } = await api.rotationBody(user, token);
    assert.equal(body.packages.length, 2);
    assert.equal(body.shares.length, 1);
    assert.ok(body.packages.every(p => typeof p.encryptedSessionKey === 'string'));
    const before = snapshot(user.id);
    const wrapped = body.packages[0].encryptedSessionKey;

    const refused = {
        'a package left out': { packages: body.packages.slice(1) },
        'the share left out': { shares: [] },
        'another account\'s package instead': { packages: [body.packages[1], { id: foreign, encryptedSessionKey: wrapped }] },
        'a package that does not exist': { packages: [...body.packages, { id: crypto.randomUUID(), encryptedSessionKey: wrapped }] },
        'no packages at all': { packages: [], shares: [] }
    };
    for (const [label, change] of Object.entries(refused)) {
        const res = await api.json('POST', '/api/auth/rotate-keys', { ...body, ...change }, token);
        assert.equal(res.status, 409, label);
        assert.equal(res.data.code, 'lists-changed', label);
    }
    const malformed = {
        'the same package twice': { packages: [...body.packages, body.packages[0]] },
        'the same share twice': { shares: [body.shares[0], body.shares[0]] },
        'no lists': { packages: undefined, shares: undefined },
        'a list that is not one': { packages: 'all' },
        'a key that is not the new key\'s size': { packages: [body.packages[0], { ...body.packages[1], encryptedSessionKey: randomB64(512) }] },
        'a missing key': { packages: [body.packages[0], { id: body.packages[1].id }] },
        'an id in another format': { packages: [body.packages[0], { ...body.packages[1], id: body.packages[1].id.toUpperCase() }] },
        'a share token that is not one': { shares: [{ ...body.shares[0], token: '../x' }] }
    };
    for (const [label, change] of Object.entries(malformed)) {
        assert.equal((await api.json('POST', '/api/auth/rotate-keys', { ...body, ...change }, token)).status, 400, label);
    }

    // Nothing was written, the vault included: the old password still logs in to the old key
    assert.deepEqual(snapshot(user.id), before);
    assert.equal((await api.login('leo', 'leo password')).data.encryptedPrivateKey, before.user.encrypted_private_key);
    assert.equal((await api.json('GET', '/api/auth/rotate-keys')).status, 404, 'POST only');

    // The full lists go through
    assert.equal((await api.json('POST', '/api/auth/rotate-keys', body, token)).status, 200);
    assert.equal(await publicKeyOf(user.id), body.publicKey);
});

test('a session token alone cannot rotate the keys', async () => {
    const { user } = await api.register('mia', 'mia password');
    const token = (await api.login('mia', 'mia password')).data.sessionToken;
    assert.equal((await api.drop(user.id, user.publicKey, [{ name: 'a', content: 'a' }])).status, 200);
    const { body } = await api.rotationBody(user, token);

    assert.equal((await api.json('POST', '/api/auth/rotate-keys', { ...body, currentServerAuthHash: randomB64(32) }, token)).status, 403);
    assert.equal((await api.json('POST', '/api/auth/rotate-keys', body)).status, 401);
    assert.equal((await api.json('POST', '/api/auth/rotate-keys', body, crypto.randomUUID())).status, 401);
    for (const [label, change] of Object.entries({
        'weak key derivation': { kdf: 'pbkdf2-sha256:1000' },
        'no current auth hash': { currentServerAuthHash: undefined },
        'not a public key': { publicKey: randomB64(294) },
        'bad salt': { salt: 'AAAA' },
        'the current public key': { publicKey: user.publicKey }
    })) {
        assert.equal((await api.json('POST', '/api/auth/rotate-keys', { ...body, ...change }, token)).status, 400, label);
    }
    // A new salt is required, so the auth hash changes and a password change racing it fails its guard
    const currentSalt = (await api.json('GET', '/api/auth/salt/mia')).data.salt;
    const sameSalt = await api.json('POST', '/api/auth/rotate-keys', { ...body, salt: currentSalt }, token);
    assert.equal(sameSalt.status, 400);
    assert.equal(sameSalt.data.error, 'The new vault must use a new salt');
    assert.equal((await api.json('POST', '/api/auth/rotate-keys', { ...body, serverAuthHash: user.serverAuthHash }, token)).status, 400);
    // Routed and parsed the same in any case, with a trailing slash
    assert.deepEqual((await api.json('POST', '/API/Auth/Rotate-Keys/', { ...body, salt: currentSalt }, token)).data, sameSalt.data);
    // Only key sizes whose wrapped keys drops and shares accept
    const odd = await subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2560, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']);
    const oddKey = await api.json('POST', '/api/auth/rotate-keys', { ...body, publicKey: b64(await subtle.exportKey('spki', odd.publicKey)) }, token);
    assert.equal(oddKey.status, 400);
    assert.equal(oddKey.data.error, 'Invalid public key');

    // Still the old keys
    assert.equal(await publicKeyOf(user.id), user.publicKey);
    assert.equal((await api.login('mia', 'mia password')).status, 200);
});

test('the login auth hash alone cannot swap the public key (proof of the current private key)', async () => {
    const { user } = await api.register('tess', 'tess password');
    // Whoever saw a login request has the auth hash, and with it a session and the encrypted vault
    const stolen = (await api.json('POST', '/api/auth/login', { username: 'tess', serverAuthHash: user.serverAuthHash })).data;
    const attacker = await subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']);
    const body = {
        currentServerAuthHash: user.serverAuthHash, publicKey: b64(await subtle.exportKey('spki', attacker.publicKey)),
        salt: randomB64(16), kdf: 'pbkdf2-sha256:600000', encryptedPrivateKey: stolen.encryptedPrivateKey, iv: stolen.iv,
        serverAuthHash: randomB64(32), packages: [], shares: []
    };
    const attempt = extra => api.json('POST', '/api/auth/rotate-keys', { ...body, ...extra }, stolen.sessionToken);
    const noProof = await attempt({});
    assert.equal(noProof.status, 403);
    assert.equal(noProof.data.code, 'key-proof');
    // A real challenge, but the answer cannot be computed without the private key
    const challenge = (await api.json('POST', '/api/auth/rotate-keys/challenge', null, stolen.sessionToken)).data;
    assert.equal((await attempt({ challengeId: challenge.challengeId, challengeResponse: randomB64(32) })).status, 403);
    assert.equal((await attempt({ challengeId: crypto.randomUUID(), challengeResponse: randomB64(32) })).status, 403);
    // The challenge opens only under its own label, never as a package key, a share key or a migration challenge
    await assert.rejects(CryptoUtils.answerMigrationChallenge(user.privateKey, challenge.challenge));
    assert.equal(await CryptoUtils.rewrapPackageKey(user.privateKey, attacker.publicKey, { format: 2, encrypted_session_key: challenge.challenge }), null);
    assert.equal(await CryptoUtils.rewrapPackageKey(user.privateKey, attacker.publicKey, { format: 1, encrypted_session_key: challenge.challenge }), null);
    assert.equal(await CryptoUtils.rewrapShareOwnerKey(user.privateKey, attacker.publicKey, challenge.challenge), null);
    assert.equal(typeof await CryptoUtils.answerRotationChallenge(user.privateKey, challenge.challenge), 'string');

    assert.equal(await publicKeyOf(user.id), user.publicKey);
    assert.equal((await api.login('tess', 'tess password')).status, 200);
});

test('a share still uploading from a session the rotation ended is refused', async () => {
    const http = require('http');
    const { user } = await api.register('rhea', 'rhea password');
    const token = (await api.login('rhea', 'rhea password')).data.sessionToken;
    const other = (await api.login('rhea', 'rhea password')).data.sessionToken;
    const form = new FormData();
    form.append('file', new Blob([new Uint8Array(1000)]), 'encrypted.bin');
    for (const [k, v] of Object.entries(api.shareFields())) form.append(k, v);
    const request = new Request('http://x/', { method: 'POST', body: form });
    const bytes = Buffer.from(await request.arrayBuffer());
    // The first bytes arrive before the rotation (the session check passes), the rest after it
    let finish;
    const answer = new Promise((resolve, reject) => {
        const req = http.request(`${server.base}/api/share/${user.id}`, {
            method: 'POST',
            headers: { Authorization: `Bearer ${other}`, 'Content-Type': request.headers.get('content-type'), 'Content-Length': bytes.length }
        }, res => {
            let text = '';
            res.on('data', c => { text += c; });
            res.on('end', () => resolve({ status: res.statusCode, text }));
        });
        req.on('error', reject);
        req.write(bytes.subarray(0, 200));
        finish = () => req.end(bytes.subarray(200));
    });
    await settle();
    const { body } = await api.rotationBody(user, token);
    assert.equal((await api.json('POST', '/api/auth/rotate-keys', body, token)).status, 200);
    finish();
    const res = await answer;
    assert.equal(res.status, 401, res.text);
    assert.equal(rows('SELECT COUNT(*) AS n FROM shares WHERE user_id = ?', user.id)[0].n, 0);
});

test('a lost or failed answer: the page asks the server which keys it has', async () => {
    const { user } = await api.register('ugo', 'ugo password');
    assert.equal((await api.drop(user.id, user.publicKey, [{ name: 'a.txt', content: 'uno' }])).status, 200);
    const storage = new Map();
    let mode = 'proxy-error';
    const fetch = async (url, options) => {
        if (url !== '/api/auth/rotate-keys') return toServer(url, options);
        // A proxy error page, or a 200 that is not the server's answer, without the request reaching it
        if (mode === 'proxy-error') return new Response('<html>502 Bad Gateway</html>', { status: 502 });
        if (mode === 'not-the-server') return new Response('<html>Welcome</html>', { status: 200 });
        // The server applies it, but the answer never arrives
        await toServer(url, options);
        throw new TypeError('fetch failed');
    };
    const ui = await loginPage('ugo', 'ugo password', { storage, fetch });
    const oldFingerprint = ui.page.user.keyFingerprint;

    assert.match(await rotate(ui, 'ugo password'), /Nothing changed/);
    assert.equal(ui.page.user.keyFingerprint, oldFingerprint);
    assert.equal(await publicKeyOf(user.id), user.publicKey);
    mode = 'not-the-server';
    assert.match(await rotate(ui, 'ugo password'), /Nothing changed/);
    assert.equal(ui.page.user.keyFingerprint, oldFingerprint);

    mode = 'lost-answer';
    assert.match(await rotate(ui, 'ugo password'), /Keys rotated/);
    assert.notEqual(ui.page.user.keyFingerprint, oldFingerprint);
    assert.equal(ui.page.user.keyFingerprint, await fingerprint(await publicKeyOf(user.id)));
    assert.deepEqual((await openAll(ui)).contents, ['uno']);
    // The pin followed: logging in again does not ask
    const again = await loginPage('ugo', 'ugo password', { storage, confirm: () => assert.fail('no prompt') });
    assert.equal(again.page.user.keyFingerprint, ui.page.user.keyFingerprint);
});

test('the page gives up after three attempts if packages keep arriving', async () => {
    const { user } = await api.register('vera', 'vera password');
    let posts = 0;
    const fetch = async (url, options) => {
        if (url === '/api/auth/rotate-keys') {
            posts++;
            assert.equal((await api.drop(user.id, user.publicKey, [{ name: 'x', content: 'x' }])).status, 200);
        }
        return toServer(url, options);
    };
    const ui = await loginPage('vera', 'vera password', { fetch });
    assert.match(await rotate(ui, 'vera password'), /Turn off the public link/);
    assert.equal(posts, 3);
    assert.equal(await publicKeyOf(user.id), user.publicKey);
});

test('a logout and a new login during the rotation do not lend it the new session', async () => {
    const { user } = await api.register('sam', 'sam password');
    assert.equal((await api.drop(user.id, user.publicKey, [{ name: 's.txt', content: 'sam' }])).status, 200);
    const holder = {};
    const sent = [];
    const fetch = async (url, options) => {
        if (url === '/api/auth/rotate-keys/challenge' && !holder.relogged) {
            holder.relogged = true;
            const res = await toServer(url, options);
            // Double ESC, then the same account logs in again before the rotation sends its request
            holder.ui.page.logout();
            holder.ui.el('username').value = 'sam';
            holder.ui.el('password').value = 'sam password';
            await holder.ui.page.handleLogin();
            return res;
        }
        if (url === '/api/auth/rotate-keys') sent.push(options.headers.Authorization);
        return toServer(url, options);
    };
    const ui = holder.ui = await loginPage('sam', 'sam password', { fetch });
    const firstToken = ui.page.user.sessionToken;
    await rotate(ui, 'sam password');
    // The rotation went out with the session it started in, which the logout ended: nothing changed
    assert.deepEqual(sent, [`Bearer ${firstToken}`]);
    assert.notEqual(ui.page.user.sessionToken, firstToken);
    assert.equal(await publicKeyOf(user.id), user.publicKey);
    // The new session and the server agree on the key, and its packages open
    assert.equal(ui.page.user.keyFingerprint, await fingerprint(user.publicKey));
    assert.deepEqual((await openAll(ui)).contents, ['sam']);
});

// Runs the real drop.js for a link against the test server; returns a function that sends a message
async function dropPage(url) {
    const { search, hash } = new URL(url);
    const elements = {};
    const document = { getElementById: id => (elements[id] ||= fakeElement()), createElement: fakeElement, addEventListener() {} };
    document.getElementById('btn-submit').disabled = true; // as in drop.html
    const window = { location: { search, hash }, crypto: globalThis.crypto, btoa, atob };
    const forms = [];
    const fetch = (u, options) => {
        if (options && options.body instanceof FormData) forms.push(options.body);
        return toServer(u, options);
    };
    const code = read('drop.js').replace('// Initialize\nfetchPublicKey();', 'const __ready = fetchPublicKey();');
    assert.ok(code.includes('const __ready'), 'drop.js no longer ends with fetchPublicKey()');
    const page = new Function('window', 'document', 'fetch', `${read('crypto.js')}\n${code}\nreturn { ready: __ready };`)(window, document, fetch);
    await page.ready;
    const el = id => document.getElementById(id);
    return {
        el, forms,
        async send(text) {
            el('message').value = text;
            el('sender-name').value = 'Sender';
            await el('btn-submit').listeners.click[0]();
            return el('status-msg').textContent;
        }
    };
}

test('a send page opened before the rotation cannot leave a package for the old key', async () => {
    const { user } = await api.register('nina', 'nina password');
    const ui = await loginPage('nina', 'nina password');
    const newOtl = async () => (await api.json('POST', `/api/user/${user.id}/one-time-link`, null, ui.page.user.sessionToken)).data.token;
    const spare = await newOtl();
    const otl = await newOtl();
    const oldFingerprint = ui.page.user.keyFingerprint;
    // Both pages fetched and checked the old key before the rotation
    const publicPage = await dropPage(CryptoUtils.dropLink('https://x', user.id, oldFingerprint));
    const otlPage = await dropPage(CryptoUtils.dropLink('https://x', otl, oldFingerprint));
    assert.equal(publicPage.el('btn-submit').disabled, false);

    // The page says which links stopped working, with the new fingerprint
    const done = await rotate(ui, 'nina password');
    assert.match(done, /Keys rotated/);
    assert.ok(done.includes(ui.page.user.keyFingerprint));
    assert.match(done, /public drop link and your 2 unused one-time link\(s\)/);
    assert.equal(ui.el('btn-replace-otl').classList.contains('hidden'), false);

    assert.match(await publicPage.send('late'), /changed their keys/);
    assert.equal(publicPage.forms[0].get('keyFingerprint'), oldFingerprint);
    assert.match(await otlPage.send('late'), /changed their keys/);
    assert.equal((await api.json('GET', `/api/packages/${user.id}`, null, ui.page.user.sessionToken)).data.length, 0);
    // The one-time link was not used up, and the old links no longer pass the send page's check
    const links = async () => (await api.json('GET', `/api/user/${user.id}/one-time-links`, null, ui.page.user.sessionToken)).data.map(l => l.token).sort();
    assert.deepEqual(await links(), [otl, spare].sort());
    const stale = await dropPage(CryptoUtils.dropLink('https://x', user.id, oldFingerprint));
    assert.equal(stale.el('btn-submit').disabled, true);
    assert.match(stale.el('status-msg').textContent, /may have changed their keys: ask them for their new link/);

    // The new links work, the one-time link included
    for (const id of [user.id, otl]) {
        const page = await dropPage(CryptoUtils.dropLink('https://x', id, ui.page.user.keyFingerprint));
        await page.send(`to ${id}`);
        assert.equal(page.forms[0].get('keyFingerprint'), ui.page.user.keyFingerprint);
        assert.equal(page.el('success-panel').classList.contains('active'), true, page.el('status-msg').textContent);
    }
    assert.deepEqual((await openAll(ui)).messages, [`to ${otl}`, `to ${user.id}`].sort());

    // Replacing the one-time links still unused makes the old tokens useless
    await ui.page.replaceOneTimeLinks();
    assert.match(ui.el('rotate-msg').textContent, /1 one-time link\(s\) replaced/);
    const replaced = await links();
    assert.equal(replaced.length, 1);
    assert.notEqual(replaced[0], spare);
    assert.equal((await api.json('GET', `/api/user/${spare}/public-key`)).status, 404);
    // Anything but a fingerprint is refused
    assert.equal((await api.drop(user.id, await publicKeyOf(user.id), [], 'x', { keyFingerprint: 'short' })).status, 400);
});

test('a package that arrives while the page rotates is picked up by reading the lists again', async () => {
    const { user } = await api.register('olga', 'olga password');
    assert.equal((await api.drop(user.id, user.publicKey, [{ name: 'early.txt', content: 'temprano' }])).status, 200);
    let attempts = 0;
    const fetch = async (url, options) => {
        if (url === '/api/auth/rotate-keys' && ++attempts === 1) {
            // Encrypted for the current key, between the page reading the lists and the server applying them
            assert.equal((await api.drop(user.id, user.publicKey, [{ name: 'late.txt', content: 'tarde' }])).status, 200);
        }
        return toServer(url, options);
    };
    const ui = await loginPage('olga', 'olga password', { fetch });
    assert.match(await rotate(ui, 'olga password'), /Keys rotated/);
    assert.equal(attempts, 2);
    assert.deepEqual((await openAll(ui)).contents, ['tarde', 'temprano']);
});

test('a package the current key cannot open is left as it was', async () => {
    const { user } = await api.register('pia', 'pia password');
    assert.equal((await api.drop(user.id, user.publicKey, [{ name: 'real.txt', content: 'real' }])).status, 200);
    // Junk anyone with the link can send: a session key that was never wrapped for this account
    const junkKey = randomB64(256);
    const form = new FormData();
    for (const [k, v] of Object.entries({ format: '2', senderName: 'junk', encryptedSessionKey: junkKey, encryptedMessage: randomB64(64), messageIv: randomB64(12) })) form.append(k, v);
    assert.equal((await fetch(`${server.base}/api/drop/${user.id}`, { method: 'POST', body: form })).status, 200);
    const junk = rows('SELECT id, encrypted_session_key FROM packages WHERE user_id = ? AND encrypted_session_key = ?', user.id, junkKey)[0];
    assert.ok(junk);

    const ui = await loginPage('pia', 'pia password');
    assert.match(await rotate(ui, 'pia password'), /Keys rotated[\s\S]*1 key\(s\) that your previous key could not open were left as they were/);
    assert.equal(rows('SELECT encrypted_session_key FROM packages WHERE id = ?', junk.id)[0].encrypted_session_key, junk.encrypted_session_key);
    const real = (await api.json('GET', `/api/packages/${user.id}`, null, ui.page.user.sessionToken)).data.filter(p => p.id !== junk.id);
    ui.page.packages = real;
    await ui.page.openPackage(real[0].id);
    assert.equal(ui.el('modal-message').textContent, 'hello');
});

test('logging out while the rotation is answered keeps the new keys out of the next session', async () => {
    const { user } = await api.register('quin', 'quin password');
    const storage = new Map();
    const holder = {};
    // The boss key pressed after the server applied the rotation, before the page got the answer
    const fetch = async (url, options) => {
        const res = await toServer(url, options);
        if (url === '/api/auth/rotate-keys') holder.ui.page.logout();
        return res;
    };
    const ui = holder.ui = await loginPage('quin', 'quin password', { storage, fetch });
    await rotate(ui, 'quin password');
    assert.equal(ui.page.user.sessionToken, null);
    assert.equal(ui.page.user.privateKey, null);
    assert.equal(ui.el('drop-link').textContent, '');
    assert.equal(ui.el('rotate-new-link').value, '');
    assert.doesNotMatch(ui.el('rotate-msg').textContent, /Keys rotated/);
    // The rotation went through and the pin follows it: the next login does not ask
    const again = await loginPage('quin', 'quin password', { storage, confirm: () => assert.fail('no prompt') });
    assert.equal(again.page.user.keyFingerprint, await fingerprint(await publicKeyOf(user.id)));
    assert.notEqual(await publicKeyOf(user.id), user.publicKey);
});

test('a login that races a rotation never keeps a session with the old keys', async () => {
    // Every database call takes a while, as with MySQL, so the two requests interleave
    const slow = await startServer({ DB_TEST_LATENCY_MS: '40' });
    try {
        const slowApi = client(slow.base);
        for (const offset of [5, 15, 25, 35, 45, 60]) {
            const name = `race_${offset}`;
            const { user } = await slowApi.register(name, 'race password');
            const token = (await slowApi.login(name, 'race password')).data.sessionToken;
            const { body } = await slowApi.rotationBody(user, token);
            const rotation = slowApi.json('POST', '/api/auth/rotate-keys', body, token);
            await new Promise(r => setTimeout(r, offset));
            const login = await slowApi.json('POST', '/api/auth/login', { username: name, serverAuthHash: user.serverAuthHash });
            assert.equal((await rotation).status, 200);
            if (login.status !== 200) continue;
            // A session that survived the rotation must have been given the new vault
            const alive = (await slowApi.json('GET', `/api/packages/${user.id}`, null, login.data.sessionToken)).status === 200;
            if (alive) assert.equal(login.data.encryptedPrivateKey, body.encryptedPrivateKey, `login ${offset} ms after the rotation started`);
        }
    } finally {
        await slow.stop();
    }
});
