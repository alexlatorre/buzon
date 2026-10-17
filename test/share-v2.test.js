// Shares, format 2: the file name and type are not readable on the server or by whoever holds the
// link before the password; the owner still sees their shares by name. Runs the real app.js (upload,
// list) and share.js (download page) against a test server.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const { startServer, client } = require('./helpers');
const { loadCryptoUtils } = require('./browser-crypto');
const { loadAppPage, fakeElement } = require('./app-page');

const CryptoUtils = loadCryptoUtils();
const subtle = globalThis.crypto.subtle;
const read = f => fs.readFileSync(path.join(__dirname, '..', 'public', f), 'utf8');
const NAME = 'informe-secreto ñ.pdf';
const PASSWORD = 'correct horse battery';
const settle = () => new Promise(r => setTimeout(r, 30));

let server, api, owner;

before(async () => {
    server = await startServer();
    api = client(server.base);
    await api.register('erin', 'erin password');
    // Log in through the real page, so currentUser has the keys app.js derives
    owner = loadAppPage({ fetch: (url, options) => globalThis.fetch(server.base + url, options) });
    owner.el('username').value = 'erin';
    owner.el('password').value = 'erin password';
    await owner.page.handleLogin();
    assert.ok(owner.page.user.sessionToken);
});

after(() => server.stop());

// Uploads a file through handleShareUpload and returns its token
async function uploadShare(name, content, type = 'application/pdf') {
    owner.el('share-file').files = [{ name, type, size: content.length, arrayBuffer: async () => new TextEncoder().encode(content).buffer }];
    owner.el('share-pw').value = PASSWORD;
    owner.el('share-note').value = '';
    owner.el('share-expiry').value = '0';
    owner.el('share-max-dl').value = '3';
    owner.el('btn-share-upload').disabled = false;
    await owner.page.handleShareUpload();
    const link = owner.el('share-result-link').value;
    assert.match(link, /share\.html\?token=/, owner.el('share-upload-msg').textContent);
    return new URL(link).searchParams.get('token');
}

// Runs the real share.js for a token; returns its elements and the file it saves
async function sharePage(token) {
    const elements = {};
    const created = [];
    const document = {
        getElementById: id => (elements[id] ||= fakeElement()),
        createElement: tag => { const el = fakeElement(tag); created.push(el); return el; },
        body: fakeElement('body')
    };
    const saved = [];
    const URL_ = { createObjectURL: blob => (saved.push(blob), 'blob:1'), revokeObjectURL() {} };
    const window = { crypto: globalThis.crypto, btoa, atob, location: { search: `?token=${token}`, hash: '' } };
    const fetch = (url, options) => globalThis.fetch(server.base + url, options);
    new Function('window', 'document', 'fetch', 'URL', `${read('crypto.js')}\n${read('share.js')}`)(window, document, fetch, URL_);
    for (let i = 0; i < 50 && !elements['share-filename']?.textContent && !elements['share-error-msg']?.textContent; i++) await settle();
    const el = id => document.getElementById(id);
    return {
        el,
        async unlock(password) {
            el('share-password').value = password;
            await el('btn-share-download').listeners.click[0]();
            const anchor = created.find(a => a.download);
            return { name: anchor && anchor.download, blob: saved[0] };
        }
    };
}

const rawKey = () => globalThis.crypto.getRandomValues(new Uint8Array(32)).buffer;
const sealedAs = async (key, aad) => {
    const c = await CryptoUtils.aesGcmEncrypt(key, CryptoUtils.padTo256(new TextEncoder().encode(JSON.stringify({ name: 'x' }))), aad);
    return `enc2:${Buffer.from(c.iv).toString('base64')}:${Buffer.from(c.ciphertext).toString('base64')}`;
};

test('the sealed name opens with the file key and with nothing else', async () => {
    const raw = rawKey();
    const sealed = await CryptoUtils.sealShareName(raw, NAME);
    assert.match(sealed, /^enc2:/);
    assert.equal(await CryptoUtils.openShareName(raw, sealed), NAME);
    assert.equal(await CryptoUtils.openShareName(rawKey(), sealed), 'encrypted-file');
    assert.equal(await CryptoUtils.openShareName(raw, NAME), 'encrypted-file');
    // Padded: the length of the name does not show
    assert.equal((await CryptoUtils.sealShareName(raw, 'a')).length, (await CryptoUtils.sealShareName(raw, 'x'.repeat(200))).length);
    // Sealed with the file key itself (not the derived name key), or under another role, it does not open
    const fileKey = await subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt']);
    assert.equal(await CryptoUtils.openShareName(raw, await sealedAs(fileKey, CryptoUtils.SHARE_V2.NAME)), 'encrypted-file');
    const nameKey = await CryptoUtils.importShareNameKey(await CryptoUtils.shareNameKeyBytes(raw), ['encrypt']);
    assert.equal(await CryptoUtils.openShareName(raw, await sealedAs(nameKey, CryptoUtils.DROP_V2.NAME)), 'encrypted-file');
    assert.equal(await CryptoUtils.openShareName(raw, await sealedAs(nameKey, CryptoUtils.SHARE_V2.NAME)), 'x');
});

test('the owner gets only the name key: it shows the name and cannot decrypt the file', async () => {
    const keys = await subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']);
    const raw = rawKey();
    const wrapped = await CryptoUtils.wrapShareNameKeyForOwner(keys.publicKey, raw);
    const sealed = await CryptoUtils.sealShareName(raw, NAME);
    assert.equal(await CryptoUtils.ownerShareName(keys.privateKey, wrapped, sealed), NAME);

    const label = new TextEncoder().encode(CryptoUtils.SHARE_V2.OWNER_KEY_LABEL);
    const unwrapped = Buffer.from(await subtle.decrypt({ name: 'RSA-OAEP', label }, keys.privateKey, Buffer.from(wrapped, 'base64')));
    assert.equal(unwrapped.equals(Buffer.from(raw)), false, 'the owner copy is not the file key');
    const fileKey = await subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt']);
    const iv = new Uint8Array(12);
    const body = await subtle.encrypt({ name: 'AES-GCM', iv }, fileKey, new TextEncoder().encode('content'));
    const asFileKey = await subtle.importKey('raw', unwrapped, { name: 'AES-GCM' }, false, ['decrypt']);
    await assert.rejects(subtle.decrypt({ name: 'AES-GCM', iv }, asFileKey, body));
    assert.notEqual(await CryptoUtils.shareDownloadProof(unwrapped), await CryptoUtils.shareDownloadProof(raw));

    // Only under its own label
    const bytes = Buffer.from(wrapped, 'base64');
    await assert.rejects(subtle.decrypt({ name: 'RSA-OAEP' }, keys.privateKey, bytes));
    await assert.rejects(subtle.decrypt({ name: 'RSA-OAEP', label: new TextEncoder().encode(CryptoUtils.DROP_V2.SESSION_KEY_LABEL) }, keys.privateKey, bytes));
    await assert.rejects(CryptoUtils.answerMigrationChallenge(keys.privateKey, wrapped));
    const dropKey = await subtle.encrypt({ name: 'RSA-OAEP', label: new TextEncoder().encode(CryptoUtils.DROP_V2.SESSION_KEY_LABEL) }, keys.publicKey, raw);
    assert.equal(await CryptoUtils.ownerShareName(keys.privateKey, Buffer.from(dropKey).toString('base64'), sealed), 'encrypted-file');
});

test('nothing readable about the file reaches the server or the page before the password', async () => {
    const token = await uploadShare(NAME, 'contenido del informe');
    const db = new Database(path.join(server.dataDir, 'buzon.db'), { readonly: true });
    const row = db.prepare('SELECT * FROM shares WHERE token = ?').get(token);
    db.close();
    assert.equal(row.format, 2);
    assert.match(row.original_name, /^enc2:/);
    assert.equal(row.mime_type, 'application/octet-stream');
    assert.ok(row.owner_key);

    const meta = (await api.json('GET', `/api/share/${token}/meta`)).data;
    const text = JSON.stringify(meta);
    for (const leak of ['informe', '.pdf', 'application/pdf']) assert.equal(text.includes(leak), false, `meta leaks ${leak}`);
    for (const field of ['mimeType', 'createdAt', 'downloadCount', 'maxDownloads']) assert.equal(field in meta, false, field);
    assert.equal(meta.format, 2);
    assert.equal(meta.downloadsLeft, 3);

    const page = await sharePage(token);
    assert.equal(page.el('share-filename').textContent.includes('informe'), false);
    assert.match(page.el('share-limits').innerHTML, /3 downloads remaining/);
});

test('the right password shows and saves the real name, with a neutral type', async () => {
    const token = await uploadShare(NAME, 'contenido del informe');
    const page = await sharePage(token);
    const wrong = await page.unlock('wrong password here');
    assert.equal(wrong.blob, undefined);
    const saved = await page.unlock(PASSWORD);
    assert.equal(saved.name, NAME);
    assert.equal(page.el('share-filename').textContent, NAME);
    assert.equal(saved.blob.type, 'application/octet-stream');
    assert.equal(Buffer.from(await saved.blob.arrayBuffer()).toString(), 'contenido del informe');
});

test('the owner sees their shares by name', async () => {
    await uploadShare('lista-del-owner.txt', 'x');
    await owner.page.fetchShares();
    await settle();
    const names = owner.el('share-list').children.map(item => item.children[0].children[0].textContent);
    assert.ok(names.includes('lista-del-owner.txt'), JSON.stringify(names));
    assert.ok(names.includes(NAME));
    assert.equal(names.some(n => n.startsWith('enc2:')), false);
});

test('shares created before format 2 still download with their name (and a neutral type)', async () => {
    // Built the way the previous app.js did: name and type in clear, no owner key
    const fileKey = await CryptoUtils.generateSessionKey();
    const raw = await subtle.exportKey('raw', fileKey);
    const fileIv = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const body = await subtle.encrypt({ name: 'AES-GCM', iv: fileIv }, fileKey, new TextEncoder().encode('old share'));
    const salt = CryptoUtils.generateSalt(16);
    const derived = await CryptoUtils.deriveMasterKey(PASSWORD, CryptoUtils.base64ToBuffer(salt), false);
    const keyIv = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const wrapped = await subtle.encrypt({ name: 'AES-GCM', iv: keyIv }, derived, raw);
    const form = new FormData();
    form.append('file', new Blob([body]), 'encrypted.bin');
    for (const [k, v] of Object.entries({
        encryptedFileKey: Buffer.from(wrapped).toString('base64'), keyIv: Buffer.from(keyIv).toString('base64'), salt,
        fileIv: Buffer.from(fileIv).toString('base64'), originalName: 'viejo.txt', mimeType: 'text/plain', maxDownloads: '0', expiresIn: '0',
        downloadProof: await CryptoUtils.shareDownloadProof(raw)
    })) form.append(k, v);
    const res = await fetch(`${server.base}/api/share/${owner.page.user.id}`, { method: 'POST', headers: { Authorization: `Bearer ${owner.page.user.sessionToken}` }, body: form });
    const { token } = await res.json();
    const page = await sharePage(token);
    assert.equal(page.el('share-filename').textContent, 'viejo.txt');
    const saved = await page.unlock(PASSWORD);
    assert.equal(saved.name, 'viejo.txt');
    assert.equal(saved.blob.type, 'application/octet-stream');
    assert.equal(Buffer.from(await saved.blob.arrayBuffer()).toString(), 'old share');
});

test('format 2 shares must carry a sealed name and an owner key, and no type', async () => {
    const sealed = await CryptoUtils.sealShareName(rawKey(), 'x');
    const ownerKey = Buffer.from(globalThis.crypto.getRandomValues(new Uint8Array(256))).toString('base64');
    const token = owner.page.user.sessionToken;
    const cases = {
        'plain name': { format: '2', originalName: 'plain.pdf', mimeType: undefined, ownerKey },
        'type sent': { format: '2', originalName: sealed, mimeType: 'application/pdf', ownerKey },
        'no owner key': { format: '2', originalName: sealed, mimeType: undefined },
        'owner key wrong size': { format: '2', originalName: sealed, mimeType: undefined, ownerKey: 'AAAA' },
        'unknown format': { format: '3' },
        'owner key on format 1': { ownerKey }
    };
    for (const [label, fields] of Object.entries(cases)) {
        assert.equal((await api.share(owner.page.user.id, token, { fields })).status, 400, label);
    }
    assert.equal((await api.share(owner.page.user.id, token, { fields: { format: '2', originalName: sealed, mimeType: undefined, ownerKey } })).status, 200);
});
