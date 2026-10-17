// Drop attachments must not carry their name or type in clear text: the stored payload is only
// { ciphertext, iv }, and the download uses the encrypted name. Runs the real public/crypto.js.
const { test, before } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { loadCryptoUtils } = require('./browser-crypto');

const CryptoUtils = loadCryptoUtils();
const subtle = globalThis.crypto.subtle;
const read = file => fs.readFileSync(path.join(__dirname, '..', 'public', file), 'utf8');
const NAME = 'nóminas-2026 confidencial.pdf';

let sessionKey;

before(async () => {
    assert.equal(typeof CryptoUtils.encryptDropFile, 'function');
    assert.equal(typeof CryptoUtils.decryptDropFile, 'function');
    sessionKey = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
});

test('the stored payload holds only the ciphertext and its IV', async () => {
    const content = new TextEncoder().encode('%PDF-1.7 secret body');
    const { payload, encryptedName } = await CryptoUtils.encryptDropFile(sessionKey, content, NAME);

    assert.deepEqual(Object.keys(JSON.parse(payload)).sort(), ['ciphertext', 'iv']);
    for (const leak of [NAME, 'nóminas', '.pdf', 'application/pdf', 'filename', 'mimeType']) {
        assert.ok(!payload.includes(leak), `payload leaks ${leak}`);
    }
    assert.match(encryptedName, /^enc:[A-Za-z0-9+/]+=*:[A-Za-z0-9+/]+=*$/);
    assert.ok(!encryptedName.includes('nóminas'));
});

test('the payload and the name decrypt with the session key', async () => {
    const content = new TextEncoder().encode('round trip');
    const { payload, encryptedName } = await CryptoUtils.encryptDropFile(sessionKey, content, NAME);

    const body = await CryptoUtils.decryptDropFile(sessionKey, payload);
    assert.equal(new TextDecoder().decode(body), 'round trip');
    assert.equal(await CryptoUtils.decryptDropName(sessionKey, encryptedName), NAME);
});

test('encrypted names are padded so their length is hidden', async () => {
    const short = await CryptoUtils.encryptDropFile(sessionKey, new Uint8Array(1), 'a');
    const long = await CryptoUtils.encryptDropFile(sessionKey, new Uint8Array(1), 'x'.repeat(200) + '.pdf');
    assert.equal(short.encryptedName.length, long.encryptedName.length);
    assert.equal(await CryptoUtils.decryptDropName(sessionKey, short.encryptedName), 'a');
});

test('decryptDropName shows the real name and nothing that can disguise it', async () => {
    const shown = async name => CryptoUtils.decryptDropName(sessionKey, (await CryptoUtils.encryptDropFile(sessionKey, new Uint8Array(1), name)).encryptedName);
    assert.equal(await shown(NAME), NAME);
    assert.equal(await shown('日本語.bin'), '日本語.bin');
    // Right-to-left override: "report\u202Efdp.exe" displays as "reportexe.pdf"
    assert.equal(await shown('report\u202Efdp.exe'), 'reportfdp.exe');
    // Whitespace that pushes the real extension out of view
    assert.equal(await shown('invoice.pdf' + '\u00a0'.repeat(80) + '.html'), 'invoice.pdf .html');
    assert.equal(await shown('\u200b\u200b'), 'file');
});

test('decryptDropName handles names stored before encryption and broken ones', async () => {
    // Pre-encryption rows went through multer, which reads UTF-8 names as latin1
    assert.equal(await CryptoUtils.decryptDropName(sessionKey, 'nÃ³minas 2026.pdf'), 'nóminas 2026.pdf');
    assert.equal(await CryptoUtils.decryptDropName(sessionKey, 'café.txt'), 'café.txt');
    assert.equal(await CryptoUtils.decryptDropName(sessionKey, 'enc:report.pdf'), 'enc:report.pdf');
    assert.equal(await CryptoUtils.decryptDropName(sessionKey, 'enc:AAAAAAAAAAAAAAAA:AAAAAAAAAAAAAAAAAAAAAAAA'), 'encrypted-file');
    assert.equal(await CryptoUtils.decryptDropName(sessionKey, null), 'file');
});

test('drop.js builds attachments only through encryptDropFile', () => {
    const drop = read('drop.js');
    assert.match(drop, /CryptoUtils\.encryptDropFile\(/);
    assert.doesNotMatch(drop, /filename|mimeType|file\.type/);
    // Every file part is sent under the fixed name, never the real one
    const fileParts = drop.match(/formData\.append\('files'.*$/gm) || [];
    assert.equal(fileParts.length, 1);
    assert.match(fileParts[0], /'encrypted\.bin'\);$/);
    assert.doesNotMatch(fileParts[0], /file\.name/);
});

test('app.js saves downloads under the decrypted name with a neutral type', () => {
    const app = read('app.js');
    const download = app.slice(app.indexOf('async function downloadFile('), app.indexOf('async function decryptFileName('));
    assert.match(download, /CryptoUtils\.decryptDropFile\(/);
    assert.deepEqual(download.match(/\.download\s*=.*$/gm), ['.download = f.displayName;']);
    assert.deepEqual(download.match(/new Blob\(.*$/gm), ["new Blob([decryptedBuffer], { type: 'application/octet-stream' });"]);
    assert.doesNotMatch(download, /filename|mimeType|original_name|mime_type/);
    assert.match(app, /return CryptoUtils\.decryptDropName\(currentPackageSessionKey, storedName\);/);
});
