// Drop packages: nothing readable about a file reaches the server, the recipient sees and saves the
// real name, and packages sent before format 2 still open. Runs the real public/crypto.js.
const { test, before } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { loadCryptoUtils } = require('./browser-crypto');

const CryptoUtils = loadCryptoUtils();
const subtle = globalThis.crypto.subtle;
const read = file => fs.readFileSync(path.join(__dirname, '..', 'public', file), 'utf8');
const NAME = 'nóminas-2026 confidencial.pdf';
const enc = s => new TextEncoder().encode(s);
const RLO = String.fromCharCode(0x202e);
const NBSP = String.fromCharCode(0xa0);
const ZWSP = String.fromCharCode(0x200b);

let keys;

before(async () => {
    assert.equal(typeof CryptoUtils.encryptDropPackage, 'function');
    assert.equal(typeof CryptoUtils.openDropPackage, 'function');
    keys = await subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']);
});

// What the server would store for a package, in the shape the inbox API returns
const stored = pkg => ({ format: pkg.format, encrypted_session_key: pkg.encryptedSessionKey, encrypted_message: pkg.encryptedMessage, message_iv: pkg.messageIv });

test('stored file bodies are raw IV || ciphertext with nothing readable in them', async () => {
    const content = enc('%PDF-1.7 secret body');
    const pkg = await CryptoUtils.encryptDropPackage(keys.publicKey, 'note', [{ name: NAME, data: content }]);
    const body = Buffer.from(pkg.bodies[0]);
    assert.equal(body.length, content.length + 28);
    for (const leak of ['nóminas', '.pdf', 'PDF-1.7', 'application/pdf', 'filename', 'ciphertext']) {
        assert.equal(body.includes(Buffer.from(leak)), false, `body leaks ${leak}`);
    }
    assert.match(pkg.names[0], /^enc2:[A-Za-z0-9+/]+=*:[A-Za-z0-9+/]+=*$/);
});

test('the recipient gets back the message, names and bytes', async () => {
    const pkg = await CryptoUtils.encryptDropPackage(keys.publicKey, 'hola', [{ name: NAME, data: enc('uno') }, { name: '日本語.bin', data: enc('dos') }]);
    const opened = await CryptoUtils.openDropPackage(keys.privateKey, stored(pkg));
    assert.equal(opened.text, 'hola');
    assert.equal(opened.fileIds.length, 2);
    for (let i = 0; i < 2; i++) {
        const entry = await CryptoUtils.decryptDropEntry(opened.sessionKey, pkg.names[i]);
        assert.equal(entry.id, opened.fileIds[i]);
        assert.equal(entry.name, [NAME, '日本語.bin'][i]);
        const bytes = await CryptoUtils.decryptDropBody(opened.sessionKey, pkg.bodies[i].buffer, 2, entry.id);
        assert.equal(new TextDecoder().decode(bytes), ['uno', 'dos'][i]);
    }
});

test('encrypted names are padded so their length is hidden', async () => {
    const pkg = await CryptoUtils.encryptDropPackage(keys.publicKey, '', [{ name: 'a', data: enc('x') }, { name: 'x'.repeat(150) + '.pdf', data: enc('x') }]);
    assert.equal(pkg.names[0].length, pkg.names[1].length);
});

test('names that try to disguise themselves are cleaned', async () => {
    const shown = async name => {
        const pkg = await CryptoUtils.encryptDropPackage(keys.publicKey, '', [{ name, data: enc('x') }]);
        const opened = await CryptoUtils.openDropPackage(keys.privateKey, stored(pkg));
        return (await CryptoUtils.decryptDropEntry(opened.sessionKey, pkg.names[0])).name;
    };
    // Right-to-left override: "report<RLO>fdp.exe" displays as "reportexe.pdf"
    assert.equal(await shown(`report${RLO}fdp.exe`), 'reportfdp.exe');
    // Whitespace that pushes the real extension out of view
    assert.equal(await shown('invoice.pdf' + NBSP.repeat(80) + '.html'), 'invoice.pdf .html');
    assert.equal(await shown(ZWSP + ZWSP), 'file');
});

test('format 1 packages (sent before) still open', async () => {
    // Built the way the previous drop.js did: unlabelled RSA wrap, no AAD, JSON bodies, "enc:" names
    const sessionKey = await CryptoUtils.generateSessionKey();
    const raw = await subtle.exportKey('raw', sessionKey);
    const message = await CryptoUtils.encryptSymmetric(sessionKey, enc('mensaje v1'));
    const name = await CryptoUtils.encryptSymmetric(sessionKey, CryptoUtils.padTo256(enc('viejo.txt')));
    const body = await CryptoUtils.encryptSymmetric(sessionKey, enc('contenido v1'));
    const v1 = {
        format: 1, encrypted_session_key: await CryptoUtils.encryptAsymmetric(keys.publicKey, raw),
        encrypted_message: message.ciphertext, message_iv: message.iv
    };
    const opened = await CryptoUtils.openDropPackage(keys.privateKey, v1);
    assert.equal(opened.text, 'mensaje v1');
    assert.equal(opened.fileIds, null);
    const entry = await CryptoUtils.decryptDropEntry(opened.sessionKey, `enc:${name.iv}:${name.ciphertext}`);
    assert.deepEqual(entry, { name: 'viejo.txt', id: null });
    const bytes = await CryptoUtils.decryptDropBody(opened.sessionKey, enc(JSON.stringify(body)).buffer, 1, null);
    assert.equal(new TextDecoder().decode(bytes), 'contenido v1');
});

test('names stored before encryption are shown repaired and broken ones safely', async () => {
    const sessionKey = await CryptoUtils.generateSessionKey();
    assert.equal(await CryptoUtils.decryptDropName(sessionKey, 'nÃ³minas 2026.pdf'), 'nóminas 2026.pdf');
    assert.equal(await CryptoUtils.decryptDropName(sessionKey, 'café.txt'), 'café.txt');
    assert.equal(await CryptoUtils.decryptDropName(sessionKey, 'enc:report.pdf'), 'enc:report.pdf');
    assert.equal(await CryptoUtils.decryptDropName(sessionKey, 'enc:AAAAAAAAAAAAAAAA:AAAAAAAAAAAAAAAAAAAAAAAA'), 'encrypted-file');
    assert.deepEqual(await CryptoUtils.decryptDropEntry(sessionKey, 'enc2:AAAAAAAAAAAAAAAA:AAAAAAAAAAAAAAAAAAAAAAAA'), { name: 'encrypted-file', id: null });
    assert.equal(await CryptoUtils.decryptDropName(sessionKey, null), 'file');
});

test('drop.js sends format 2 packages built by encryptDropPackage only', () => {
    const drop = read('drop.js');
    assert.match(drop, /CryptoUtils\.encryptDropPackage\(targetPublicKey, message, files, senderNameInput\)/);
    assert.match(drop, /formData\.append\('format', '2'\)/);
    assert.doesNotMatch(drop, /filename|mimeType|file\.type|encryptSymmetric|encryptAsymmetric/);
    const fileParts = drop.match(/formData\.append\('files'.*$/gm) || [];
    assert.equal(fileParts.length, 1);
    assert.match(fileParts[0], /'encrypted\.bin'\)\);$/);
});

// Behaviour is covered by inbox-v2.test.js; this pins that nothing stored in clear decides the saved file
test('app.js saves downloads only under the decrypted name, with a neutral type', () => {
    const app = read('app.js');
    assert.match(app, /CryptoUtils\.openDropPackage\(currentUser\.privateKey, pkg\)/);
    const download = app.slice(app.indexOf('async function downloadFile('), app.indexOf('function showPackageWarning('));
    assert.match(download, /CryptoUtils\.decryptDropBody\(currentPackageSessionKey, await res\.arrayBuffer\(\), selectedPackage\.format, f\.fileId\)/);
    assert.deepEqual(download.match(/\.download\s*=.*$/gm), ['.download = f.displayName;']);
    assert.deepEqual(download.match(/new Blob\(.*$/gm), ["new Blob([decryptedBuffer], { type: 'application/octet-stream' });"]);
    assert.doesNotMatch(download, /filename|mimeType|original_name|mime_type/);
    assert.doesNotMatch(app, /decryptAsymmetric\(currentUser\.privateKey, pkg/);
});
