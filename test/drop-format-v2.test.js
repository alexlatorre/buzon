// Format 2 binds every ciphertext of a package to its role, so a server that rearranges what it
// stores gets a decryption failure or a manifest warning, never a different readable result.
const { test, before } = require('node:test');
const assert = require('node:assert/strict');
const { loadCryptoUtils } = require('./browser-crypto');

const CryptoUtils = loadCryptoUtils();
const subtle = globalThis.crypto.subtle;
const enc = s => new TextEncoder().encode(s);
const AES_FAILURE = { name: 'OperationError' };

let keys, pkg, opened, entries;

const stored = p => ({ format: p.format, encrypted_session_key: p.encryptedSessionKey, encrypted_message: p.encryptedMessage, message_iv: p.messageIv });

before(async () => {
    keys = await subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']);
    pkg = await CryptoUtils.encryptDropPackage(keys.publicKey, 'the message', [
        { name: 'contract.pdf', data: enc('real contract') },
        { name: 'photo.jpg', data: enc('real photo') }
    ]);
    opened = await CryptoUtils.openDropPackage(keys.privateKey, stored(pkg));
    entries = [];
    for (const name of pkg.names) entries.push(await CryptoUtils.decryptDropEntry(opened.sessionKey, name));
});

test('swapping file bodies between files makes decryption fail', async () => {
    await assert.rejects(CryptoUtils.decryptDropBody(opened.sessionKey, pkg.bodies[1].buffer, 2, entries[0].id), AES_FAILURE);
    await assert.rejects(CryptoUtils.decryptDropBody(opened.sessionKey, pkg.bodies[0].buffer, 2, entries[1].id), AES_FAILURE);
});

test('a body cannot be read without the id from its own name', async () => {
    await assert.rejects(CryptoUtils.decryptDropBody(opened.sessionKey, pkg.bodies[0].buffer, 2, null));
    await assert.rejects(CryptoUtils.decryptDropBody(opened.sessionKey, pkg.bodies[0].buffer, 2, 'made-up-id'), AES_FAILURE);
});

test('the message cannot be served as a name, nor a name as the message', async () => {
    const asName = `enc2:${pkg.messageIv}:${pkg.encryptedMessage}`;
    assert.deepEqual(await CryptoUtils.decryptDropEntry(opened.sessionKey, asName), { name: 'encrypted-file', id: null });
    const [, iv, ct] = pkg.names[0].split(':');
    await assert.rejects(CryptoUtils.openDropPackage(keys.privateKey, { ...stored(pkg), encrypted_message: ct, message_iv: iv }), AES_FAILURE);
});

test('a body cannot be served as the message', async () => {
    const body = Buffer.from(pkg.bodies[0]);
    const tampered = { ...stored(pkg), message_iv: body.subarray(0, 12).toString('base64'), encrypted_message: body.subarray(12).toString('base64') };
    await assert.rejects(CryptoUtils.openDropPackage(keys.privateKey, tampered), AES_FAILURE);
});

test('relabelling the package as format 1 does not open it', async () => {
    await assert.rejects(CryptoUtils.openDropPackage(keys.privateKey, { ...stored(pkg), format: 1 }));
});

test('the session key is wrapped under its own OAEP label', async () => {
    const wrapped = Buffer.from(pkg.encryptedSessionKey, 'base64');
    // Not with the plain unwrap (format 1) ...
    await assert.rejects(subtle.decrypt({ name: 'RSA-OAEP' }, keys.privateKey, wrapped), AES_FAILURE);
    // ... nor through the migration challenge answer
    await assert.rejects(CryptoUtils.answerMigrationChallenge(keys.privateKey, pkg.encryptedSessionKey), AES_FAILURE);
});

test('the manifest reveals files dropped or added by the server', async () => {
    const ids = entries.map(e => e.id);
    assert.deepEqual(CryptoUtils.manifestProblems(opened.fileIds, ids), { missing: 0, unexpected: 0 });
    assert.deepEqual(CryptoUtils.manifestProblems(opened.fileIds, [ids[0]]), { missing: 1, unexpected: 0 });
    assert.deepEqual(CryptoUtils.manifestProblems(opened.fileIds, [...ids, null]), { missing: 0, unexpected: 1 });
    // A file from another package of the same recipient decrypts to nothing here
    const other = await CryptoUtils.encryptDropPackage(keys.publicKey, 'other', [{ name: 'x', data: enc('x') }]);
    const foreign = await CryptoUtils.decryptDropEntry(opened.sessionKey, other.names[0]);
    assert.deepEqual(CryptoUtils.manifestProblems(opened.fileIds, [...ids, foreign.id]), { missing: 0, unexpected: 1 });
});

test('each role has its own associated data: none decrypts without it', async () => {
    const noAad = (iv, ct) => subtle.decrypt({ name: 'AES-GCM', iv }, opened.sessionKey, ct);
    await assert.rejects(noAad(Buffer.from(pkg.messageIv, 'base64'), Buffer.from(pkg.encryptedMessage, 'base64')), AES_FAILURE);
    const [, iv, ct] = pkg.names[0].split(':');
    await assert.rejects(noAad(Buffer.from(iv, 'base64'), Buffer.from(ct, 'base64')), AES_FAILURE);
    const body = Buffer.from(pkg.bodies[0]);
    await assert.rejects(noAad(body.subarray(0, 12), body.subarray(12)), AES_FAILURE);
});

test('a file row listed twice counts as not attached', () => {
    const ids = entries.map(e => e.id);
    assert.deepEqual(CryptoUtils.manifestProblems(opened.fileIds, [...ids, ids[0]]), { missing: 0, unexpected: 1 });
});

test('in a format 2 package only sealed names are shown', async () => {
    assert.deepEqual(await CryptoUtils.decryptDropEntry(opened.sessionKey, 'INVOICE-pay-now.pdf', 2), { name: 'encrypted-file', id: null });
    assert.deepEqual(await CryptoUtils.decryptDropEntry(opened.sessionKey, 'enc:AAAAAAAAAAAAAAAA:AAAAAAAAAAAAAAAAAAAAAAAA', 2), { name: 'encrypted-file', id: null });
    assert.equal((await CryptoUtils.decryptDropEntry(opened.sessionKey, pkg.names[0], 2)).name, 'contract.pdf');
});

test('the sealed sender name comes back, and a sender cannot pass off a malformed message', async () => {
    const withSender = await CryptoUtils.encryptDropPackage(keys.publicKey, 'x', [], 'Ana');
    assert.equal((await CryptoUtils.openDropPackage(keys.privateKey, stored(withSender))).sender, 'Ana');
    assert.equal(opened.sender, null);

    // Messages built by hand: what a sender can put in the sealed JSON
    const seal = async plain => {
        const sessionKey = await CryptoUtils.generateSessionKey();
        const raw = await subtle.exportKey('raw', sessionKey);
        const wrapped = await subtle.encrypt({ name: 'RSA-OAEP', label: enc(CryptoUtils.DROP_V2.SESSION_KEY_LABEL) }, keys.publicKey, raw);
        const m = await CryptoUtils.aesGcmEncrypt(sessionKey, enc(JSON.stringify(plain)), CryptoUtils.DROP_V2.MESSAGE);
        return { format: 2, encrypted_session_key: Buffer.from(wrapped).toString('base64'), encrypted_message: Buffer.from(m.ciphertext).toString('base64'), message_iv: Buffer.from(m.iv).toString('base64') };
    };
    const ids = n => Array.from({ length: n }, (_, i) => `id${i}`);
    assert.deepEqual((await CryptoUtils.openDropPackage(keys.privateKey, await seal({ text: 't', files: ids(20) }))).fileIds, ids(20));
    for (const bad of [{ text: 't', files: ids(21) }, { text: 't', files: [1] }, { text: 't', files: [{}] }, { text: 't', sender: 5, files: [] }, { files: [] }, { text: 't' }]) {
        await assert.rejects(CryptoUtils.openDropPackage(keys.privateKey, await seal(bad)), /Malformed package/, JSON.stringify(bad));
    }
});

test('a body shorter than IV and tag is refused before decrypting', async () => {
    await assert.rejects(CryptoUtils.decryptDropBody(opened.sessionKey, new Uint8Array(27).buffer, 2, entries[0].id), /Malformed file/);
});
