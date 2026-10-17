// The legacy-migration answer must not turn the browser into an RSA decryption oracle for the server.
// These tests run the real public/crypto.js and play the part of a malicious server.
const { test, before } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { loadCryptoUtils } = require('./browser-crypto');

const CryptoUtils = loadCryptoUtils();
const subtle = globalThis.crypto.subtle;
const LABEL = Buffer.from('shadowdrop/migration-challenge/v1');
const PREFIX = Buffer.from('shadowdrop/migration-response/v1');

let keyPair, nodePublicKey;

// Errors the client must raise: WebCrypto's OAEP failure, or our size check. Matching them keeps a
// missing function (TypeError) or any other failure from counting as "rejected".
const OAEP_FAILURE = { name: 'OperationError' };
const SIZE_FAILURE = /Unexpected migration challenge/;

before(async () => {
    assert.equal(typeof CryptoUtils.answerMigrationChallenge, 'function');
    keyPair = await subtle.generateKey(
        { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
        true, ['encrypt', 'decrypt']
    );
    const spki = Buffer.from(await subtle.exportKey('spki', keyPair.publicKey));
    nodePublicKey = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
});

const serverEncrypt = (plaintext, oaepLabel) => crypto.publicEncrypt(
    { key: nodePublicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256', ...(oaepLabel ? { oaepLabel } : {}) },
    plaintext
).toString('base64');

test('a package session key sent as the challenge is not decrypted (oracle attack)', async () => {
    // Wrap a session key exactly as drop.js does, then hand it to the client as a "challenge"
    const sessionKey = crypto.randomBytes(32);
    const wrapped = await CryptoUtils.encryptAsymmetric(keyPair.publicKey, sessionKey);

    let answer = null;
    await assert.rejects(async () => { answer = await CryptoUtils.answerMigrationChallenge(keyPair.privateKey, wrapped); }, OAEP_FAILURE);
    assert.equal(answer, null);
});

test('any unlabelled RSA ciphertext is refused, whatever its length', async () => {
    for (const size of [16, 32, 64]) {
        const ciphertext = serverEncrypt(crypto.randomBytes(size));
        await assert.rejects(CryptoUtils.answerMigrationChallenge(keyPair.privateKey, ciphertext), OAEP_FAILURE);
    }
});

test('a labelled challenge that is not a 32-byte nonce is refused', async () => {
    for (const size of [0, 16, 31, 33, 64]) {
        await assert.rejects(CryptoUtils.answerMigrationChallenge(keyPair.privateKey, serverEncrypt(crypto.randomBytes(size), LABEL)), SIZE_FAILURE);
    }
});

test('a valid challenge is answered with a domain-separated hash, never the nonce', async () => {
    const nonce = crypto.randomBytes(32);
    const answer = await CryptoUtils.answerMigrationChallenge(keyPair.privateKey, serverEncrypt(nonce, LABEL));
    const expected = crypto.createHash('sha256').update(PREFIX).update(nonce).digest('base64');
    assert.equal(answer, expected);
    assert.notEqual(answer, nonce.toString('base64'));
    assert.ok(!Buffer.from(answer, 'base64').includes(nonce));
});

test('client and server use the same label and prefix', () => {
    const server = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
    assert.equal(CryptoUtils.MIGRATION_CHALLENGE_LABEL, LABEL.toString());
    assert.equal(CryptoUtils.MIGRATION_RESPONSE_PREFIX, PREFIX.toString());
    assert.ok(server.includes(`Buffer.from('${LABEL}')`));
    assert.ok(server.includes(`Buffer.from('${PREFIX}')`));
});

test('app.js answers the challenge only through answerMigrationChallenge', () => {
    const app = fs.readFileSync(path.join(__dirname, '..', 'public', 'app.js'), 'utf8');
    assert.match(app, /answerMigrationChallenge\(\s*legacyKey,\s*data\.challenge\s*\)/);
    assert.doesNotMatch(app, /decryptAsymmetric\([^)]*challenge/);
});

test('the migration label is reserved for the challenge and package keys stay unlabelled', () => {
    // Domain separation only holds while nothing else is ever encrypted under this label
    const files = ['server.js', ...fs.readdirSync(path.join(__dirname, '..', 'public')).filter(f => f.endsWith('.js')).map(f => `public/${f}`)];
    const users = files.filter(f => fs.readFileSync(path.join(__dirname, '..', f), 'utf8').includes(LABEL.toString()));
    assert.deepEqual(users.sort(), ['public/crypto.js', 'server.js']);
    const cryptoJs = fs.readFileSync(path.join(__dirname, '..', 'public', 'crypto.js'), 'utf8');
    assert.match(cryptoJs, /encryptAsymmetric[\s\S]*?\{ name: "RSA-OAEP" \}/);
});
