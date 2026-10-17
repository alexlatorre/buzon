// A drop link carries the recipient's key fingerprint in its fragment (#k=), which never reaches the
// server. The sender's page must refuse a public key from the server that does not match it, so a
// malicious server cannot swap in its own key and read what is sent.
const { test, before } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { loadCryptoUtils } = require('./browser-crypto');

const CryptoUtils = loadCryptoUtils();
const subtle = globalThis.crypto.subtle;
const read = f => fs.readFileSync(path.join(__dirname, '..', 'public', f), 'utf8');
const ID = '0b3a2a6e-7d3c-4c1e-9f1a-2b9e8d4c5a61';

let recipient, attacker;

async function keyPair() {
    const pair = await subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']);
    return { spki: await CryptoUtils.exportPublicKey(pair.publicKey), pkcs8: await CryptoUtils.exportPrivateKey(pair.privateKey) };
}

// Computed here with Node, independently of crypto.js
const nodeFingerprint = spki => crypto.createHash('sha256').update(Buffer.from(spki, 'base64')).digest('base64url').slice(0, 22);

before(async () => {
    recipient = await keyPair();
    attacker = await keyPair();
    recipient.fp = await CryptoUtils.fingerprintFromPkcs8(recipient.pkcs8);
});

// Runs the real drop.js (with the real crypto.js) on a minimal DOM, the server answering with `publicKey`
async function openDropPage(url, publicKey) {
    const { search, hash } = new URL(url);
    const elements = {};
    const element = () => ({
        textContent: '', className: '', value: '', disabled: false, style: {}, files: [], innerHTML: '',
        classList: { add() {}, remove() {}, contains: () => false }, addEventListener() {}, appendChild() {}, append() {}
    });
    const document = { getElementById: id => (elements[id] ||= element()), createElement: element, addEventListener() {} };
    document.getElementById('btn-submit').disabled = true; // as in drop.html
    const window = { location: { search, hash }, crypto: globalThis.crypto, btoa, atob };
    let fetched = 0;
    const fetch = async () => { fetched++; return new Response(JSON.stringify({ publicKey }), { status: 200 }); };
    const drop = read('drop.js').replace('// Initialize\nfetchPublicKey();', 'const __ready = fetchPublicKey();');
    assert.ok(drop.includes('const __ready'), 'drop.js no longer ends with fetchPublicKey()');
    const page = new Function('window', 'document', 'fetch', `${read('crypto.js')}\n${drop}\nreturn { ready: __ready, key: () => targetPublicKey };`)(window, document, fetch);
    await page.ready;
    return {
        sendEnabled: !document.getElementById('btn-submit').disabled,
        keyLoaded: page.key() !== null,
        status: document.getElementById('system-status').textContent,
        message: document.getElementById('status-msg').textContent,
        fetched
    };
}

test('the fingerprint is the first 22 base64url characters of SHA-256 over the SPKI', async () => {
    assert.equal(await CryptoUtils.publicKeyFingerprint(recipient.spki), nodeFingerprint(recipient.spki));
    assert.equal(recipient.fp, nodeFingerprint(recipient.spki), 'derived from the private key');
});

test('verifyRecipientKey accepts only the matching key and exact fingerprints', async () => {
    assert.equal(await CryptoUtils.verifyRecipientKey(recipient.spki, recipient.fp), true);
    assert.equal(await CryptoUtils.verifyRecipientKey(attacker.spki, recipient.fp), false);
    for (const bad of ['', recipient.fp.slice(0, 21), recipient.fp + 'A', undefined, null]) {
        assert.equal(await CryptoUtils.verifyRecipientKey(recipient.spki, bad), false, String(bad));
    }
});

test('the send page refuses a key the server swapped in (attack)', async () => {
    const page = await openDropPage(`https://x/drop.html?id=${ID}#k=${recipient.fp}`, attacker.spki);
    assert.equal(page.sendEnabled, false);
    assert.equal(page.keyLoaded, false);
    assert.match(page.message, /not the one in this link/);
});

test('the send page accepts the right key and shows the fingerprint in use', async () => {
    const page = await openDropPage(`https://x/drop.html?id=${ID}#k=${recipient.fp}`, recipient.spki);
    assert.equal(page.sendEnabled, true);
    assert.equal(page.keyLoaded, true);
    assert.ok(page.status.includes(recipient.fp));
});

test('links without a fingerprint still work, with a warning', async () => {
    const page = await openDropPage(`https://x/drop.html?id=${ID}`, recipient.spki);
    assert.equal(page.sendEnabled, true);
    assert.match(page.message, /cannot be verified/);
});

test('malformed fragments and ids are refused before asking the server for a key', async () => {
    for (const url of [
        `https://x/drop.html?id=${ID}#k=${recipient.fp}&k=${recipient.fp}`,
        `https://x/drop.html?id=${ID}#k=short`,
        `https://x/drop.html?id=${ID}#x=1`,
        `https://x/drop.html?id=${ID}%23k%3D${recipient.fp}`,
        `https://x/drop.html?id=not-a-uuid#k=${recipient.fp}`
    ]) {
        const page = await openDropPage(url, attacker.spki);
        assert.equal(page.sendEnabled, false, url);
        assert.equal(page.fetched, 0, url);
    }
});

test('drop links are built only from a valid id and fingerprint (no injection)', () => {
    assert.equal(CryptoUtils.dropLink('https://x', ID, recipient.fp), `https://x/drop.html?id=${ID}#k=${recipient.fp}`);
    // A server-chosen id that tries to plant its own fingerprint
    assert.throws(() => CryptoUtils.dropLink('https://x', `${ID}#k=${'A'.repeat(22)}&x=`, recipient.fp));
    assert.throws(() => CryptoUtils.dropLink('https://x', ID, undefined));
    assert.throws(() => CryptoUtils.dropLink('https://x', ID, recipient.fp.slice(0, 8)));
});

test('the dashboard builds links with dropLink and the fingerprint from the private key', () => {
    const app = read('app.js');
    assert.match(app, /CryptoUtils\.dropLink\(window\.location\.origin, data\.id, fingerprint\)/);
    assert.match(app, /CryptoUtils\.dropLink\(window\.location\.origin, l\.token, currentUser\.keyFingerprint\)/);
    const decrypt = app.slice(app.indexOf('async function decryptPrivateKey('), app.indexOf('async function postLogin('));
    assert.match(decrypt, /fingerprint: await CryptoUtils\.fingerprintFromPkcs8\(pkcs8\)/);
    assert.match(app, /keyFingerprint: fingerprint,/);
    assert.doesNotMatch(app, /drop\.html\?id=\$\{/, 'drop links must go through dropLink');
});
