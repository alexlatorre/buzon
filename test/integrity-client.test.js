// The client side of the integrity check must hash exactly the bytes served (like the server does)
// and show a fingerprint that changes when any of the checked files changes.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Loads public/integrity.js without a DOM: init() is never reached (document stays "loading")
function loadIntegrity(fetchImpl) {
    const code = fs.readFileSync(path.join(__dirname, '..', 'public', 'integrity.js'), 'utf8');
    const document = { readyState: 'loading', addEventListener() {} };
    const window = { crypto: globalThis.crypto };
    return new Function('window', 'document', 'fetch', 'localStorage', `${code}\nreturn IntegrityCheck;`)(window, document, fetchImpl, {});
}

const sha256hex = data => crypto.createHash('sha256').update(data).digest('hex');

test('files are hashed as bytes, exactly like the server does (BOM included)', async () => {
    const withBom = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('console.log("hi");\n')]);
    const integrity = loadIntegrity(async () => new Response(withBom));
    assert.equal(await integrity.hashFile('app.js'), sha256hex(withBom));
});

test('the fingerprint depends on every file, not only the first', async () => {
    const integrity = loadIntegrity(async () => new Response(''));
    const hashes = Object.fromEntries(integrity.CRITICAL_FILES.map(f => [f, sha256hex(f)]));
    const base = await integrity.fingerprintOf(hashes);
    const changed = await integrity.fingerprintOf({ ...hashes, 'share.html': sha256hex('tampered') });
    assert.match(base, /^[0-9A-F]{8}$/);
    assert.notEqual(base, changed);
    // The same set of hashes always gives the same fingerprint, whatever the key order
    const reordered = Object.fromEntries(Object.entries(hashes).reverse());
    assert.equal(await integrity.fingerprintOf(reordered), base);
});
