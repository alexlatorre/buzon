// The inbox (real app.js) opening format 2 packages: what the recipient sees when the server lists the
// package faithfully, and when it drops, duplicates or renames what the sender sealed
const { test, before } = require('node:test');
const assert = require('node:assert/strict');
const { loadCryptoUtils } = require('./browser-crypto');
const { loadAppPage } = require('./app-page');

const CryptoUtils = loadCryptoUtils();
const subtle = globalThis.crypto.subtle;
const enc = s => new TextEncoder().encode(s);

let keys;

before(async () => {
    keys = await subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']);
});

// A package as the server stores it and the inbox API returns it, plus its file bodies by row id
async function sealed(text, files, sender = 'Ana') {
    const pkg = await CryptoUtils.encryptDropPackage(keys.publicKey, text, files.map(([name, data]) => ({ name, data: enc(data) })), sender);
    const bodies = {};
    const row = {
        id: 'pkg-1', format: 2, sender_name: sender, created_at: '2026-10-18 10:00:00',
        encrypted_session_key: pkg.encryptedSessionKey, encrypted_message: pkg.encryptedMessage, message_iv: pkg.messageIv,
        files: pkg.names.map((name, i) => {
            bodies[i + 1] = pkg.bodies[i];
            return { id: i + 1, original_name: name, mime_type: 'application/octet-stream', size: pkg.bodies[i].length };
        })
    };
    return { row, bodies };
}

async function openInInbox({ row, bodies }) {
    const fetch = async url => {
        const m = /\/file\/(\d+)$/.exec(url);
        return m && bodies[m[1]] ? new Response(bodies[m[1]]) : new Response('{}', { status: 404 });
    };
    const ui = loadAppPage({ fetch, hidden: ['modal-warning'] });
    ui.page.user = { id: 'u', privateKey: keys.privateKey, sessionToken: 't' };
    ui.page.packages = [row];
    await ui.page.openPackage(row.id);
    const warning = ui.el('modal-warning');
    return { ...ui, warning: warning.classList.contains('hidden') ? null : warning.textContent };
}

test('a package listed as sealed opens with no warning and downloads byte-exact', async () => {
    const pkg = await sealed('hola ⚠ not a warning', [['contrato.pdf', 'PDF bytes'], ['foto.jpg', 'JPG bytes']]);
    const ui = await openInInbox(pkg);
    assert.equal(ui.warning, null);
    assert.equal(ui.el('modal-message').textContent, 'hola ⚠ not a warning');
    assert.equal(ui.el('modal-sender').textContent, 'Ana');
    assert.deepEqual(pkg.row.files.map(f => f.displayName), ['contrato.pdf', 'foto.jpg']);
    assert.equal(await ui.page.downloadFile(pkg.row.files[1]), true);
    assert.equal(Buffer.from(await ui.saved[0].arrayBuffer()).toString(), 'JPG bytes');
    assert.equal(ui.saved[0].type, 'application/octet-stream');
});

test('a file the server leaves out is reported as missing', async () => {
    const pkg = await sealed('', [['a.txt', 'a'], ['b.txt', 'b']]);
    pkg.row.files.pop();
    const ui = await openInInbox(pkg);
    assert.match(ui.warning, /1 attachment\(s\) in the sealed list are missing/);
});

test('a file row the server lists twice is reported', async () => {
    const pkg = await sealed('', [['a.txt', 'a']]);
    pkg.row.files.push({ ...pkg.row.files[0], id: 2 });
    pkg.bodies[2] = pkg.bodies[1];
    const ui = await openInInbox(pkg);
    assert.match(ui.warning, /1 attachment\(s\) are not in the sealed list/);
});

test('a plain name the server puts in a format 2 package is not shown as the file name', async () => {
    const pkg = await sealed('', [['a.txt', 'a']]);
    pkg.row.files.push({ id: 2, original_name: 'INVOICE-pay-now.pdf', size: 40 });
    pkg.bodies[2] = pkg.bodies[1];
    const ui = await openInInbox(pkg);
    assert.equal(pkg.row.files[1].displayName, 'encrypted-file');
    assert.match(ui.warning, /not in the sealed list/);
    assert.equal(await ui.page.downloadFile(pkg.row.files[1]), false);
});

test('the sender name shown is the sealed one, and a rename by the server is reported', async () => {
    const pkg = await sealed('', [['a.txt', 'a']], 'Ana');
    pkg.row.sender_name = 'Your bank';
    const ui = await openInInbox(pkg);
    assert.equal(ui.el('modal-sender').textContent, 'Ana');
    assert.match(ui.warning, /sender name listed in the inbox is not the sealed one/);
});

test('a sender name with control characters is sealed the way the server stores it', async () => {
    const raw = `  Ana${String.fromCharCode(7)} López${'x'.repeat(80)}  `;
    const stored = raw.replace(/[\x00-\x1f\x7f]/g, '').trim().substring(0, 64); // as server.js does
    const pkg = await sealed('', [['a.txt', 'a']], raw);
    pkg.row.sender_name = stored;
    const ui = await openInInbox(pkg);
    assert.equal(ui.warning, null);
    assert.equal(ui.el('modal-sender').textContent, stored);
});

test('format 1 packages open with no warning', async () => {
    const sessionKey = await CryptoUtils.generateSessionKey();
    const raw = await subtle.exportKey('raw', sessionKey);
    const message = await CryptoUtils.encryptSymmetric(sessionKey, enc('v1 text'));
    const name = await CryptoUtils.encryptSymmetric(sessionKey, CryptoUtils.padTo256(enc('viejo.txt')));
    const body = await CryptoUtils.encryptSymmetric(sessionKey, enc('v1 body'));
    const row = {
        id: 'pkg-1', format: 1, sender_name: 'Old', created_at: '2026-10-18 10:00:00',
        encrypted_session_key: await CryptoUtils.encryptAsymmetric(keys.publicKey, raw),
        encrypted_message: message.ciphertext, message_iv: message.iv,
        files: [{ id: 1, original_name: `enc:${name.iv}:${name.ciphertext}`, size: 10 }]
    };
    const ui = await openInInbox({ row, bodies: { 1: enc(JSON.stringify(body)) } });
    assert.equal(ui.warning, null);
    assert.equal(ui.el('modal-message').textContent, 'v1 text');
    assert.equal(ui.el('modal-sender').textContent, 'Old');
    assert.equal(await ui.page.downloadFile(row.files[0]), true);
    assert.equal(Buffer.from(await ui.saved[0].arrayBuffer()).toString(), 'v1 body');
});

test('a package that does not open still shows the modal, without a stale warning', async () => {
    const first = await sealed('', [['a.txt', 'a']]);
    first.row.files.pop();
    const ui = await openInInbox(first);
    assert.ok(ui.warning);
    const broken = { ...first.row, id: 'pkg-2', encrypted_message: first.row.encrypted_session_key.slice(0, 40) };
    ui.page.packages = [broken];
    await ui.page.openPackage('pkg-2');
    assert.ok(ui.el('modal-warning').classList.contains('hidden'));
    assert.match(ui.el('modal-message').textContent, /could not be decrypted/);
});
