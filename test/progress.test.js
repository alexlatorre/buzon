// public/progress.js: the bar the pages show while they read, encrypt, transfer and decrypt, the
// upload that reports bytes sent, and the download that reports bytes received
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { fakeElement, fakeXMLHttpRequest } = require('./app-page');

const source = fs.readFileSync(path.join(__dirname, '..', 'public', 'progress.js'), 'utf8');
const load = (XMLHttpRequest = undefined) => new Function('XMLHttpRequest', `${source}\nreturn Progress;`)(XMLHttpRequest);
const Progress = load();

// A response whose body arrives in the given pieces
function streamed(pieces, headers = {}) {
    const body = new ReadableStream({
        start(controller) {
            for (const piece of pieces) controller.enqueue(new Uint8Array(piece));
            controller.close();
        }
    });
    return new Response(body, { headers });
}

function barElement() {
    const el = fakeElement();
    el.classList.add('hidden');
    return el;
}

test('formatBytes and formatTimeLeft read naturally', () => {
    assert.equal(Progress.formatBytes(512), '512 B');
    assert.equal(Progress.formatBytes(1536), '1.5 KB');
    assert.equal(Progress.formatBytes(200 * 1048576), '200.0 MB');
    assert.equal(Progress.formatBytes(1.5 * 1073741824), '1.50 GB');
    assert.equal(Progress.formatTimeLeft(0.2), '1 s left');
    assert.equal(Progress.formatTimeLeft(42), '42 s left');
    assert.equal(Progress.formatTimeLeft(150), '3 min left');
});

test('a busy step shows its name and a moving bar, a transfer its bytes and percentage', () => {
    const el = barElement();
    const bar = Progress.bar(el);
    bar.busy('Encrypting 200.0 MB in your browser...');
    assert.equal(el.classList.contains('hidden'), false);
    assert.equal(el.classList.contains('progress-busy'), true);
    assert.equal(el.querySelector('.progress-label').textContent, 'Encrypting 200.0 MB in your browser...');

    bar.bytes('Uploading', 50 * 1048576, 200 * 1048576);
    assert.equal(el.classList.contains('progress-busy'), false);
    assert.equal(el.querySelector('.progress-fill').style.width, '25%');
    assert.equal(el.querySelector('.progress-label').textContent, 'Uploading 50.0 MB of 200.0 MB · 25%');

    // The last report always paints, however soon it comes
    bar.bytes('Uploading', 200 * 1048576, 200 * 1048576);
    assert.equal(el.querySelector('.progress-fill').style.width, '100%');

    bar.hide();
    assert.equal(el.classList.contains('hidden'), true);
    assert.equal(el.querySelector('.progress-label').textContent, '');
});

test('a transfer of unknown size shows the bytes so far without a percentage', () => {
    const el = barElement();
    Progress.bar(el).bytes('Downloading', 3 * 1048576, 0);
    assert.equal(el.classList.contains('progress-busy'), true);
    assert.equal(el.querySelector('.progress-label').textContent, 'Downloading 3.0 MB');
});

test('readBody returns the exact bytes and reports each piece against the Content-Length', async () => {
    const reports = [];
    const body = await Progress.readBody(streamed([[1, 2, 3], [4, 5], [6]], { 'Content-Length': '6' }), (done, total) => reports.push([done, total]));
    assert.deepEqual([...new Uint8Array(body)], [1, 2, 3, 4, 5, 6]);
    assert.deepEqual(reports, [[0, 6], [3, 6], [5, 6], [6, 6]]);
});

test('readBody falls back to the expected size, and copes with a length that is wrong', async () => {
    const reports = [];
    const body = await Progress.readBody(streamed([[1, 2], [3]]), (done, total) => reports.push([done, total]), 3);
    assert.deepEqual([...new Uint8Array(body)], [1, 2, 3]);
    assert.deepEqual(reports.at(-1), [3, 3]);

    // More bytes than declared, and fewer: the bytes that arrived, as they arrived
    const more = await Progress.readBody(streamed([[1, 2], [3, 4]], { 'Content-Length': '3' }), () => {});
    assert.deepEqual([...new Uint8Array(more)], [1, 2, 3, 4]);
    const fewer = await Progress.readBody(streamed([[1, 2]], { 'Content-Length': '5' }), () => {});
    assert.deepEqual([...new Uint8Array(fewer)], [1, 2]);
});

test('upload reports the bytes sent and resolves to the server\'s response', async () => {
    const sent = [];
    const fetch = async (url, options) => {
        sent.push({ url, options });
        return new Response(JSON.stringify({ token: 'abc' }), { status: 201 });
    };
    const P = load(fakeXMLHttpRequest(fetch));
    const reports = [];
    const res = await P.upload('/api/x', { method: 'POST', headers: { Authorization: 'Bearer t' }, body: 'payload' }, (done, total) => reports.push([done, total]));
    assert.equal(res.status, 201);
    assert.deepEqual(await res.json(), { token: 'abc' });
    assert.deepEqual(reports, [[50, 100], [100, 100]]);
    assert.equal(sent[0].options.headers.Authorization, 'Bearer t');
    assert.equal(sent[0].options.body, 'payload');
});

test('upload rejects like fetch when the request does not get through', async () => {
    const P = load(fakeXMLHttpRequest(async () => { throw new TypeError('offline'); }));
    await assert.rejects(P.upload('/api/x', { body: 'x' }), TypeError);
});
