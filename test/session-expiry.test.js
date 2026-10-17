// When the session expires (24 h, or a server restart) every authenticated call must take the user
// back to the login screen instead of failing silently, and "Download All" must only offer to destroy
// a package when every file was actually downloaded.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const app = fs.readFileSync(path.join(__dirname, '..', 'public', 'app.js'), 'utf8');
const between = (from, to) => app.slice(app.indexOf(from), app.indexOf(to, app.indexOf(from) + from.length));

test('authFetch logs out with a message on 401', () => {
    const fn = between('async function authFetch(', '\n}\n');
    assert.match(fn, /res\.status === 401/);
    assert.match(fn, /secureLogout\(\)/);
    assert.match(fn, /Session expired/);
});

test('every authenticated call except logout goes through authFetch', () => {
    const lines = app.split('\n');
    lines.forEach((line, i) => {
        if (!/'Authorization': `Bearer/.test(line)) return;
        const context = lines.slice(Math.max(0, i - 6), i + 1).join('\n');
        if (/\/api\/auth\/logout/.test(context)) return;
        assert.match(context, /authFetch\(/, `line ${i + 1} uses fetch directly`);
    });
});

test('Download All only offers to destroy when every file succeeded', () => {
    const single = between('async function downloadFile(', 'async function decryptFileName(');
    assert.match(single, /return true;/);
    assert.match(single, /return false;/);
    const all = between('async function downloadFiles(', '\n}\n');
    assert.match(all, /if \(failed === 0 && confirm\(/);
});
