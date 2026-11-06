// Anyone with a share link gets the salt and wrapped key and can guess the password offline. The owner
// may still choose any password (a DNI, say); the dashboard marks a weak one instead of refusing it
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const read = f => fs.readFileSync(path.join(__dirname, '..', 'public', f), 'utf8');

test('the dashboard accepts any non-empty share password and marks weak ones', () => {
    const app = read('app.js');
    assert.doesNotMatch(app, /MIN_SHARE_PASSWORD_LENGTH/);
    assert.match(app, /if \(!password\) \{/);
    assert.match(app, /function isWeakSharePassword\(pw\)/);
    assert.match(app, /sharePwWarning\.classList\.toggle\('hidden', !val \|\| !isWeakSharePassword\(val\)\)/);
});

test('the share password field asks for a new password and sets no minimum', () => {
    const html = read('index.html');
    const field = html.match(/<input[^>]*id="share-pw"[^>]*>/)[0];
    assert.match(field, /autocomplete="new-password"/);
    assert.doesNotMatch(field, /minlength/);
    assert.match(html, /id="share-pw-warning" class="field-warning hidden"/);
});
