// Anyone with a share link gets the salt and wrapped key and can guess the password offline, so the
// dashboard must not accept short share passwords (it used to accept 4 characters)
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const read = f => fs.readFileSync(path.join(__dirname, '..', 'public', f), 'utf8');

test('the dashboard requires at least 12 characters for a share password', () => {
    const app = read('app.js');
    assert.match(app, /const MIN_SHARE_PASSWORD_LENGTH = 12;/);
    assert.match(app, /password\.length < MIN_SHARE_PASSWORD_LENGTH/);
    assert.doesNotMatch(app, /password\.length < 4\b/);
});

test('the share password field asks for a new password and states the minimum', () => {
    const field = read('index.html').match(/<input[^>]*id="share-pw"[^>]*>/)[0];
    assert.match(field, /autocomplete="new-password"/);
    assert.match(field, /minlength="12"/);
});
