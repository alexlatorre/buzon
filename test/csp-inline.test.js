// The CSP allows only scripts from our own files (script-src 'self'), so inline event handlers in the
// HTML never run: they must be attached from the JS files instead
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const PUBLIC = path.join(__dirname, '..', 'public');

test('no HTML page relies on inline event handlers or inline scripts', () => {
    for (const file of fs.readdirSync(PUBLIC).filter(f => f.endsWith('.html'))) {
        const html = fs.readFileSync(path.join(PUBLIC, file), 'utf8');
        assert.doesNotMatch(html, /\son[a-z]+\s*=/i, `${file} has an inline event handler`);
        assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)[^>]*>/i, `${file} has an inline script`);
        assert.doesNotMatch(html, /href\s*=\s*["']javascript:/i, `${file} has a javascript: link`);
    }
});

test('the "Send Another Package" button is wired from drop.js', () => {
    const html = fs.readFileSync(path.join(PUBLIC, 'drop.html'), 'utf8');
    const js = fs.readFileSync(path.join(PUBLIC, 'drop.js'), 'utf8');
    assert.match(html, /<button[^>]*id="btn-send-another"[^>]*>Send Another Package<\/button>/);
    assert.match(js, /getElementById\('btn-send-another'\)\.addEventListener\('click'/);
});
