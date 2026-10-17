// Every script and stylesheet the pages load carries a Subresource Integrity hash of the file as it is
// in the repository, so the browser itself refuses a modified file (npm run hashes keeps them current)
const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PUBLIC = path.join(__dirname, '..', 'public');
const sri = file => 'sha256-' + crypto.createHash('sha256').update(fs.readFileSync(path.join(PUBLIC, file))).digest('base64');

test('every script and stylesheet tag has the right integrity hash', () => {
    let tags = 0;
    for (const page of fs.readdirSync(PUBLIC).filter(f => f.endsWith('.html'))) {
        const html = fs.readFileSync(path.join(PUBLIC, page), 'utf8');
        for (const [tag, file] of [...html.matchAll(/<script[^>]*\ssrc="([^"]+)"[^>]*>/g)].map(m => [m[0], m[1]])
            .concat([...html.matchAll(/<link[^>]*rel="stylesheet"[^>]*href="([^"]+)"[^>]*>/g)].map(m => [m[0], m[1]]))) {
            tags++;
            const integrity = (tag.match(/\sintegrity="([^"]+)"/) || [])[1];
            assert.equal(integrity, sri(file), `${page}: ${tag}`);
        }
    }
    assert.ok(tags >= 9, `only ${tags} tags checked`);
});
