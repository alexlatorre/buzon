// The share page must still show the sender's decrypted note after the download finishes
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'share.html'), 'utf8');
const js = fs.readFileSync(path.join(__dirname, '..', 'public', 'share.js'), 'utf8');

// Returns the markup of the element with this id, from its opening tag to its matching </div>
function block(id) {
    const start = html.indexOf(`id="${id}"`);
    assert.ok(start >= 0, `#${id} not found`);
    const open = html.lastIndexOf('<div', start);
    let depth = 0;
    const tags = /<div\b|<\/div>/g;
    tags.lastIndex = open;
    for (let m; (m = tags.exec(html));) {
        depth += m[0] === '</div>' ? -1 : 1;
        if (depth === 0) return html.slice(open, tags.lastIndex);
    }
    throw new Error(`#${id} is not closed`);
}

test('the note is not inside the form that is hidden after the download', () => {
    assert.ok(!block('share-form').includes('id="share-message-box"'));
});

test('the note is shown in the success panel', () => {
    assert.ok(block('share-success').includes('id="share-message-box"'));
    // share.js hides the form and shows the success panel once the file is decrypted
    assert.match(js, /formEl\.classList\.add\('hidden'\);\s*successEl\.classList\.remove\('hidden'\);/);
    assert.match(js, /messageEl\.textContent = message;/);
});

test('Enter does not start a second download while one is running', () => {
    const handler = js.slice(js.indexOf('async function handleDownload('));
    const firstLines = handler.split('\n').slice(0, 4).join('\n');
    assert.match(firstLines, /if \(btnDownload\.disabled\) return;/);
});
