// Run after changing any frontend file: npm run hashes
// 1. Rewrites the Subresource Integrity attributes of every script and stylesheet in public/*.html
// 2. Rewrites the "Trusted Hashes" table in README.md from the files in public/
// Step 1 goes first because the HTML pages are themselves in the table.
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const FILES = ['app.js', 'crypto.js', 'integrity.js', 'share.js', 'drop.js', 'style.css', 'index.html', 'about.html', 'drop.html', 'share.html'];
const root = path.join(__dirname, '..');
const publicDir = path.join(root, 'public');
const readmePath = path.join(root, 'README.md');

function readChecked(file) {
    const content = fs.readFileSync(path.join(publicDir, file));
    if (content.includes('\r\n')) {
        console.error(`public/${file} has CRLF line endings; check out with LF (see .gitattributes)`);
        process.exit(1);
    }
    return content;
}

// --- 1. Subresource Integrity ---
const sri = file => 'sha256-' + crypto.createHash('sha256').update(readChecked(file)).digest('base64');
for (const page of fs.readdirSync(publicDir).filter(f => f.endsWith('.html'))) {
    const pagePath = path.join(publicDir, page);
    const html = fs.readFileSync(pagePath, 'utf8');
    const updated = html
        .replace(/<script src="([^"]+)"(?: integrity="[^"]*")?><\/script>/g,
            (tag, src) => `<script src="${src}" integrity="${sri(src)}"></script>`)
        .replace(/<link rel="stylesheet" href="([^"]+)"(?: integrity="[^"]*")?>/g,
            (tag, href) => `<link rel="stylesheet" href="${href}" integrity="${sri(href)}">`);
    if (updated !== html) {
        fs.writeFileSync(pagePath, updated);
        console.log(`SRI updated in ${page}`);
    }
}

// --- 2. README table ---
const rows = ['| File | SHA-256 |', '|---|---|'];
for (const file of FILES) {
    rows.push(`| \`${file}\` | \`${crypto.createHash('sha256').update(readChecked(file)).digest('hex')}\` |`);
}

const readme = fs.readFileSync(readmePath, 'utf8');
const updatedReadme = readme.replace(
    /<!-- hashes:start -->[\s\S]*?<!-- hashes:end -->/,
    `<!-- hashes:start -->\n${rows.join('\n')}\n<!-- hashes:end -->`
);
fs.writeFileSync(readmePath, updatedReadme);
console.log(rows.slice(2).join('\n'));
