// Rewrites the "Trusted Hashes" table in README.md from the files in public/
// Run after changing any frontend file: npm run hashes
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const FILES = ['app.js', 'crypto.js', 'integrity.js', 'share.js', 'drop.js', 'style.css', 'index.html', 'about.html', 'drop.html', 'share.html'];
const root = path.join(__dirname, '..');
const readmePath = path.join(root, 'README.md');

const rows = ['| File | SHA-256 |', '|---|---|'];
for (const file of FILES) {
    const content = fs.readFileSync(path.join(root, 'public', file));
    if (content.includes('\r\n')) {
        console.error(`public/${file} has CRLF line endings; check out with LF (see .gitattributes)`);
        process.exit(1);
    }
    rows.push(`| \`${file}\` | \`${crypto.createHash('sha256').update(content).digest('hex')}\` |`);
}

const readme = fs.readFileSync(readmePath, 'utf8');
const updated = readme.replace(
    /<!-- hashes:start -->[\s\S]*?<!-- hashes:end -->/,
    `<!-- hashes:start -->\n${rows.join('\n')}\n<!-- hashes:end -->`
);
fs.writeFileSync(readmePath, updated);
console.log(rows.slice(2).join('\n'));
