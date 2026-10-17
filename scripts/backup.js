// Consistent backup of a SQLite deployment: npm run backup -- <destination folder>
// Copies the database through SQLite's online backup API (so nothing still in the WAL is lost),
// the drop/ and shares/ folders and .salt_secret, which must travel with the database.
// Safe to run while the server is up. Files that change during the copy belong to new uploads.
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

async function backup(dataDir, destination) {
    if (!fs.existsSync(path.join(dataDir, 'buzon.db'))) throw new Error(`No buzon.db in ${dataDir}`);
    if (fs.existsSync(destination) && fs.readdirSync(destination).length) throw new Error(`${destination} is not empty`);
    fs.mkdirSync(destination, { recursive: true });

    const db = new Database(path.join(dataDir, 'buzon.db'), { readonly: true });
    try {
        await db.backup(path.join(destination, 'buzon.db'));
    } finally {
        db.close();
    }
    for (const folder of ['drop', 'shares']) {
        const from = path.join(dataDir, folder);
        if (fs.existsSync(from)) fs.cpSync(from, path.join(destination, folder), { recursive: true });
    }
    const secret = path.join(dataDir, '.salt_secret');
    if (fs.existsSync(secret)) fs.copyFileSync(secret, path.join(destination, '.salt_secret'));
}

if (require.main === module) {
    const dataDir = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
    const destination = process.argv[2];
    if (!destination) {
        console.error('Usage: npm run backup -- <destination folder>');
        process.exit(1);
    }
    backup(dataDir, path.resolve(destination))
        .then(() => console.log(`Backup of ${dataDir} written to ${path.resolve(destination)}`))
        .catch(error => { console.error(`Backup failed: ${error.message}`); process.exit(1); });
}

module.exports = { backup };
