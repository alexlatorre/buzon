// A database that is missing while the data directory still holds what an earlier install left behind
// (the salt secret, the WAL, uploaded files) is almost always a lost or unmounted database. Starting
// with an empty one would hide every account and write new data where nobody expects it.
const fs = require('fs');
const path = require('path');

function dataLeftovers(dataDir) {
    const found = [];
    for (const file of ['.salt_secret', 'buzon.db-wal']) {
        if (fs.existsSync(path.join(dataDir, file))) found.push(file);
    }
    for (const dir of ['drop', 'shares']) {
        const full = path.join(dataDir, dir);
        const count = fs.existsSync(full) ? fs.readdirSync(full).length : 0;
        if (count > 0) found.push(`${dir}/ (${count} file${count === 1 ? '' : 's'})`);
    }
    return found;
}

function lostDatabaseMessage(where, dataDir, found) {
    return `${where} has no Shadow Drop tables, but ${dataDir} still holds ${found.join(', ')} from an earlier install. `
        + 'Restore or mount the database (with its .salt_secret) instead of starting with an empty one. '
        + 'To really start from scratch, move those files out of the data directory first.';
}

module.exports = { dataLeftovers, lostDatabaseMessage };
