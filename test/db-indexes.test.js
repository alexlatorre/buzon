// The lookups done on every request (quota on each anonymous drop, inbox, shares, one-time links)
// must use indexes instead of scanning whole tables
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const Database = require('better-sqlite3');
const { startServer } = require('./helpers');

let server, db;

before(async () => {
    server = await startServer();
    db = new Database(path.join(server.dataDir, 'buzon.db'), { readonly: true });
});

after(async () => {
    db.close();
    await server.stop();
});

const plan = sql => db.prepare(`EXPLAIN QUERY PLAN ${sql}`).all().map(r => r.detail).join(' | ');

test('per-user and per-package lookups use an index', () => {
    const queries = {
        'pending packages of a user': "SELECT * FROM packages WHERE user_id = 'x' AND status = 'pending'",
        'files of a package': "SELECT * FROM package_files WHERE package_id = 'x'",
        'shares of a user': "SELECT * FROM shares WHERE user_id = 'x'",
        'unused one-time links of a user': "SELECT * FROM one_time_links WHERE user_id = 'x' AND is_used = 0"
    };
    for (const [label, sql] of Object.entries(queries)) {
        const detail = plan(sql);
        assert.match(detail, /USING (COVERING )?INDEX/, `${label}: ${detail}`);
    }
});
