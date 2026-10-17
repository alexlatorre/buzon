// The working folder keeps real data for debugging (TLS key and certificate, the SQLite database, the
// salt secret, uploaded files, an exported image). None of it may reach git or the Docker image.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const LOCAL_ONLY = ['key.pem', 'cert.pem', 'privkey.pem', 'fullchain.pem', 'certs/privkey.pem', 'data/buzon.db',
    'data/buzon.db-wal', 'data/.salt_secret', 'data/drop/x', 'data/shares/x.enc', 'buzon.db', 'shadow-drop.tar', 'docs/report.md'];

test('git ignores every local-only file and tracks none of them', () => {
    const ignored = execFileSync('git', ['check-ignore', '--no-index', ...LOCAL_ONLY], { cwd: root, encoding: 'utf8' }).trim().split('\n');
    assert.deepEqual(ignored.sort(), [...LOCAL_ONLY].sort());
    const tracked = execFileSync('git', ['ls-files'], { cwd: root, encoding: 'utf8' }).split('\n');
    assert.deepEqual(tracked.filter(f => /\.(pem|key|crt|tar|db)$|^data\/|^certs\/|^docs\//.test(f)), []);
});

test('the Docker image copies only named files, and the build context excludes local data', () => {
    const dockerfile = fs.readFileSync(path.join(root, 'Dockerfile'), 'utf8');
    for (const line of dockerfile.split('\n').filter(l => /^\s*(COPY|ADD)\b/.test(l))) {
        assert.doesNotMatch(line, /\s\.\s|\s\.\/?\s|\*/, `copies the whole folder: ${line}`);
        assert.doesNotMatch(line, /pem|data|certs|docs|\.tar|\.db/, line);
    }
    const dockerignore = fs.readFileSync(path.join(root, '.dockerignore'), 'utf8').split(/\r?\n/).map(l => l.trim());
    for (const entry of ['data', '*.pem', 'certs', 'buzon.db*', 'shadow-drop.tar', 'docs', '.env']) {
        assert.ok(dockerignore.includes(entry), `.dockerignore lacks ${entry}`);
    }
});
