// Accounts and administration: the registration switch, admin-created accounts (invitations whose keys
// are created at activation), account management and link control. An admin manages accounts and links
// and never gets files, messages, file names, keys or link tokens.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const { startServer, client } = require('./helpers');
const { loadCryptoUtils } = require('./browser-crypto');

const CryptoUtils = loadCryptoUtils();
const repo = path.join(__dirname, '..');
let server, api, admin, adminToken;

// The command-line tool against the test server's database
function cli(...args) {
    const r = spawnSync(process.execPath, [path.join(repo, 'scripts', 'admin.js'), ...args], {
        env: { ...process.env, DATA_DIR: server.dataDir, DB_ENGINE: 'sqlite' }, encoding: 'utf8'
    });
    return { status: r.status, out: r.stdout + r.stderr };
}
const tokenFrom = out => (/#activate=([A-Za-z0-9_-]{43})/.exec(out) || [])[1];
const rows = (sql, ...params) => {
    const db = new Database(path.join(server.dataDir, 'buzon.db'), { readonly: true });
    try { return db.prepare(sql).all(...params); } finally { db.close(); }
};
const write = (sql, ...params) => {
    const db = new Database(path.join(server.dataDir, 'buzon.db'));
    try { db.prepare(sql).run(...params); } finally { db.close(); }
};
const as = (method, url, body, token = adminToken) => api.json(method, url, body, token);

before(async () => {
    server = await startServer({ API_RATE_LIMIT: '5000' });
    api = client(server.base);
    // Bootstrap: the first admin comes from the server's shell
    const invite = cli('invite', 'root_admin', '--admin', '--origin', 'https://box.test');
    assert.equal(invite.status, 0, invite.out);
    assert.match(invite.out, /https:\/\/box\.test\/#activate=/);
    const { res, user } = await api.register('root_admin', 'root admin password', { invitationToken: tokenFrom(invite.out) });
    assert.equal(res.status, 200, JSON.stringify(res.data));
    admin = user;
    const login = await api.login('root_admin', 'root admin password');
    assert.equal(login.data.role, 'admin');
    adminToken = login.data.sessionToken;
});

after(() => server.stop());

test('registration is open by default and the config says so', async () => {
    assert.deepEqual((await api.json('GET', '/api/config')).data, { registrationOpen: true });
    assert.equal((await api.register('open_user', 'open user password')).res.status, 200);
    assert.equal((await api.login('open_user', 'open user password')).data.role, 'user');
});

test('an invitation creates the account at activation, once, for its username only', async () => {
    const created = await as('POST', '/api/admin/invitations', { username: 'invited_bob' });
    assert.equal(created.status, 200);
    const { token } = created.data;
    assert.match(token, /^[A-Za-z0-9_-]{43}$/);
    // Only its hash is stored
    assert.equal(rows('SELECT * FROM invitations WHERE username = ?', 'invited_bob')[0].token_hash.includes(token), false);
    assert.equal(JSON.stringify(rows('SELECT * FROM invitations')).includes(token), false);
    // The page can ask whose it is, nothing more
    assert.deepEqual((await api.json('POST', '/api/auth/invitation', { token })).data, { username: 'invited_bob' });
    assert.equal((await api.json('POST', '/api/auth/invitation', { token: 'x'.repeat(43) })).status, 404);
    // The username is reserved while the invitation is pending
    assert.equal((await api.register('invited_bob', 'squatter password')).res.status, 409);
    // Another username with this token, or a made-up token, does not work
    assert.equal((await api.register('someone_else', 'bob password', { invitationToken: token })).res.status, 403);
    assert.equal((await api.register('invited_bob', 'bob password', { invitationToken: 'A'.repeat(43) })).res.status, 403);
    assert.equal((await api.register('invited_bob', 'bob password', { invitationToken: token })).res.status, 200);
    assert.equal((await api.register('invited_bob2', 'bob password', { invitationToken: token })).res.status, 403);
    assert.equal((await api.login('invited_bob', 'bob password')).status, 200);
    assert.equal(rows('SELECT * FROM invitations WHERE username = ?', 'invited_bob').length, 0);
});

test('an expired or revoked invitation does not activate', async () => {
    const expired = (await as('POST', '/api/admin/invitations', { username: 'late_carol' })).data;
    write('UPDATE invitations SET expires_at = ? WHERE id = ?', new Date(Date.now() - 1000).toISOString(), expired.id);
    assert.equal((await api.json('POST', '/api/auth/invitation', { token: expired.token })).status, 404);
    assert.equal((await api.register('late_carol', 'carol password', { invitationToken: expired.token })).res.status, 403);
    const revoked = (await as('POST', '/api/admin/invitations', { username: 'revoked_dan' })).data;
    assert.equal((await as('DELETE', `/api/admin/invitations/${revoked.id}`)).status, 200);
    assert.equal((await api.register('revoked_dan', 'dan password', { invitationToken: revoked.token })).res.status, 403);
});

test('with registration closed only invitations create accounts', async () => {
    assert.equal((await as('POST', '/api/admin/registration', { open: false })).status, 200);
    assert.deepEqual((await api.json('GET', '/api/config')).data, { registrationOpen: false });
    const refused = await api.register('closed_eve', 'eve password');
    assert.equal(refused.res.status, 403);
    assert.match(refused.res.data.error, /closed/);
    const { token } = (await as('POST', '/api/admin/invitations', { username: 'closed_eve' })).data;
    assert.equal((await api.register('closed_eve', 'eve password', { invitationToken: token })).res.status, 200);
    assert.equal((await as('GET', '/api/admin/overview')).data.registration.setBy, 'admin');
    assert.equal((await as('POST', '/api/admin/registration', { open: true })).status, 200);
});

test('REGISTRATION=closed is the starting value, and an invalid value stops the server', async () => {
    const closed = await startServer({ REGISTRATION: 'closed' });
    try {
        const closedApi = client(closed.base);
        assert.deepEqual((await closedApi.json('GET', '/api/config')).data, { registrationOpen: false });
        assert.equal((await closedApi.register('nobody_here', 'some password')).res.status, 403);
    } finally {
        await closed.stop();
    }
    await assert.rejects(startServer({ REGISTRATION: 'maybe' }), /REGISTRATION must be/);
});

test('admin routes are for admins only', async () => {
    const { user } = await api.register('plain_frank', 'frank password');
    const userToken = (await api.login('plain_frank', 'frank password')).data.sessionToken;
    const routes = [
        ['GET', '/api/admin/overview'], ['GET', '/api/admin/links'], ['POST', '/api/admin/registration', { open: false }],
        ['POST', '/api/admin/invitations', { username: 'by_frank', role: 'admin' }],
        ['POST', `/api/admin/accounts/${admin.id}`, { disabled: true }], ['DELETE', `/api/admin/accounts/${admin.id}`, { currentServerAuthHash: user.serverAuthHash }],
        ['POST', `/api/admin/accounts/${admin.id}/public-link`, { enabled: false }],
        ['DELETE', '/api/admin/one-time-links/0123456789abcdef01234567'], ['POST', '/api/admin/shares/0123456789abcdef01234567/expire']
    ];
    for (const [method, url, body] of routes) {
        assert.equal((await api.json(method, url, body, userToken)).status, 403, `${method} ${url} as a user`);
        assert.equal((await api.json(method, url, body)).status, 401, `${method} ${url} without a session`);
    }
    assert.deepEqual((await api.json('GET', '/api/config')).data, { registrationOpen: true });
});

test('the overview and the link list carry no keys, hashes, names or link tokens', async () => {
    const { user } = await api.register('leaky_gina', 'gina password');
    const token = (await api.login('leaky_gina', 'gina password')).data.sessionToken;
    const otl = (await api.json('POST', `/api/user/${user.id}/one-time-link`, null, token)).data.token;
    const share = (await api.share(user.id, token, { maxDownloads: 3 })).data.token;
    await api.drop(user.id, user.publicKey, [{ name: 'secret-name.txt', content: 'secret content' }]);
    const text = JSON.stringify((await as('GET', '/api/admin/overview')).data) + JSON.stringify((await as('GET', '/api/admin/links')).data);
    const stored = rows('SELECT * FROM users WHERE id = ?', user.id)[0];
    for (const secret of [stored.salt, stored.public_key, stored.encrypted_private_key, stored.iv, stored.server_auth_hash, otl, share, 'secret-name', 'secret content']) {
        assert.equal(text.includes(secret), false, `admin view leaks ${String(secret).slice(0, 20)}`);
    }
    const links = (await as('GET', '/api/admin/links')).data;
    assert.ok(links.oneTimeLinks.some(o => o.username === 'leaky_gina' && /^[0-9a-f]{24}$/.test(o.ref)));
    assert.ok(links.shares.some(s => s.username === 'leaky_gina' && s.maxDownloads === 3));
    const account = (await as('GET', '/api/admin/overview')).data.accounts.find(a => a.username === 'leaky_gina');
    assert.equal(account.packages, 1);
    assert.equal(account.shares, 1);
    assert.ok(account.storageUsed > 0);
});

test('an admin cannot read other accounts\' packages or files', async () => {
    const { user } = await api.register('private_hugo', 'hugo password');
    await api.drop(user.id, user.publicKey, [{ name: 'a.txt', content: 'x' }]);
    const hugoToken = (await api.login('private_hugo', 'hugo password')).data.sessionToken;
    const pkg = (await api.json('GET', `/api/packages/${user.id}`, null, hugoToken)).data[0];
    assert.equal((await as('GET', `/api/packages/${user.id}`)).status, 403);
    const file = await fetch(`${server.base}/api/package/${pkg.id}/file/${pkg.files[0].id}`, { headers: { Authorization: `Bearer ${adminToken}` } });
    assert.ok([403, 404].includes(file.status));
    assert.equal((await as('GET', `/api/shares/${user.id}`)).status, 403);
});

test('a disabled account cannot log in, loses its sessions, and its links stop working', async () => {
    const { user } = await api.register('paused_ivy', 'ivy password');
    const token = (await api.login('paused_ivy', 'ivy password')).data.sessionToken;
    const share = (await api.share(user.id, token)).data.token;
    assert.equal((await as('POST', `/api/admin/accounts/${user.id}`, { disabled: true })).status, 200);
    assert.equal((await api.login('paused_ivy', 'ivy password')).status, 401);
    assert.equal((await api.json('GET', `/api/packages/${user.id}`, null, token)).status, 401);
    assert.equal((await api.json('GET', `/api/user/${user.id}/public-key`)).status, 404);
    assert.equal((await api.json('GET', `/api/share/${share}/meta`)).status, 410);
    assert.equal((await as('POST', `/api/admin/accounts/${user.id}`, { disabled: false })).status, 200);
    assert.equal((await api.login('paused_ivy', 'ivy password')).status, 200);
    assert.equal((await api.json('GET', `/api/share/${share}/meta`)).status, 200);
});

test('an admin cannot disable, demote or delete their own account', async () => {
    assert.equal((await as('POST', `/api/admin/accounts/${admin.id}`, { disabled: true })).status, 409);
    assert.equal((await as('POST', `/api/admin/accounts/${admin.id}`, { role: 'user' })).status, 409);
    assert.equal((await as('DELETE', `/api/admin/accounts/${admin.id}`, { currentServerAuthHash: admin.serverAuthHash })).status, 409);
    // Promoting someone else works, and the last admin cannot be demoted from the shell either
    const { user } = await api.register('second_jo', 'jo password');
    assert.equal((await as('POST', `/api/admin/accounts/${user.id}`, { role: 'admin' })).status, 200);
    assert.equal((await api.login('second_jo', 'jo password')).data.role, 'admin');
    assert.equal(cli('demote', 'second_jo').status, 0);
    const lastDemote = cli('demote', 'root_admin');
    assert.notEqual(lastDemote.status, 0);
    assert.match(lastDemote.out, /at least one active admin/);
});

test('deleting an account needs the admin password and removes its data and files', async () => {
    const { user } = await api.register('gone_kai', 'kai password');
    const token = (await api.login('gone_kai', 'kai password')).data.sessionToken;
    await api.drop(user.id, user.publicKey, [{ name: 'a.txt', content: 'x' }]);
    const share = (await api.share(user.id, token)).data.token;
    await api.json('POST', `/api/user/${user.id}/one-time-link`, null, token);
    const dropFiles = () => fs.readdirSync(path.join(server.dataDir, 'drop')).filter(f => rows('SELECT id FROM packages WHERE user_id = ?', user.id).some(p => f.startsWith(p.id)));
    assert.equal(dropFiles().length, 1);
    assert.equal((await as('DELETE', `/api/admin/accounts/${user.id}`, { currentServerAuthHash: user.serverAuthHash })).status, 403);
    assert.equal((await as('DELETE', `/api/admin/accounts/${user.id}`, {})).status, 403);
    assert.equal(rows('SELECT id FROM users WHERE id = ?', user.id).length, 1);
    const pkgIds = rows('SELECT id FROM packages WHERE user_id = ?', user.id).map(p => p.id);
    assert.equal((await as('DELETE', `/api/admin/accounts/${user.id}`, { currentServerAuthHash: admin.serverAuthHash })).status, 200);
    for (const table of ['users WHERE id', 'packages WHERE user_id', 'shares WHERE user_id', 'one_time_links WHERE user_id']) {
        assert.equal(rows(`SELECT * FROM ${table} = ?`, user.id).length, 0, table);
    }
    assert.equal(fs.readdirSync(path.join(server.dataDir, 'drop')).some(f => pkgIds.some(id => f.startsWith(id))), false);
    assert.equal(fs.existsSync(path.join(server.dataDir, 'shares', `${share}.enc`)), false);
    assert.equal((await api.json('GET', `/api/packages/${user.id}`, null, token)).status, 401);
    assert.equal((await api.login('gone_kai', 'kai password')).status, 401);
});

test('an admin can disable public links, cancel one-time links, and expire or cancel shares', async () => {
    const { user } = await api.register('linked_lea', 'lea password');
    const token = (await api.login('linked_lea', 'lea password')).data.sessionToken;
    const otl = (await api.json('POST', `/api/user/${user.id}/one-time-link`, null, token)).data.token;
    const keep = (await api.share(user.id, token)).data.token;
    const cancel = (await api.share(user.id, token)).data.token;
    const links = (await as('GET', '/api/admin/links')).data;
    const ref = t => require('crypto').createHash('sha256').update('shadowdrop/admin-link-ref/v1|').update(t).digest('hex').slice(0, 24);

    assert.equal((await as('POST', `/api/admin/accounts/${user.id}/public-link`, { enabled: false })).status, 200);
    assert.equal((await api.json('GET', `/api/user/${user.id}/public-key`)).status, 404);
    assert.equal((await api.json('GET', `/api/user/${otl}/public-key`)).status, 200, 'the one-time link still works');

    assert.ok(links.oneTimeLinks.some(o => o.ref === ref(otl)));
    assert.equal((await as('DELETE', `/api/admin/one-time-links/${ref(otl)}`)).status, 200);
    assert.equal((await api.json('GET', `/api/user/${otl}/public-key`)).status, 404);
    assert.equal((await as('DELETE', `/api/admin/one-time-links/${ref(otl)}`)).status, 404);

    assert.equal((await as('POST', `/api/admin/shares/${ref(keep)}/expire`)).status, 200);
    assert.equal((await api.json('GET', `/api/share/${keep}/meta`)).status, 410);
    assert.ok((await as('GET', '/api/admin/links')).data.shares.find(s => s.ref === ref(keep)).expired);

    assert.equal((await as('DELETE', `/api/admin/shares/${ref(cancel)}`)).status, 200);
    assert.equal((await api.json('GET', `/api/share/${cancel}/meta`)).status, 404);
    assert.equal(fs.existsSync(path.join(server.dataDir, 'shares', `${cancel}.enc`)), false);
    assert.equal((await as('DELETE', '/api/admin/shares/not-a-ref')).status, 400);
});

test('the command line lists accounts and switches registration', async () => {
    assert.match(cli('list').out, /root_admin\tadmin/);
    assert.equal(cli('registration', 'closed').status, 0);
    assert.deepEqual((await api.json('GET', '/api/config')).data, { registrationOpen: false });
    assert.equal(cli('registration', 'open').status, 0);
    assert.notEqual(cli('invite', 'root_admin').status, 0, 'existing username');
    assert.notEqual(cli('invite', 'bad name!').status, 0);
    assert.notEqual(cli('nonsense').status, 0);
});

test('an invitation dies with its creator\'s admin rights', async () => {
    const { user } = await api.register('rogue_mo', 'mo password');
    assert.equal((await as('POST', `/api/admin/accounts/${user.id}`, { role: 'admin' })).status, 200);
    const rogue = (await api.login('rogue_mo', 'mo password')).data.sessionToken;
    const sleeper = (await api.json('POST', '/api/admin/invitations', { username: 'sleeper_ned', role: 'admin' }, rogue)).data;
    const pending = (await as('GET', '/api/admin/overview')).data.invitations.find(i => i.username === 'sleeper_ned');
    assert.equal(pending.createdBy, 'rogue_mo');
    assert.equal(pending.void, false);
    // Demoting the creator voids what they handed out
    assert.equal((await as('POST', `/api/admin/accounts/${user.id}`, { role: 'user' })).status, 200);
    assert.equal((await as('GET', '/api/admin/overview')).data.invitations.find(i => i.username === 'sleeper_ned').void, true);
    assert.equal((await api.json('POST', '/api/auth/invitation', { token: sleeper.token })).status, 404);
    assert.equal((await api.register('sleeper_ned', 'ned password', { invitationToken: sleeper.token })).res.status, 403);
    // A void invitation no longer reserves its username
    assert.equal((await api.register('sleeper_ned', 'ned password')).res.status, 200);
    assert.equal((await api.login('sleeper_ned', 'ned password')).data.role, 'user');
    // Invitations from the server shell have no creator to lose
    assert.ok((await as('GET', '/api/admin/overview')).data.accounts.some(a => a.username === 'root_admin'));
});

test('a used activation link says so, and an expired invitation frees its username', async () => {
    const used = (await as('POST', '/api/admin/invitations', { username: 'used_ola' })).data;
    assert.equal((await api.register('used_ola', 'ola password', { invitationToken: used.token })).res.status, 200);
    const lookup = await api.json('POST', '/api/auth/invitation', { token: used.token });
    assert.equal(lookup.status, 410);
    assert.equal(lookup.data.code, 'activated');
    const expired = (await as('POST', '/api/admin/invitations', { username: 'freed_pia' })).data;
    write('UPDATE invitations SET expires_at = ? WHERE id = ?', new Date(Date.now() - 1000).toISOString(), expired.id);
    // The admin can invite the name again, and self-registration is no longer blocked by it
    const again = await as('POST', '/api/admin/invitations', { username: 'freed_pia' });
    assert.equal(again.status, 200);
    assert.equal((await as('DELETE', `/api/admin/invitations/${again.data.id}`)).status, 200);
    assert.equal((await api.register('freed_pia', 'pia password')).res.status, 200);
});

test('an admin can turn a public link off but not back on', async () => {
    const { user } = await api.register('owner_quin', 'quin password');
    assert.equal((await as('POST', `/api/admin/accounts/${user.id}/public-link`, { enabled: false })).status, 200);
    assert.equal((await as('POST', `/api/admin/accounts/${user.id}/public-link`, { enabled: true })).status, 400);
    assert.equal((await api.json('GET', `/api/user/${user.id}/public-key`)).status, 404);
});

test('with two admins, an admin still cannot disable, demote or delete themselves', async () => {
    const { user } = await api.register('peer_rae', 'rae password');
    assert.equal((await as('POST', `/api/admin/accounts/${user.id}`, { role: 'admin' })).status, 200);
    const peer = (await api.login('peer_rae', 'rae password')).data.sessionToken;
    assert.equal((await api.json('POST', `/api/admin/accounts/${user.id}`, { disabled: true }, peer)).status, 409);
    assert.equal((await api.json('POST', `/api/admin/accounts/${user.id}`, { role: 'user' }, peer)).status, 409);
    assert.equal((await api.json('DELETE', `/api/admin/accounts/${user.id}`, { currentServerAuthHash: user.serverAuthHash }, peer)).status, 409);
    assert.equal((await as('POST', `/api/admin/accounts/${user.id}`, { role: 'user' })).status, 200);
});

test('invitations are refused for taken usernames and unknown roles', async () => {
    assert.equal((await as('POST', '/api/admin/invitations', { username: 'root_admin' })).status, 409);
    assert.equal((await as('POST', '/api/admin/invitations', { username: 'role_sam', role: 'superuser' })).status, 400);
    assert.equal((await as('POST', '/api/admin/invitations', { username: 'x' })).status, 400);
});

test('a disabled account\'s one-time links and share downloads stop working too', async () => {
    const { user } = await api.register('stopped_tia', 'tia password');
    const token = (await api.login('stopped_tia', 'tia password')).data.sessionToken;
    const otl = (await api.json('POST', `/api/user/${user.id}/one-time-link`, null, token)).data.token;
    const share = (await api.share(user.id, token)).data.token;
    assert.equal((await as('POST', `/api/admin/accounts/${user.id}`, { disabled: true })).status, 200);
    assert.equal((await api.json('GET', `/api/user/${otl}/public-key`)).status, 404);
    assert.equal((await api.drop(otl, user.publicKey, [{ name: 'a.txt', content: 'x' }])).status, 404);
    assert.equal((await fetch(`${server.base}/api/share/${share}/download`)).status, 410);
});
