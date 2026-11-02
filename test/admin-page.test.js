// The real app.js: activating an admin-created account from its link (keys created in the browser), the
// registration switch on the login page, and the admin panel.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('child_process');
const path = require('path');
const { startServer, client } = require('./helpers');
const { loadAppPage } = require('./app-page');

let server, api, adminToken;
const settle = () => new Promise(r => setTimeout(r, 20));

function cliInvite(username, ...flags) {
    const r = spawnSync(process.execPath, [path.join(__dirname, '..', 'scripts', 'admin.js'), 'invite', username, ...flags], {
        env: { ...process.env, DATA_DIR: server.dataDir, DB_ENGINE: 'sqlite' }, encoding: 'utf8'
    });
    return /#activate=([A-Za-z0-9_-]{43})/.exec(r.stdout)[1];
}

function page(options = {}) {
    return loadAppPage({ fetch: (url, opts) => globalThis.fetch(server.base + url, opts), hidden: ['btn-open-admin', 'admin-invite-result'], ...options });
}

async function loginPage(username, password, options) {
    const ui = page(options);
    ui.el('username').value = username;
    ui.el('password').value = password;
    await ui.page.handleLogin();
    assert.ok(ui.page.user.sessionToken, ui.el('auth-msg').textContent);
    return ui;
}

before(async () => {
    server = await startServer({ API_RATE_LIMIT: '5000' });
    api = client(server.base);
    const token = cliInvite('panel_admin', '--admin');
    assert.equal((await api.register('panel_admin', 'panel admin password', { invitationToken: token })).res.status, 200);
    adminToken = (await api.login('panel_admin', 'panel admin password')).data.sessionToken;
});

after(() => server.stop());

test('an activation link lets the person choose a password and creates the keys in the browser', async () => {
    const token = cliInvite('link_mia');
    const ui = page({ hash: `#activate=${token}` });
    for (let i = 0; i < 50 && ui.el('username').value !== 'link_mia'; i++) await settle();
    assert.equal(ui.el('username').value, 'link_mia');
    assert.equal(ui.el('username').readOnly, true);
    assert.equal(ui.window.location.hash, '', 'the token is taken out of the address bar');
    assert.ok(ui.el('btn-login').classList.contains('hidden'));
    assert.equal(ui.el('password-confirm-group').classList.contains('hidden'), false);
    assert.equal(ui.el('btn-register').textContent, 'Activate Account');

    ui.el('password').value = 'mia new password';
    ui.el('password-confirm').value = 'something else';
    await ui.page.handleRegister();
    assert.match(ui.el('auth-msg').textContent, /do not match/);
    ui.el('password-confirm').value = 'mia new password';
    await ui.page.handleRegister();
    assert.match(ui.el('auth-msg').textContent, /Account activated/);
    assert.equal(ui.el('username').readOnly, false);
    assert.equal(ui.el('btn-login').classList.contains('hidden'), false);

    const login = await api.login('link_mia', 'mia new password');
    assert.equal(login.status, 200);
    assert.equal(login.data.role, 'user');
    // The same link cannot be used again
    const again = page({ hash: `#activate=${token}` });
    for (let i = 0; i < 50 && !again.el('auth-msg').textContent; i++) await settle();
    assert.match(again.el('auth-msg').textContent, /already used.*someone else may have taken it/);
});

test('with registration closed the login page offers no registration', async () => {
    assert.equal((await api.json('POST', '/api/admin/registration', { open: false }, adminToken)).status, 200);
    const closed = page();
    for (let i = 0; i < 50 && !closed.el('btn-register').classList.contains('hidden'); i++) await settle();
    assert.ok(closed.el('btn-register').classList.contains('hidden'));
    assert.equal((await api.json('POST', '/api/admin/registration', { open: true }, adminToken)).status, 200);
    const open = page();
    await settle(); await settle();
    assert.equal(open.el('btn-register').classList.contains('hidden'), false);
});

test('only admins see the admin panel, and it lists accounts and creates activation links', async () => {
    await api.register('panel_user', 'panel user password');
    const user = await loginPage('panel_user', 'panel user password');
    assert.ok(user.el('btn-open-admin').classList.contains('hidden'));
    await user.page.openAdminModal();
    assert.equal(user.el('admin-accounts').children.length, 0);

    const ui = await loginPage('panel_admin', 'panel admin password');
    assert.equal(ui.el('btn-open-admin').classList.contains('hidden'), false);
    await ui.page.openAdminModal();
    const names = ui.el('admin-accounts').children.map(row => row.children[0].children[0].textContent);
    assert.ok(names.some(n => n.startsWith('panel_admin · admin')), JSON.stringify(names));
    assert.ok(names.some(n => n.startsWith('panel_user · user')));

    ui.el('admin-new-username').value = 'from_panel';
    await ui.page.handleAdminInvite();
    assert.match(ui.el('admin-invite-link').value, /^https:\/\/box\.test\/#activate=[A-Za-z0-9_-]{43}$/);
    assert.equal(ui.el('admin-invite-result').classList.contains('hidden'), false);
    const invited = ui.el('admin-invitations').children.map(row => row.children[0].children[0].textContent);
    assert.ok(invited.includes('from_panel · user'));

    // Logging out leaves nothing of the panel behind
    ui.page.logout();
    assert.equal(ui.el('admin-accounts').children.length, 0);
    assert.equal(ui.el('admin-invite-link').value, '');
    assert.ok(ui.el('btn-open-admin').classList.contains('hidden'));
});

test('deleting an account from the panel asks for the admin password', async () => {
    await api.register('panel_target', 'target password');
    const ui = await loginPage('panel_admin', 'panel admin password');
    await ui.page.openAdminModal();
    const row = () => ui.el('admin-accounts').children.find(r => r.children[0].children[0].textContent.startsWith('panel_target'));
    const deleteButton = () => row().children[1].children.find(b => b.textContent === 'Delete');
    await deleteButton().onclick();
    assert.match(ui.el('admin-msg').textContent, /Enter your password/);
    ui.el('admin-password').value = 'not the admin password';
    await deleteButton().onclick();
    assert.match(ui.el('admin-msg').textContent, /password is wrong/);
    ui.el('admin-password').value = 'panel admin password';
    await deleteButton().onclick();
    assert.match(ui.el('admin-msg').textContent, /deleted/);
    assert.equal(row(), undefined);
    assert.equal((await api.login('panel_target', 'target password')).status, 401);
});
