// Account administration from the server's shell, for what has to happen before any admin exists:
//
//   node scripts/admin.js invite <username> [--admin] [--origin https://host]   activation link for a new account
//   node scripts/admin.js promote <username> | demote <username>                 change an existing account's role
//   node scripts/admin.js registration open|closed                              switch self-registration
//   node scripts/admin.js list                                                   accounts and pending invitations
//
// In Docker: docker exec shadow-drop node scripts/admin.js invite alex --admin
// It uses the same database settings as the server (DATA_DIR, DB_ENGINE, MYSQL_*). An invitation's
// keys are created in the invited person's browser when they activate it; this script never sees them.
const db = require('../db');
const { newInvitationToken, invitationTokenHash } = require('../invitations');

const USERNAME_REGEX = /^[a-zA-Z0-9_]{3,32}$/;
const INVITATION_TTL_HOURS = Number(process.env.INVITATION_TTL_HOURS) || 72;

function fail(message) {
    console.error(message);
    process.exit(1);
}

function option(args, name) {
    const i = args.indexOf(name);
    return i >= 0 ? args[i + 1] : undefined;
}

async function invite(args) {
    const username = args[0];
    if (!username || !USERNAME_REGEX.test(username)) fail('Username: 3-32 characters, alphanumeric and underscores only');
    const role = args.includes('--admin') ? 'admin' : 'user';
    if (await db.getUserByUsername(username)) fail(`${username} already exists`);
    const pending = await db.getInvitationByUsername(username);
    if (pending && new Date(pending.expires_at) > new Date()) fail(`${username} is already invited`);
    if (pending) await db.deleteInvitation(pending.id);
    const token = newInvitationToken();
    const expiresAt = new Date(Date.now() + INVITATION_TTL_HOURS * 3600000).toISOString();
    await db.createInvitation(username, role, invitationTokenHash(token), expiresAt, null);
    const origin = (option(args, '--origin') || '').replace(/\/$/, '');
    console.log(`Invitation for ${username} (${role}), valid until ${expiresAt}.`);
    console.log('Activation link (shown only now; it works once):');
    console.log(`${origin || '<https://your-host>'}/#activate=${token}`);
}

async function setRole(username, role) {
    const user = await db.getUserByUsername(username || '');
    if (!user) fail(`No account named ${username}`);
    if (role === 'user' && user.role === 'admin' && !user.disabled && await db.countActiveAdmins() <= 1) fail('There must be at least one active admin');
    await db.setUserRole(user.id, role);
    console.log(`${username} is now ${role === 'admin' ? 'an admin' : 'a regular user'}.`);
}

async function list() {
    for (const a of await db.listAccounts()) {
        console.log(`${a.username}\t${a.role}${a.disabled ? '\tdisabled' : ''}`);
    }
    for (const i of await db.listInvitations()) {
        console.log(`${i.username}\t${i.role}\tinvited, expires ${new Date(i.expires_at).toISOString()}`);
    }
    console.log(`registration: ${(await db.getSetting('registration')) || process.env.REGISTRATION || 'open'}`);
}

(async () => {
    await db.ready;
    const [command, ...args] = process.argv.slice(2);
    if (command === 'invite') await invite(args);
    else if (command === 'promote') await setRole(args[0], 'admin');
    else if (command === 'demote') await setRole(args[0], 'user');
    else if (command === 'registration' && ['open', 'closed'].includes(args[0])) {
        await db.setSetting('registration', args[0]);
        console.log(`Registration ${args[0]}.`);
    } else if (command === 'list') await list();
    else fail('Usage: node scripts/admin.js invite <username> [--admin] [--origin URL] | promote <username> | demote <username> | registration open|closed | list');
    process.exit(0);
})().catch(error => fail(`Error: ${error.message}`));
