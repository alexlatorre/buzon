// Invitation tokens: 32 random bytes, base64url. The database keeps only their SHA-256, so the token
// itself exists once: in the activation link the admin hands to the person.
const crypto = require('crypto');

const TOKEN_REGEX = /^[A-Za-z0-9_-]{43}$/;

function newInvitationToken() {
    return crypto.randomBytes(32).toString('base64url');
}

function invitationTokenHash(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
}

function isInvitationToken(value) {
    return typeof value === 'string' && TOKEN_REGEX.test(value);
}

module.exports = { newInvitationToken, invitationTokenHash, isInvitationToken };
