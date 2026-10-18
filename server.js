const express = require('express');
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const db = require('./db');

// --- Session Management ---
const sessions = new Map(); // token -> { userId, createdAt }
const SESSION_TTL = 24 * 60 * 60 * 1000; // 24 hours

function createSession(userId) {
    const token = crypto.randomUUID();
    sessions.set(token, { userId, createdAt: Date.now() });
    return token;
}

function validateSession(token) {
    const session = sessions.get(token);
    if (!session) return null;
    if (Date.now() - session.createdAt > SESSION_TTL) {
        sessions.delete(token);
        return null;
    }
    return session;
}

function destroySession(token) {
    sessions.delete(token);
}

// --- Auth Hash Helpers ---
// The DB stores sha256(serverAuthHash), so a leaked DB can't be replayed to log in
const AUTH_HASH_PREFIX = 'sha256:';
const LEGACY_AUTH_MARKER = 'LEGACY_MIGRATION_REQUIRED';

function hashAuthToken(value) {
    return AUTH_HASH_PREFIX + crypto.createHash('sha256').update(String(value)).digest('hex');
}

function safeEqual(a, b) {
    const bufA = Buffer.from(String(a));
    const bufB = Buffer.from(String(b));
    return bufA.length === bufB.length && crypto.timingSafeEqual(bufA, bufB);
}

function verifyAuthHash(stored, provided) {
    if (stored.startsWith(AUTH_HASH_PREFIX)) return safeEqual(stored, hashAuthToken(provided));
    // Rows written before hashing was introduced; upgraded on the next successful login
    return safeEqual(stored, provided);
}

// Fake salts for unknown usernames: deterministic per username and indistinguishable from real ones
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}
const SALT_SECRET_PATH = path.join(DATA_DIR, '.salt_secret');

function loadSaltSecret() {
    if (fs.existsSync(SALT_SECRET_PATH)) return fs.readFileSync(SALT_SECRET_PATH);
    const secret = crypto.randomBytes(32);
    fs.writeFileSync(SALT_SECRET_PATH, secret, { mode: 0o600 });
    // A new secret next to existing accounts means it was lost (e.g. a restore without dotfiles):
    // fake salts change, so comparing them over time reveals which usernames are real
    db.countUsers().then(count => {
        if (count > 0) {
            console.warn(`[Security] ${SALT_SECRET_PATH} was missing and has been regenerated although the database has ${count} account(s). `
                + 'Restore the original .salt_secret from your backup to keep unknown usernames indistinguishable.');
        }
    }).catch(() => {});
    return secret;
}
const saltSecret = loadSaltSecret();

function fakeSaltFor(username) {
    return crypto.createHmac('sha256', saltSecret).update(username).digest().subarray(0, 16).toString('base64');
}

// Legacy accounts (no auth hash yet) must prove they hold the private key before a hash is accepted.
// The nonce is encrypted under its own OAEP label so the browser cannot be used to decrypt anything
// else (package session keys have no label), and the client answers with a hash of the nonce.
// Both strings must match public/crypto.js.
// Migrating a legacy account means handing its encrypted private key to whoever asks for the username
// (there is nothing else to check the password against), which allows offline guessing. So it is
// closed by default; set LEGACY_MIGRATION=open for as long as legacy owners need to log in once.
const LEGACY_MIGRATION_OPEN = process.env.LEGACY_MIGRATION === 'open';
const MIGRATION_CHALLENGE_LABEL = Buffer.from('shadowdrop/migration-challenge/v1');
const MIGRATION_RESPONSE_PREFIX = Buffer.from('shadowdrop/migration-response/v1');
// Keyed by a random id per attempt, so one login attempt can only consume its own challenge and a
// stranger asking for challenges cannot invalidate the owner's
const migrationChallenges = new Map(); // challengeId -> { userId, expectedResponse, expiresAt }
const CHALLENGE_TTL = 5 * 60 * 1000;
const MAX_PENDING_CHALLENGES = 20; // per user; the oldest is dropped beyond this

// Proof of holding an account's private key: a random nonce encrypted to its public key under a label
// of its own, answered with a hash of the nonce (never the nonce itself). Kept in `store` per attempt
function createKeyChallenge(store, user, label, responsePrefix) {
    const nonce = crypto.randomBytes(32);
    const publicKey = crypto.createPublicKey({ key: Buffer.from(user.public_key, 'base64'), format: 'der', type: 'spki' });
    const encrypted = crypto.publicEncrypt(
        { key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256', oaepLabel: label },
        nonce
    );
    const expectedResponse = crypto.createHash('sha256').update(responsePrefix).update(nonce).digest('base64');

    const pending = [...store].filter(([, c]) => c.userId === user.id);
    if (pending.length >= MAX_PENDING_CHALLENGES) store.delete(pending[0][0]);
    const challengeId = crypto.randomUUID();
    store.set(challengeId, { userId: user.id, publicKey: user.public_key, expectedResponse, expiresAt: Date.now() + CHALLENGE_TTL });
    return { challengeId, challenge: encrypted.toString('base64') };
}

function createMigrationChallenge(user) {
    return createKeyChallenge(migrationChallenges, user, MIGRATION_CHALLENGE_LABEL, MIGRATION_RESPONSE_PREFIX);
}

// A key rotation must come from whoever holds the current private key, not only the login auth hash
// (which a login request carries): otherwise that hash alone could swap the public key senders get.
// Own label and prefix, both in public/crypto.js too
const ROTATION_CHALLENGE_LABEL = Buffer.from('shadowdrop/rotation-challenge/v1');
const ROTATION_RESPONSE_PREFIX = Buffer.from('shadowdrop/rotation-response/v1');
const rotationChallenges = new Map(); // challengeId -> { userId, publicKey, expectedResponse, expiresAt }

// Cleanup expired sessions and challenges every hour
setInterval(() => {
    const now = Date.now();
    for (const [token, session] of sessions) {
        if (now - session.createdAt > SESSION_TTL) sessions.delete(token);
    }
    for (const store of [migrationChallenges, rotationChallenges]) {
        for (const [challengeId, challenge] of store) {
            if (challenge.expiresAt < now) store.delete(challengeId);
        }
    }
}, 60 * 60 * 1000);

// Auth middleware — extracts and validates session from Authorization header
function requireAuth(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    const token = authHeader.slice(7);
    const session = validateSession(token);
    if (!session) {
        return res.status(401).json({ error: 'Invalid or expired session' });
    }
    req.session = session;
    req.sessionToken = token;
    next();
}

// UUID format validator
// Lowercase only: the server issues lowercase ids, and an uppercase variant could miss a DB row
// while still naming the same file on a case-insensitive filesystem
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
function isValidUUID(str) {
    return UUID_REGEX.test(str);
}

// --- File Integrity System ---
// SHA-256 of every critical public file, as served. Recomputed when a file changes on disk, so
// updating public/ without a restart does not make every browser report a MITM.
// The same list lives in public/integrity.js and scripts/update-hashes.js (a test keeps them equal).
const INTEGRITY_FILES = ['app.js', 'crypto.js', 'drop.js', 'integrity.js', 'share.js', 'index.html', 'about.html', 'drop.html', 'share.html', 'style.css'];
const hashCache = new Map(); // file -> { mtimeMs, size, hash }

function currentFileHashes() {
    const hashes = {};
    for (const file of INTEGRITY_FILES) {
        const filePath = path.join(__dirname, 'public', file);
        let stat;
        try { stat = fs.statSync(filePath); } catch { continue; }
        const cached = hashCache.get(file);
        if (!cached || cached.mtimeMs !== stat.mtimeMs || cached.size !== stat.size) {
            const hash = crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
            hashCache.set(file, { mtimeMs: stat.mtimeMs, size: stat.size, hash });
        }
        hashes[file] = hashCache.get(file).hash;
    }
    return hashes;
}

console.log(`[Integrity] Computed SHA-256 hashes for ${Object.keys(currentFileHashes()).length} files`);

const app = express();
const PORT = process.env.PORT || 4000;
// TLS=off forces plain HTTP (TLS terminated by a reverse proxy, or tests)
const sslCerts = process.env.TLS === 'off' ? null : findSSLCerts();
// Plain HTTP only when asked for: without certificates and without TLS=off the server would serve
// cleartext on the port the operator believes is HTTPS (e.g. a certificate volume not mounted)
if (process.env.TLS !== 'off' && !sslCerts) {
    console.error('No TLS certificates found (looked for certs/fullchain.pem + certs/privkey.pem, fullchain.pem + privkey.pem, cert.pem + key.pem).');
    console.error('Mount them, or set TLS=off to serve plain HTTP behind a TLS-terminating proxy.');
    process.exit(1);
}

// X-Forwarded-For decides the client IP the rate limiters see, so it is only trusted when the
// operator says a proxy is in front: TRUST_PROXY, or TLS=off (the documented "TLS terminated by a
// proxy" mode, one hop). Otherwise clients could forge it and dodge every limit.
function parseTrustProxy(value) {
    if (value === undefined || value === '') return process.env.TLS === 'off' ? 1 : false;
    if (value === 'false') return false;
    if (value === 'true') {
        console.error('TRUST_PROXY=true trusts every X-Forwarded-For entry, so clients could bypass the rate limits. '
            + 'Set it to the number of proxies in front of the app (for example 1) or to false.');
        process.exit(1);
    }
    if (/^\d+$/.test(value)) return Number(value);
    return value;
}
app.set('trust proxy', parseTrustProxy(process.env.TRUST_PROXY));

app.disable('x-powered-by');

// --- Security Headers (CSP + hardening) ---
// First middleware of all, so 429s, body-parser errors and 404s carry them too
app.use((req, res, next) => {
    // Strict Content Security Policy — blocks all inline scripts and external sources
    res.setHeader('Content-Security-Policy', [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self' 'unsafe-inline'",   // inline styles needed for some UI elements
        "img-src 'self' data:",                // data: URIs for emoji rendering
        "font-src 'self'",
        "connect-src 'self'",                  // fetch/XHR only to same origin
        "frame-src 'none'",                    // no iframes
        "object-src 'none'",                   // no plugins/Flash
        "base-uri 'self'",                     // prevent <base> tag hijacking
        "form-action 'self'",                  // forms only submit to same origin
        "frame-ancestors 'none'",              // prevent clickjacking (like X-Frame-Options)
        "upgrade-insecure-requests"
    ].join('; '));

    // HSTS — enforce HTTPS for 1 year
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');

    // Prevent MIME type sniffing
    res.setHeader('X-Content-Type-Options', 'nosniff');

    // Cross-origin isolation: no other origin may open us in a window it controls or embed our resources
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');

    // Clickjacking protection
    res.setHeader('X-Frame-Options', 'DENY');

    // Don't leak referrer info
    res.setHeader('Referrer-Policy', 'no-referrer');

    // Restrict browser features
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), interest-cohort=()');

    // Prevent caching of sensitive data
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');

    next();
});

// A key rotation carries one re-wrapped key per package and share, so it may be larger; its body is
// read by its own parser, only once the session has been checked
const ROTATE_KEYS_PATH = '/api/auth/rotate-keys';
const jsonBody = express.json({ limit: '5mb' });
// As Express routes it: any case, one trailing slash
const isRotateKeysPath = p => p.toLowerCase().replace(/\/$/, '') === ROTATE_KEYS_PATH;
app.use((req, res, next) => (isRotateKeysPath(req.path) ? next() : jsonBody(req, res, next)));
// Express 5 leaves req.body undefined without a JSON body; handlers then answer 400 instead of crashing
app.use((req, res, next) => {
    if (req.body === undefined) req.body = {};
    next();
});

// Rate limiting
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: Number(process.env.AUTH_RATE_LIMIT) || 20, message: { error: 'Too many attempts, try again later' } });
const dropLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 50, message: { error: 'Too many uploads, try again later' } });
// Login has its own limiter: ordinary dashboard traffic must not lock an IP out of signing in
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: Number(process.env.API_RATE_LIMIT) || 200,
    skip: req => req.path.startsWith('/auth/'),
    message: { error: 'Too many requests, try again later' }
});
app.use('/api/auth/', authLimiter);
app.use('/api/drop/', dropLimiter);
app.use('/api/', apiLimiter);


app.use(express.static(path.join(__dirname, 'public')));

const DROP_DIR = path.join(DATA_DIR, 'drop');
if (!fs.existsSync(DROP_DIR)) {
    fs.mkdirSync(DROP_DIR, { recursive: true });
}

// Set up file storage for dropped files
const dropStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, DROP_DIR);
    },
    filename: (req, file, cb) => {
        cb(null, `${uuidv4()}.upload`);
    }
});
const MAX_DROP_FILES = 20;
// Largest multipart text field: the encrypted message (base64 of up to MAX_MESSAGE_BYTES)
const MAX_MESSAGE_BYTES = 256 * 1024;
const MAX_FIELD_SIZE = 360 * 1024;

// --- Upload field validation ---
// Multipart fields arrive as strings; a repeated field becomes an array, which must be refused too.
const BASE64_REGEX = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

// Decoded size of a canonical base64 string, or -1 if it is not one
function base64Bytes(value) {
    if (typeof value !== 'string' || !BASE64_REGEX.test(value)) return -1;
    return Buffer.from(value, 'base64').length;
}

// Whole number in [min, max]; missing or empty means 0; anything else is null
function intField(value, min, max) {
    if (value === undefined || value === '') return 0;
    if (typeof value !== 'string' || !/^\d{1,6}$/.test(value)) return null;
    const n = Number(value);
    return n >= min && n <= max ? n : null;
}

const optionalString = (value, maxLength) => value === undefined || (typeof value === 'string' && value.length <= maxLength);

// RSA-OAEP session key (2048, 3072 or 4096-bit key), 12-byte GCM IV, message = ciphertext + 16-byte tag
function dropFieldsError(body, files) {
    const fileCount = files.length;
    if (body.format !== undefined && body.format !== '2') return 'Unknown package format';
    // Format 2 bodies are IV (12) || ciphertext || tag (16): anything shorter cannot be a file
    if (body.format === '2' && files.some(f => f.size < 28)) return 'Invalid file';
    if (![256, 384, 512].includes(base64Bytes(body.encryptedSessionKey))) return 'Invalid session key';
    if (base64Bytes(body.messageIv) !== 12) return 'Invalid message IV';
    const messageBytes = base64Bytes(body.encryptedMessage);
    if (messageBytes < 16 || messageBytes > MAX_MESSAGE_BYTES + 16) return 'Invalid message';
    if (fileCount === 0 && messageBytes === 16) return 'Nothing to send';
    if (!optionalString(body.senderName, 256)) return 'Invalid sender name';
    if (!optionalString(body.fileNames, MAX_FIELD_SIZE)) return 'Invalid file names';
    if (body.keyFingerprint !== undefined && !(typeof body.keyFingerprint === 'string' && KEY_FINGERPRINT_REGEX.test(body.keyFingerprint))) return 'Invalid key fingerprint';
    return null;
}

// Fingerprint of a public key as public/crypto.js publicKeyFingerprint computes it (the "#k=" of drop
// links): base64url SHA-256 of the SPKI, 22 characters
const KEY_FINGERPRINT_REGEX = /^[A-Za-z0-9_-]{22}$/;
function publicKeyFingerprint(spkiBase64) {
    return crypto.createHash('sha256').update(Buffer.from(spkiBase64, 'base64')).digest('base64url').slice(0, 22);
}

// Wrapped AES-256 key (32 + 16 tag), 12-byte IVs, 16-byte PBKDF2 salt, values the dashboard offers
// Format 2 (format=2): name sealed with the file key ("enc2:"), no type, file key wrapped for the owner
function shareFieldsError(body) {
    if (body.format !== undefined && body.format !== '2') return 'Unknown share format';
    if (base64Bytes(body.encryptedFileKey) !== 48) return 'Invalid file key';
    if (base64Bytes(body.keyIv) !== 12 || base64Bytes(body.fileIv) !== 12) return 'Invalid IV';
    if (base64Bytes(body.salt) !== 16) return 'Invalid salt';
    if (body.format === '2') {
        if (typeof body.originalName !== 'string' || body.originalName.length > 2048
            || !body.originalName.startsWith('enc2:') || !ENC_NAME_REGEX.test(body.originalName)) return 'Invalid file name';
        if (body.mimeType !== undefined) return 'Invalid file type';
        if (![256, 384, 512].includes(base64Bytes(body.ownerKey))) return 'Invalid owner key';
    } else {
        if (typeof body.originalName !== 'string' || !body.originalName || body.originalName.length > 255) return 'Invalid file name';
        if (!optionalString(body.mimeType, 255)) return 'Invalid file type';
        if (body.ownerKey !== undefined) return 'Invalid owner key';
    }
    if (body.encryptedMessage !== undefined) {
        const messageBytes = base64Bytes(body.encryptedMessage);
        if (messageBytes < 16 || messageBytes > MAX_MESSAGE_BYTES + 16) return 'Invalid message';
        if (base64Bytes(body.messageIv) !== 12) return 'Invalid message IV';
    } else if (body.messageIv !== undefined) {
        return 'Invalid message IV';
    }
    if (body.downloadProof !== undefined && base64Bytes(body.downloadProof) !== 32) return 'Invalid download proof';
    if (intField(body.maxDownloads, 0, 1000) === null) return 'maxDownloads must be 0-1000';
    if (intField(body.expiresIn, 0, 8760) === null) return 'expiresIn must be 0-8760 hours';
    return null;
}
const upload = multer({
    storage: dropStorage,
    limits: { fileSize: 50 * 1024 * 1024, files: MAX_DROP_FILES, fields: 10, fieldSize: MAX_FIELD_SIZE } // 50MB max per file
});

// Deletes a stored file. "Already gone" is fine; anything else is logged so a file left behind (e.g.
// locked on a Windows/SMB volume) is visible instead of silently orphaned
function removeFile(filePath) {
    try {
        fs.unlinkSync(filePath);
    } catch (error) {
        if (error.code !== 'ENOENT') console.error(`Could not delete ${filePath}: ${error.message}`);
    }
}

function removeUploadedFiles(req) {
    const files = req.files || (req.file ? [req.file] : []);
    files.forEach(f => removeFile(f.path));
}

// Quota is check-then-insert. With MySQL every query yields to the event loop, so concurrent uploads
// for the same user could all pass the check; this serialises that section per user. It is an
// in-process lock: enough for the single Node process this app runs as, not for several replicas.
// Key rotations, password changes and logins take it too, so sessions and keys change together.
const quotaLocks = new Map(); // userId -> promise of the last holder
async function lockUserQuota(userId) {
    const previous = quotaLocks.get(userId) || Promise.resolve();
    let release;
    const mine = new Promise(resolve => { release = resolve; });
    const tail = previous.then(() => mine);
    quotaLocks.set(userId, tail);
    await previous;
    return () => {
        release();
        if (quotaLocks.get(userId) === tail) quotaLocks.delete(userId);
    };
}

// Total storage used by a user: pending drop packages plus active shares
async function getStorageUsage(userId) {
    const used = Number(await db.getUserMailboxUsage(userId)) || 0;
    const shares = await db.getSharesByUserId(userId);
    return used + shares.reduce((acc, s) => acc + Number(s.size), 0);
}

// Resolves a drop link (user ID with public link enabled, or unused one-time token)
async function findDropRecipient(idOrToken) {
    let user = await db.getUserById(idOrToken);
    if (user && user.public_link_enabled !== 0) return { user, isToken: false };
    user = await db.getUserByToken(idOrToken);
    return user ? { user, isToken: true } : null;
}

// Runs before multer so nothing touches the disk for invalid links or full mailboxes
const MULTIPART_OVERHEAD = 1024 * 1024;

// Uploads must declare their size up front: without Content-Length (chunked) the quota pre-check
// cannot run and multer would write up to its per-file limits before the request is rejected.
// Node stops reading at the declared length, so the declared size bounds what reaches the disk.
function declaredUploadSize(req) {
    if (req.headers['transfer-encoding'] !== undefined) return null;
    const value = req.headers['content-length'];
    return /^\d+$/.test(value || '') ? Number(value) : null;
}

async function resolveDropTarget(req, res, next) {
    try {
        if (!isValidUUID(req.params.id)) {
            return res.status(400).json({ error: 'Invalid link format' });
        }
        const target = await findDropRecipient(req.params.id);
        if (!target) {
            return res.status(404).json({ error: 'Recipient or valid link not found' });
        }
        const declaredSize = declaredUploadSize(req);
        if (declaredSize === null) {
            return res.status(411).json({ error: 'Content-Length required' });
        }
        const remaining = target.user.mailbox_quota - await getStorageUsage(target.user.id);
        if (remaining <= 0 || declaredSize > remaining + MULTIPART_OVERHEAD) {
            return res.status(413).json({ error: 'Mailbox quota exceeded' });
        }
        req.dropTarget = target;
        next();
    } catch (error) {
        console.error('Drop target error:', error);
        res.status(500).json({ error: 'Server error processing drop' });
    }
}

// File names from the drop page arrive encrypted with the package session key
// "enc:" for format 1 packages, "enc2:" for format 2 (name and file id bound to the package key)
const ENC_NAME_REGEX = /^enc2?:[A-Za-z0-9+/]+=*:[A-Za-z0-9+/]+=*$/;
const UNNAMED_FILE = 'file';
const STORED_FILE_TYPE = 'application/octet-stream';
function parseEncryptedNames(raw) {
    try {
        const names = JSON.parse(raw || '[]');
        return Array.isArray(names) ? names : [];
    } catch {
        return [];
    }
}

// --- API Endpoints ---

// 0. File Integrity Endpoint
app.get('/api/integrity', (req, res) => {
    res.json({ files: currentFileHashes() });
});

// Key derivation stored per account, as public/crypto.js parseKdf accepts it. New accounts and
// password changes may only use the current default (KDF_DEFAULT in public/crypto.js, kept equal by a
// test), so no account can stand out from the fake answers for unknown usernames. After raising both,
// accounts still on the old one can be told apart until their next password change.
const DEFAULT_KDF = 'pbkdf2-sha256:600000';

// The password-protected part of an account: 16-byte salt, key derivation, AES-GCM encrypted PKCS8
// key, 12-byte IV, SHA-256 auth hash
function vaultFieldsError(body) {
    if (base64Bytes(body.salt) !== 16) return 'Invalid salt';
    if (body.kdf !== undefined && body.kdf !== DEFAULT_KDF) return 'Invalid key derivation';
    if (base64Bytes(body.iv) !== 12) return 'Invalid IV';
    if (base64Bytes(body.serverAuthHash) !== 32) return 'Invalid auth hash';
    const privateKeyBytes = base64Bytes(body.encryptedPrivateKey);
    if (privateKeyBytes < 256 || privateKeyBytes > 16 * 1024) return 'Invalid encrypted private key';
    return null;
}

// Key material must have the shape public/app.js produces: the vault fields plus an RSA-OAEP public
// key (2048-8192 bits, SPKI)
function registrationFieldsError(body) {
    const vaultError = vaultFieldsError(body);
    if (vaultError) return vaultError;
    const publicKeyBytes = base64Bytes(body.publicKey);
    if (publicKeyBytes < 0 || publicKeyBytes > 4096) return 'Invalid public key';
    const bits = rsaKeyBits(body.publicKey);
    if (!(bits >= 2048 && bits <= 8192)) return 'Invalid public key';
    return null;
}

// Modulus length of an RSA public key (base64 SPKI), or 0 when it is not one
function rsaKeyBits(spkiBase64) {
    try {
        const key = crypto.createPublicKey({ key: Buffer.from(spkiBase64, 'base64'), format: 'der', type: 'spki' });
        return key.asymmetricKeyType === 'rsa' && key.asymmetricKeyDetails ? key.asymmetricKeyDetails.modulusLength : 0;
    } catch {
        return 0;
    }
}

// Re-wrapped keys of a key rotation: each package and share once, by its id, with an RSA-OAEP
// ciphertext the size of the new key, or null for one the current key could not open (left as it is)
function rotationListsError(packages, shares, newKeyBits) {
    if (!Array.isArray(packages) || !Array.isArray(shares)) return 'Invalid key lists';
    const wrappedSize = Math.ceil(newKeyBits / 8);
    const ids = new Set();
    for (const p of packages) {
        if (!p || typeof p.id !== 'string' || !isValidUUID(p.id) || ids.has(p.id)) return 'Invalid package list';
        if (p.encryptedSessionKey !== null && base64Bytes(p.encryptedSessionKey) !== wrappedSize) return 'Invalid session key';
        ids.add(p.id);
    }
    const tokens = new Set();
    for (const s of shares) {
        if (!s || typeof s.token !== 'string' || !isValidUUID(s.token) || tokens.has(s.token)) return 'Invalid share list';
        if (s.ownerKey !== null && base64Bytes(s.ownerKey) !== wrappedSize) return 'Invalid owner key';
        tokens.add(s.token);
    }
    return null;
}

// 1. Auth / Register
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, salt, publicKey, encryptedPrivateKey, iv, serverAuthHash } = req.body;

        if (!username || !salt || !publicKey || !encryptedPrivateKey || !iv || !serverAuthHash) {
            return res.status(400).json({ error: 'Missing required registration data' });
        }
        if ([username, salt, publicKey, encryptedPrivateKey, iv, serverAuthHash].some(v => typeof v !== 'string')) {
            return res.status(400).json({ error: 'Invalid registration data' });
        }
        const keyError = registrationFieldsError(req.body);
        if (keyError) {
            return res.status(400).json({ error: keyError });
        }

        // Validate username format
        if (!/^[a-zA-Z0-9_]{3,32}$/.test(username)) {
            return res.status(400).json({ error: 'Username: 3-32 characters, alphanumeric and underscores only' });
        }

        const existingUser = await db.getUserByUsername(username);
        if (existingUser) {
            return res.status(409).json({ error: 'User already exists' });
        }

        const id = await db.createUser(username, salt, publicKey, encryptedPrivateKey, iv, hashAuthToken(serverAuthHash), req.body.kdf || DEFAULT_KDF);
        res.json({ success: true, userId: id });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Server error during registration' });
    }
});

// 2. Auth / Login (Two-step process)
// Step 1: Get the salt
app.get('/api/auth/salt/:username', async (req, res) => {
    try {
        const user = await db.getUserByUsername(req.params.username);
        if (!user) {
            // Return a fake (but stable and well-formed) salt to prevent enumeration
            return res.json({ salt: fakeSaltFor(req.params.username), kdf: DEFAULT_KDF });
        }
        res.json({ salt: user.salt, kdf: user.kdf || DEFAULT_KDF });
    } catch (error) {
        console.error('Salt fetch error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Step 2: Login with Server Auth Hash
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, serverAuthHash, challengeId, challengeResponse } = req.body;
        if (typeof username !== 'string' || typeof serverAuthHash !== 'string' || !username || !serverAuthHash) {
            return res.status(400).json({ error: 'Missing credentials' });
        }

        const user = await db.getUserByUsername(username);
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        if (user.server_auth_hash === LEGACY_AUTH_MARKER) {
            if (!LEGACY_MIGRATION_OPEN) {
                // Same answer as a wrong password, so legacy accounts cannot be told apart
                console.warn(`[Auth] Legacy account ${user.id} tried to log in; migration is closed (LEGACY_MIGRATION=open allows it)`);
                return res.status(401).json({ error: 'Invalid credentials' });
            }
            // Legacy account: only accept the new hash from whoever can decrypt with the account's private key
            const pending = typeof challengeId === 'string' ? migrationChallenges.get(challengeId) : undefined;
            if (typeof challengeResponse !== 'string' || !pending || pending.userId !== user.id || pending.expiresAt < Date.now()) {
                return res.json({
                    migrationRequired: true,
                    ...createMigrationChallenge(user),
                    encryptedPrivateKey: user.encrypted_private_key,
                    iv: user.iv
                });
            }
            migrationChallenges.delete(challengeId);
            if (!safeEqual(pending.expectedResponse, challengeResponse)) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }
            console.log(`[Auth] Legacy account ${user.id} migrated after key-possession proof`);
            await db.updateServerAuthHash(user.id, hashAuthToken(serverAuthHash));
        } else if (!verifyAuthHash(user.server_auth_hash, serverAuthHash)) {
            return res.status(401).json({ error: 'Invalid credentials' });
        } else if (!user.server_auth_hash.startsWith(AUTH_HASH_PREFIX)) {
            await db.updateServerAuthHash(user.id, hashAuthToken(serverAuthHash));
        }

        // Update Last Login
        await db.updateLastLogin(user.id);

        // The session is created under the user's lock, from the vault as it is then: a key rotation or
        // password change (under the same lock) may have replaced it since it was read above, and ends
        // every other session when it does, so it cannot miss this one
        const releaseLock = await lockUserQuota(user.id);
        let current, sessionToken;
        try {
            current = await db.getUserById(user.id);
            if (current && verifyAuthHash(current.server_auth_hash, serverAuthHash)) sessionToken = createSession(user.id);
        } finally {
            releaseLock();
        }
        if (!sessionToken) return res.status(401).json({ error: 'Invalid credentials' });

        res.json({
            id: current.id,
            salt: current.salt,
            kdf: current.kdf || DEFAULT_KDF,
            encryptedPrivateKey: current.encrypted_private_key,
            iv: current.iv,
            sessionToken
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Server error during login' });
    }
});

// Change password: the browser re-encrypts the same private key under a key derived from the new
// password. The current password's auth hash is required too, so a stolen session token is not
// enough (and the auth rate limit applies to guesses). Wrong current password: 403, not 401, so the
// page does not take it for an expired session. Every other session of the account ends.
app.post('/api/auth/password', requireAuth, async (req, res) => {
    try {
        const body = req.body || {};
        if (typeof body.currentServerAuthHash !== 'string' || body.kdf !== DEFAULT_KDF) {
            return res.status(400).json({ error: 'Invalid request' });
        }
        const fieldError = vaultFieldsError(body);
        if (fieldError) return res.status(400).json({ error: fieldError });

        const user = await db.getUserById(req.session.userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        if (user.server_auth_hash === LEGACY_AUTH_MARKER || !verifyAuthHash(user.server_auth_hash, body.currentServerAuthHash)) {
            return res.status(403).json({ error: 'Invalid credentials' });
        }

        // Only if nothing changed the vault since it was read: of two concurrent changes, one wins. Under
        // the user's lock, so a login cannot create a session between the change and the purge
        const releaseLock = await lockUserQuota(user.id);
        let updated;
        try {
            updated = await db.updateVault(user.id, user.server_auth_hash, body.salt, body.kdf, body.encryptedPrivateKey, body.iv, hashAuthToken(body.serverAuthHash));
            if (updated) {
                for (const [token, session] of sessions) {
                    if (session.userId === user.id && token !== req.sessionToken) sessions.delete(token);
                }
            }
        } finally {
            releaseLock();
        }
        if (!updated) return res.status(409).json({ error: 'The password was changed meanwhile' });
        console.log(`[Auth] Password changed for account ${user.id}`);
        res.json({ success: true });
    } catch (error) {
        console.error('Change password error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Step 1 of a key rotation: a challenge only the current private key can answer (one per attempt)
app.post('/api/auth/rotate-keys/challenge', requireAuth, async (req, res) => {
    try {
        const user = await db.getUserById(req.session.userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        if (user.server_auth_hash === LEGACY_AUTH_MARKER) return res.status(403).json({ error: 'Invalid credentials' });
        res.json(createKeyChallenge(rotationChallenges, user, ROTATION_CHALLENGE_LABEL, ROTATION_RESPONSE_PREFIX));
    } catch (error) {
        console.error('Rotation challenge error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Rotate keys: the browser generates a new key pair, unwraps each pending package's session key and
// each format 2 share's owner name key with the current private key and wraps them again for the new
// public key (same OAEP label), and encrypts the new private key under the same password (new salt).
// File bodies, names and messages do not change. Checked like a password change (current password's
// auth hash, 403 if wrong), plus the answer to a rotation challenge, which proves the caller holds the
// current private key (403 code key-proof); the lists must name every pending package and format 2 share, or the
// rotation is refused with 409 and the page reads them again. Written in one transaction under the
// user's upload lock, so a drop lands either before (and must be in the lists) or after (and is
// checked against the new key). Every other session of the account ends.
app.post(ROTATE_KEYS_PATH, requireAuth, express.json({ limit: '32mb' }), async (req, res) => {
    try {
        const body = req.body || {};
        if (typeof body.currentServerAuthHash !== 'string' || body.kdf !== DEFAULT_KDF) {
            return res.status(400).json({ error: 'Invalid request' });
        }
        // Only the key sizes whose wrapped keys drops and shares accept (256, 384 or 512 bytes)
        const newKeyBits = rsaKeyBits(body.publicKey);
        const fieldError = registrationFieldsError(body) || (![2048, 3072, 4096].includes(newKeyBits) && 'Invalid public key')
            || rotationListsError(body.packages, body.shares, newKeyBits);
        if (fieldError) return res.status(400).json({ error: fieldError });

        const user = await db.getUserById(req.session.userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        if (user.server_auth_hash === LEGACY_AUTH_MARKER || !verifyAuthHash(user.server_auth_hash, body.currentServerAuthHash)) {
            return res.status(403).json({ error: 'Invalid credentials' });
        }
        // ...and the current private key: the answer to a challenge made for the key the account has now
        const challenge = typeof body.challengeId === 'string' ? rotationChallenges.get(body.challengeId) : undefined;
        if (!challenge || challenge.userId !== user.id || challenge.publicKey !== user.public_key || challenge.expiresAt < Date.now()
            || typeof body.challengeResponse !== 'string' || !safeEqual(challenge.expectedResponse, body.challengeResponse)) {
            return res.status(403).json({ error: 'Proof of holding the current key required', code: 'key-proof' });
        }
        if (body.publicKey === user.public_key) return res.status(400).json({ error: 'The new public key is the current one' });
        // A new salt, so the auth hash changes too: a password change that read the old vault then fails
        // its guard instead of pairing the old private key with the new public key
        if (body.salt === user.salt || verifyAuthHash(user.server_auth_hash, body.serverAuthHash)) {
            return res.status(400).json({ error: 'The new vault must use a new salt' });
        }

        const vault = {
            publicKey: body.publicKey, salt: body.salt, kdf: body.kdf, encryptedPrivateKey: body.encryptedPrivateKey,
            iv: body.iv, serverAuthHash: hashAuthToken(body.serverAuthHash)
        };
        const releaseQuota = await lockUserQuota(user.id);
        let result;
        try {
            result = await db.rotateKeys(user.id, user.server_auth_hash, vault, body.packages, body.shares);
            // Still under the lock: a share another session is uploading must find its session ended
            if (result === 'ok') {
                rotationChallenges.delete(body.challengeId);
                for (const [token, session] of sessions) {
                    if (session.userId === user.id && token !== req.sessionToken) sessions.delete(token);
                }
            }
        } finally {
            releaseQuota();
        }
        if (result === 'vault') return res.status(409).json({ error: 'The password was changed meanwhile' });
        if (result === 'lists') return res.status(409).json({ error: 'Packages or shares changed meanwhile', code: 'lists-changed' });
        console.log(`[Auth] Keys rotated for account ${user.id}`);
        // The old encrypted private key and wrapped keys must not linger in the SQLite WAL
        await db.compact().catch(e => console.error('Database compaction error:', e.message));
        res.json({ success: true });
    } catch (error) {
        console.error('Rotate keys error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Logout — destroy session
app.post('/api/auth/logout', requireAuth, (req, res) => {
    destroySession(req.sessionToken);
    res.json({ success: true });
});

// 3. Get User Public Key (For the sender to encrypt files)
// This can be via User UUID (if public link enabled) or One-Time Token
app.get('/api/user/:id/public-key', async (req, res) => {
    try {
        const target = await findDropRecipient(req.params.id);
        if (!target) {
            return res.status(404).json({ error: 'Valid repository or link not found' });
        }
        res.json({ publicKey: target.user.public_key });
    } catch (error) {
        console.error('Fetch public key error:', error);
        res.status(500).json({ error: 'Server error fetching public key' });
    }
});

// 3.1 Get User Quota info
app.get('/api/user/:uuid/quota', async (req, res) => {
    try {
        const target = await findDropRecipient(req.params.uuid);
        if (!target) return res.status(404).json({ error: 'User not found' });

        const user = target.user;
        const usage = await getStorageUsage(user.id);
        res.json({
            quota: user.mailbox_quota,
            usage: usage,
            remaining: Math.max(0, user.mailbox_quota - usage),
            publicLinkEnabled: user.public_link_enabled === 1
        });
    } catch (error) {
        console.error('Quota check error:', error);
        res.status(500).json({ error: 'Server error checking quota' });
    }
});

// 3.2 Link Management API (protected)
// Owner's view of quota and link state; unlike /quota it keeps working when the public link is off
app.get('/api/user/:uuid/config', requireAuth, async (req, res) => {
    try {
        if (req.session.userId !== req.params.uuid) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        const user = await db.getUserById(req.session.userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        const usage = await getStorageUsage(user.id);
        res.json({
            quota: Number(user.mailbox_quota),
            usage,
            remaining: Math.max(0, user.mailbox_quota - usage),
            publicLinkEnabled: Number(user.public_link_enabled) === 1
        });
    } catch (err) {
        console.error('Config read error:', err);
        res.status(500).json({ error: 'Failed to read config' });
    }
});

app.post('/api/user/:uuid/config', requireAuth, async (req, res) => {
    try {
        if (req.session.userId !== req.params.uuid) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        const enabled = req.body && req.body.publicLinkEnabled;
        if (typeof enabled !== 'boolean') {
            return res.status(400).json({ error: 'publicLinkEnabled must be true or false' });
        }
        await db.togglePublicLink(req.params.uuid, enabled);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Failed to update config' });
    }
});

app.post('/api/user/:uuid/one-time-link', requireAuth, async (req, res) => {
    try {
        if (req.session.userId !== req.params.uuid) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        const token = await db.generateOneTimeLink(req.params.uuid);
        res.json({ token });
    } catch (err) {
        console.error('Generate one-time link error:', err);
        res.status(500).json({ error: 'Failed to generate link' });
    }
});

app.get('/api/user/:uuid/one-time-links', requireAuth, async (req, res) => {
    try {
        if (req.session.userId !== req.params.uuid) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        const links = await db.getOneTimeLinks(req.params.uuid);
        res.json(links);
    } catch (err) {
        console.error('List one-time links error:', err);
        res.status(500).json({ error: 'Failed to list links' });
    }
});

app.delete('/api/user/:uuid/one-time-link/:token', requireAuth, async (req, res) => {
    try {
        if (req.session.userId !== req.params.uuid) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        await db.deleteOneTimeLink(req.params.token, req.params.uuid);
        res.json({ success: true });
    } catch (err) {
        console.error('Delete one-time link error:', err);
        res.status(500).json({ error: 'Failed to delete link' });
    }
});

// 4. Drop Files (From the external sender)
app.post('/api/drop/:id', resolveDropTarget, upload.array('files'), async (req, res) => {
    try {
        const { user, isToken } = req.dropTarget;
        const userId = user.id;
        const files = req.files || [];

        // Validate every field before anything is stored or the one-time link is used
        const fieldError = dropFieldsError(req.body, files);
        if (fieldError) {
            removeUploadedFiles(req);
            return res.status(400).json({ error: fieldError });
        }
        let { senderName, encryptedSessionKey, encryptedMessage, messageIv } = req.body;

        // Keep the name as typed (the UI renders it as text); just cap length and drop control characters
        if (senderName) {
            senderName = String(senderName).replace(/[\u0000-\u001f\u007f]/g, '').trim().substring(0, 64);
        }

        const releaseQuota = await lockUserQuota(userId);
        try {
            // Validate Quota again with the real sizes, message included
            const used = await getStorageUsage(userId);
            const incomingSize = files.reduce((acc, f) => acc + f.size, 0) + encryptedMessage.length;
            if (used + incomingSize > user.mailbox_quota) {
                removeUploadedFiles(req);
                return res.status(413).json({ error: 'Mailbox quota exceeded' });
            }

            // The send page names the key it encrypted to. If the recipient rotated their keys since it
            // fetched that key, the package would not open with the new one: refuse it. Checked under
            // the same lock as the rotation, so a drop is either in its list or sees the new key
            if (req.body.keyFingerprint !== undefined) {
                const current = await db.getUserById(userId);
                if (!current || publicKeyFingerprint(current.public_key) !== req.body.keyFingerprint) {
                    removeUploadedFiles(req);
                    return res.status(409).json({ error: 'The recipient changed their keys: ask them for their new link' });
                }
            }

            // Consume the one-time token atomically so two concurrent drops can't both use it
            if (isToken && !(await db.consumeToken(req.params.id))) {
                removeUploadedFiles(req);
                return res.status(410).json({ error: 'This link has already been used' });
            }

            // Create the package in db
            const format = req.body.format === '2' ? 2 : 1;
            const packageId = await db.createPackage(userId, senderName, encryptedSessionKey, encryptedMessage, messageIv, format);

            // Register files and rename them to standard format; on any failure undo the whole package
            const encryptedNames = parseEncryptedNames(req.body.fileNames);
            const storedPaths = [];
            try {
                for (let i = 0; i < files.length; i++) {
                    const file = files[i];
                    const encName = encryptedNames[i];
                    // Only encrypted names are stored; the multipart filename and type are client-chosen plaintext
                    const storedName = typeof encName === 'string' && encName.length <= 2048 && ENC_NAME_REGEX.test(encName)
                        ? encName
                        : UNNAMED_FILE;
                    const packageFileId = await db.addPackageFile(packageId, storedName, STORED_FILE_TYPE, file.size);
                    const newPath = path.join(DROP_DIR, `${packageId}_${packageFileId}`);
                    fs.renameSync(file.path, newPath);
                    storedPaths.push(newPath);
                }
            } catch (error) {
                storedPaths.forEach(removeFile);
                await db.deletePackage(packageId).catch(() => {});
                throw error;
            }

            res.json({ success: true, packageId });
        } finally {
            releaseQuota();
        }
    } catch (error) {
        console.error('Drop error:', error);
        removeUploadedFiles(req);
        res.status(500).json({ error: 'Server error processing drop' });
    }
});

// 5. Get Pending Packages (protected)
app.get('/api/packages/:uuid', requireAuth, async (req, res) => {
    try {
        if (req.session.userId !== req.params.uuid) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        const packages = await db.getPackagesByUserId(req.params.uuid);
        res.json(packages);
    } catch (error) {
        console.error('Fetch packages error:', error);
        res.status(500).json({ error: 'Server error fetching packages' });
    }
});

// 6. Download a specific file
app.get('/api/package/:packageId/file/:fileId', requireAuth, async (req, res) => {
    try {
        const { packageId, fileId } = req.params;
        // Validate UUID format to prevent path traversal
        if (!isValidUUID(packageId) || !isValidUUID(fileId)) {
            return res.status(400).json({ error: 'Invalid ID format' });
        }
        // Verify ownership (same 404 for "not yours" and "doesn't exist")
        const pkg = await db.getPackageById(packageId);
        if (!pkg || pkg.user_id !== req.session.userId || !pkg.files.some(f => f.id === fileId)) {
            return res.status(404).json({ error: 'File not found' });
        }
        const filePath = path.join(DROP_DIR, `${packageId}_${fileId}`);

        if (fs.existsSync(filePath)) {
            res.sendFile(filePath);
        } else {
            res.status(404).json({ error: 'File not found on disk' });
        }
    } catch (error) {
        console.error('Download error:', error);
        res.status(500).json({ error: 'Server error downloading file' });
    }
});

// 7. Delete Package
app.delete('/api/package/:packageId', requireAuth, async (req, res) => {
    try {
        const { packageId } = req.params;
        if (!isValidUUID(packageId)) {
            return res.status(400).json({ error: 'Invalid ID format' });
        }
        const pkg = await db.getPackageById(packageId);

        // Same 404 for "not yours" and "does not exist"; never touch the disk without an owned row
        if (!pkg || pkg.user_id !== req.session.userId) {
            return res.status(404).json({ error: 'Package not found' });
        }

        // File paths come from the stored row, never from the request
        pkg.files.forEach(f => {
            const filePath = path.join(DROP_DIR, `${pkg.id}_${f.id}`);
            removeFile(filePath);
        });

        await db.deletePackage(pkg.id);
        res.json({ success: true });
    } catch (error) {
        console.error('Delete error:', error);
        res.status(500).json({ error: 'Server error deleting package' });
    }
});

// --- Secure File Sharing ---
const SHARE_DIR = path.join(DATA_DIR, 'shares');
if (!fs.existsSync(SHARE_DIR)) {
    fs.mkdirSync(SHARE_DIR, { recursive: true });
}

const shareStorage = multer.diskStorage({
    destination(req, file, cb) { cb(null, SHARE_DIR); },
    filename(req, file, cb) {
        const uniqueName = crypto.randomUUID() + '.enc';
        cb(null, uniqueName);
    }
});
const shareUpload = multer({ storage: shareStorage, limits: { fileSize: 100 * 1024 * 1024, files: 1, fields: 20, fieldSize: MAX_FIELD_SIZE } }); // 100MB max

// 8. Create Share (Upload encrypted file)
// Runs before multer: ownership, declared size and quota, so nothing is written for a refused share
async function resolveShareTarget(req, res, next) {
    try {
        if (req.session.userId !== req.params.userId) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        const declaredSize = declaredUploadSize(req);
        if (declaredSize === null) {
            return res.status(411).json({ error: 'Content-Length required' });
        }
        const user = await db.getUserById(req.session.userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        const remaining = user.mailbox_quota - await getStorageUsage(user.id);
        if (remaining <= 0 || declaredSize > remaining + MULTIPART_OVERHEAD) {
            return res.status(413).json({ error: 'Storage quota exceeded' });
        }
        next();
    } catch (error) {
        console.error('Share target error:', error);
        res.status(500).json({ error: 'Server error creating share' });
    }
}

app.post('/api/share/:userId', requireAuth, resolveShareTarget, shareUpload.single('file'), async (req, res) => {
    try {
        const { userId } = req.params;
        if (req.session.userId !== userId) {
            removeUploadedFiles(req);
            return res.status(403).json({ error: 'Forbidden' });
        }
        if (!req.file) {
            return res.status(400).json({ error: 'Missing file' });
        }
        const fieldError = shareFieldsError(req.body);
        if (fieldError) {
            removeUploadedFiles(req);
            return res.status(400).json({ error: fieldError });
        }
        const { encryptedFileKey, keyIv, salt, fileIv, originalName, mimeType, encryptedMessage, messageIv, downloadProof, ownerKey } = req.body;
        const format = req.body.format === '2' ? 2 : 1;
        const maxDownloads = intField(req.body.maxDownloads, 0, 1000);
        const expiresIn = intField(req.body.expiresIn, 0, 8760);

        const token = crypto.randomUUID();

        // Validate Quota (shares count towards the same mailbox quota as drops)
        const user = await db.getUserById(userId);
        if (!user) {
            removeUploadedFiles(req);
            return res.status(404).json({ error: 'User not found' });
        }

        const releaseQuota = await lockUserQuota(userId);
        try {
            // A key rotation (which holds the same lock) ends the other sessions: a share they were
            // still uploading has its owner key wrapped for the old public key
            if (!validateSession(req.sessionToken)) {
                removeUploadedFiles(req);
                return res.status(401).json({ error: 'Invalid or expired session' });
            }
            const usedQuota = await getStorageUsage(userId);
            if (usedQuota + req.file.size > user.mailbox_quota) {
                removeUploadedFiles(req);
                return res.status(413).json({ error: 'Storage quota exceeded' });
            }

            const expiresAt = expiresIn > 0 ? new Date(Date.now() + expiresIn * 3600000).toISOString() : null;

            // Row first, then the file: a failed insert leaves only the temp file, which is removed below
            await db.createShare(
                userId, token, encryptedFileKey, keyIv, salt, fileIv,
                originalName, (format === 1 && mimeType) || 'application/octet-stream', req.file.size,
                encryptedMessage || null, messageIv || null,
                maxDownloads, expiresAt, downloadProof || null, format, ownerKey || null
            );
            try {
                fs.renameSync(req.file.path, path.join(SHARE_DIR, `${token}.enc`));
            } catch (error) {
                await db.deleteShare(token).catch(() => {});
                throw error;
            }
        } finally {
            releaseQuota();
        }

        res.json({ success: true, token });
    } catch (error) {
        console.error('Share create error:', error);
        removeUploadedFiles(req);
        res.status(500).json({ error: 'Server error creating share' });
    }
});

// 9. Get Share Metadata (public — no auth)
app.get('/api/share/:token/meta', async (req, res) => {
    try {
        if (!isValidUUID(req.params.token)) {
            return res.status(400).json({ error: 'Invalid token format' });
        }
        const share = await db.getShareByToken(req.params.token);
        if (!share) return res.status(404).json({ error: 'Share not found' });

        // Check expiry
        if (share.expires_at && new Date(share.expires_at) < new Date()) {
            return res.status(410).json({ error: 'This link has expired' });
        }

        // Check download limit
        if (share.max_downloads > 0 && share.download_count >= share.max_downloads) {
            return res.status(410).json({ error: 'Download limit reached' });
        }

        // Only what the page needs before and after the password: no creation date or download
        // history, and for format 2 no readable name or type at all
        const format = Number(share.format) === 2 ? 2 : 1;
        res.json({
            format,
            originalName: share.original_name,
            ...(format === 1 ? { mimeType: share.mime_type } : {}),
            size: share.size,
            salt: share.salt,
            keyIv: share.key_iv,
            encryptedFileKey: share.encrypted_file_key,
            fileIv: share.file_iv,
            encryptedMessage: share.encrypted_message,
            messageIv: share.message_iv,
            downloadsLeft: share.max_downloads > 0 ? share.max_downloads - share.download_count : null,
            expiresAt: share.expires_at
        });
    } catch (error) {
        console.error('Share meta error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// 10. Download Encrypted Share File
app.get('/api/share/:token/download', async (req, res) => {
    try {
        if (!isValidUUID(req.params.token)) {
            return res.status(400).json({ error: 'Invalid token format' });
        }
        const share = await db.getShareByToken(req.params.token);
        if (!share) return res.status(404).json({ error: 'Share not found' });

        // Check expiry
        if (share.expires_at && new Date(share.expires_at) < new Date()) {
            return res.status(410).json({ error: 'This link has expired' });
        }

        // Check download limit
        if (share.max_downloads > 0 && share.download_count >= share.max_downloads) {
            return res.status(410).json({ error: 'Download limit reached' });
        }

        const filePath = path.join(SHARE_DIR, `${share.token}.enc`);
        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ error: 'File not found on disk' });
        }

        // HEAD would count as a download without transferring anything
        if (req.method !== 'GET') {
            return res.status(405).set('Allow', 'GET').end();
        }

        // Shares created with a proof can only be downloaded by someone who unwrapped the key with the
        // password; a link holder (or a link-preview bot) gets 403 and uses up nothing
        if (share.download_proof && !safeEqual(share.download_proof, req.get('X-Download-Proof') || '')) {
            return res.status(403).json({ error: 'Download proof required' });
        }

        // Count the download atomically; fails if a concurrent request took the last one
        if (!(await db.incrementShareDownloads(share.token))) {
            return res.status(410).json({ error: 'Download limit reached' });
        }

        // A transfer that does not complete gives the download back
        res.sendFile(filePath, err => {
            if (err) {
                db.refundShareDownload(share.token).catch(e => console.error('Download refund failed:', e.message));
            }
        });
    } catch (error) {
        console.error('Share download error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// 11. List User's Shares (protected)
app.get('/api/shares/:userId', requireAuth, async (req, res) => {
    try {
        if (req.session.userId !== req.params.userId) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        const shares = await db.getSharesByUserId(req.params.userId);
        res.json(shares);
    } catch (error) {
        console.error('List shares error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// 12. Delete Share
app.delete('/api/share/:token', requireAuth, async (req, res) => {
    try {
        const { token } = req.params;
        if (!isValidUUID(token)) {
            return res.status(400).json({ error: 'Invalid token format' });
        }
        // Same 404 for "not yours" and "does not exist"; never touch the disk without an owned row
        const share = await db.getShareByToken(token);
        if (!share || share.user_id !== req.session.userId) {
            return res.status(404).json({ error: 'Share not found' });
        }
        // The file path comes from the stored token, never from the request
        const filePath = path.join(SHARE_DIR, `${share.token}.enc`);
        removeFile(filePath);
        await db.deleteShare(share.token);
        res.json({ success: true });
    } catch (error) {
        console.error('Delete share error:', error);
        res.status(500).json({ error: 'Server error deleting share' });
    }
});

// Expired or exhausted shares: remove file and row so they stop counting against the quota
async function purgeDeadShares() {
    try {
        const now = new Date();
        const shares = await db.getAllShareLimits();
        for (const s of shares) {
            const expired = s.expires_at && new Date(s.expires_at) < now;
            const exhausted = s.max_downloads > 0 && s.download_count >= s.max_downloads;
            if (!expired && !exhausted) continue;
            removeFile(path.join(SHARE_DIR, `${s.token}.enc`));
            await db.deleteShare(s.token);
        }
    } catch (error) {
        console.error('Share cleanup error:', error);
    }
}
// Files no DB row points to: temp files of aborted uploads, files left by a failed insert or a crash.
// Only names the server itself creates are touched, and only once they are older than the grace
// period, so uploads still in progress are never removed.
const ORPHAN_GRACE_MS = Number(process.env.ORPHAN_GRACE_MS) || 60 * 60 * 1000;
const UUID_PART = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
const DROP_FILE_NAME = new RegExp(`^(${UUID_PART}_${UUID_PART}|${UUID_PART}\\.upload)$`);
const SHARE_FILE_NAME = new RegExp(`^(${UUID_PART})\\.enc$`);

// SQLite returns CURRENT_TIMESTAMP as "YYYY-MM-DD HH:MM:SS" in UTC with no zone; MySQL gives a Date
function storedDate(value) {
    if (typeof value === 'string' && /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(value)) {
        return new Date(value.replace(' ', 'T') + 'Z').getTime();
    }
    return new Date(value).getTime();
}

async function sweepOrphanFiles() {
    try {
        const cutoff = Date.now() - ORPHAN_GRACE_MS;
        const isOld = file => { try { return fs.statSync(file).mtimeMs < cutoff; } catch { return false; } };
        const remove = removeFile;

        const liveDropFiles = new Set(await db.getAllPackageFileKeys());
        for (const name of fs.readdirSync(DROP_DIR)) {
            const file = path.join(DROP_DIR, name);
            if (DROP_FILE_NAME.test(name) && !liveDropFiles.has(name) && isOld(file)) remove(file);
        }

        // The other way round: rows whose file is gone (restore mistake, manual delete) would count
        // against the quota forever and only fail on download. Old enough rows only, so a file
        // still being moved into place is never affected.
        for (const row of await db.getAllPackageFiles()) {
            const file = path.join(DROP_DIR, `${row.package_id}_${row.id}`);
            if (storedDate(row.created_at) < cutoff && !fs.existsSync(file)) {
                console.error('Removing file row with no file on disk:', row.id);
                await db.deletePackageFile(row.id);
            }
        }

        const liveShares = new Set((await db.getAllShareLimits()).map(s => s.token));
        for (const name of fs.readdirSync(SHARE_DIR)) {
            const match = SHARE_FILE_NAME.exec(name);
            const file = path.join(SHARE_DIR, name);
            if (match && !liveShares.has(match[1]) && isOld(file)) remove(file);
        }
    } catch (error) {
        console.error('Orphan sweep error:', error);
    }
}

// Pending packages expire so a drop link cannot be used to fill a mailbox for good.
// PACKAGE_RETENTION_DAYS=0 keeps them until the owner destroys them.
const PACKAGE_RETENTION_DAYS = process.env.PACKAGE_RETENTION_DAYS === undefined ? 30 : Number(process.env.PACKAGE_RETENTION_DAYS);

async function purgeExpiredPackages() {
    if (!(PACKAGE_RETENTION_DAYS > 0)) return;
    try {
        const cutoff = Date.now() - PACKAGE_RETENTION_DAYS * 24 * 3600 * 1000;
        for (const pkg of await db.getAllPackageDates()) {
            if (storedDate(pkg.created_at) >= cutoff) continue;
            const full = await db.getPackageById(pkg.id);
            for (const f of (full && full.files) || []) {
                removeFile(path.join(DROP_DIR, `${pkg.id}_${f.id}`));
            }
            await db.deletePackage(pkg.id);
        }
    } catch (error) {
        console.error('Package expiry error:', error);
    }
}

async function housekeeping() {
    await db.deleteUsedOneTimeLinks().catch(e => console.error('One-time link cleanup error:', e.message));
    await purgeDeadShares();
    await purgeExpiredPackages();
    await sweepOrphanFiles();
    await db.compact().catch(e => console.error('Database compaction error:', e.message));
}
setTimeout(housekeeping, Number(process.env.HOUSEKEEPING_DELAY_MS) || 10 * 1000);
setInterval(housekeeping, 60 * 60 * 1000);

// Upload limit errors (too many files, too large...) as JSON instead of an HTML error page
app.use((req, res) => {
    res.status(404).json({ error: 'Not found' });
});

app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError) {
        const status = err.code === 'LIMIT_FILE_SIZE' || err.code === 'LIMIT_FILE_COUNT' ? 413 : 400;
        return res.status(status).json({ error: `Upload rejected: ${err.message}` });
    }
    // body-parser and multipart errors (malformed JSON, too large, broken multipart): the client's fault.
    // Log the message only, never err.body, which holds what the client sent (auth hashes included).
    const status = err.status || err.statusCode;
    if (status >= 400 && status < 500) {
        console.warn(`Rejected request body (${status}): ${err.type || err.message}`);
        return res.status(status).json({ error: 'Invalid request body' });
    }
    console.error('Unhandled error:', err.message);
    res.status(500).json({ error: 'Server error' });
});

// --- Server Setup ---

// Find SSL certificates — supports multiple locations and naming conventions
function findSSLCerts() {
    const locations = [
        // Docker volume mount (Let's Encrypt naming)
        { cert: path.join(__dirname, 'certs', 'fullchain.pem'), key: path.join(__dirname, 'certs', 'privkey.pem') },
        // Same directory (Let's Encrypt naming)
        { cert: path.join(__dirname, 'fullchain.pem'), key: path.join(__dirname, 'privkey.pem') },
        // Same directory (generic naming)
        { cert: path.join(__dirname, 'cert.pem'), key: path.join(__dirname, 'key.pem') },
    ];

    for (const loc of locations) {
        if (fs.existsSync(loc.cert) && fs.existsSync(loc.key)) {
            // Verify files are not empty
            const certStat = fs.statSync(loc.cert);
            const keyStat = fs.statSync(loc.key);
            if (certStat.size > 0 && keyStat.size > 0) {
                return loc;
            }
        }
    }
    return null;
}

// Time budget for a whole request. Node's default (5 min) cut off legitimate large uploads on slow
// links; a drop can be up to 20 x 50 MB, so the default here allows 30 min. Headers must still
// arrive quickly, and stalled connections are checked often enough for the limit to apply.
const REQUEST_TIMEOUT_MS = Number(process.env.REQUEST_TIMEOUT_MS) || 30 * 60 * 1000;
const serverOptions = {
    requestTimeout: REQUEST_TIMEOUT_MS,
    headersTimeout: Math.min(60 * 1000, REQUEST_TIMEOUT_MS),
    connectionsCheckingInterval: Math.min(30 * 1000, Math.max(250, Math.floor(REQUEST_TIMEOUT_MS / 4)))
};

// Start listening only once the database is ready (MySQL creates and migrates tables asynchronously);
// if it cannot be reached, stop instead of answering every request with 500
let httpServer = null;

// Graceful shutdown (docker stop sends SIGTERM): stop accepting connections, let requests in flight
// finish for up to 10 s, then exit
function shutdown(signal) {
    console.log(`${signal} received, shutting down`);
    if (!httpServer) process.exit(0);
    httpServer.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 10 * 1000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

db.ready.then(() => {
    if (sslCerts) {
        try {
            const options = {
                ...serverOptions,
                key: fs.readFileSync(sslCerts.key),
                cert: fs.readFileSync(sslCerts.cert)
            };
            httpServer = https.createServer(options, app).listen(PORT, () => {
                console.log(`Buzon HTTPS server running at https://localhost:${PORT}`);
                console.log(`  SSL cert: ${path.basename(sslCerts.cert)}, key: ${path.basename(sslCerts.key)}`);
            });
        } catch (err) {
            // Fail closed: falling back to plain HTTP here would serve cleartext on the port the operator
            // believes is HTTPS (e.g. a root-only privkey.pem mounted into the container)
            console.error(`TLS certificates found (${sslCerts.cert}, ${sslCerts.key}) but unusable: ${err.message}`);
            console.error('Fix their permissions or contents, or set TLS=off to serve plain HTTP behind a TLS-terminating proxy.');
            process.exit(1);
        }
    } else {
        // TLS=off: plain HTTP behind a TLS-terminating proxy, or for development
        httpServer = http.createServer(serverOptions, app).listen(PORT, () => {
            console.log(`Buzon HTTP server running at http://localhost:${PORT}`);
        });
    }
}).catch(error => {
    console.error(`Database not ready: ${error.message}`);
    process.exit(1);
});
