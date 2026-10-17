const express = require('express');
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
const MIGRATION_CHALLENGE_LABEL = Buffer.from('shadowdrop/migration-challenge/v1');
const MIGRATION_RESPONSE_PREFIX = Buffer.from('shadowdrop/migration-response/v1');
const migrationChallenges = new Map(); // userId -> { expectedResponse, expiresAt }
const CHALLENGE_TTL = 5 * 60 * 1000;

function createMigrationChallenge(user) {
    const nonce = crypto.randomBytes(32);
    const publicKey = crypto.createPublicKey({ key: Buffer.from(user.public_key, 'base64'), format: 'der', type: 'spki' });
    const encrypted = crypto.publicEncrypt(
        { key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256', oaepLabel: MIGRATION_CHALLENGE_LABEL },
        nonce
    );
    const expectedResponse = crypto.createHash('sha256').update(MIGRATION_RESPONSE_PREFIX).update(nonce).digest('base64');
    migrationChallenges.set(user.id, { expectedResponse, expiresAt: Date.now() + CHALLENGE_TTL });
    return encrypted.toString('base64');
}

// Cleanup expired sessions and challenges every hour
setInterval(() => {
    const now = Date.now();
    for (const [token, session] of sessions) {
        if (now - session.createdAt > SESSION_TTL) sessions.delete(token);
    }
    for (const [userId, challenge] of migrationChallenges) {
        if (challenge.expiresAt < now) migrationChallenges.delete(userId);
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
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function isValidUUID(str) {
    return UUID_REGEX.test(str);
}

// --- File Integrity System ---
// Compute SHA-256 hashes of all critical public files at startup
const INTEGRITY_FILES = ['app.js', 'crypto.js', 'drop.js', 'integrity.js', 'share.js', 'index.html', 'about.html', 'drop.html', 'share.html', 'style.css'];
const fileHashes = {};

function computeFileHashes() {
    const publicDir = path.join(__dirname, 'public');
    for (const file of INTEGRITY_FILES) {
        const filePath = path.join(publicDir, file);
        if (fs.existsSync(filePath)) {
            const content = fs.readFileSync(filePath);
            const hash = crypto.createHash('sha256').update(content).digest('hex');
            fileHashes[file] = hash;
        }
    }
    console.log(`[Integrity] Computed SHA-256 hashes for ${Object.keys(fileHashes).length} files`);
}

computeFileHashes();

const app = express();
const PORT = process.env.PORT || 4000;
// TLS=off forces plain HTTP (TLS terminated by a reverse proxy, or tests)
const sslCerts = process.env.TLS === 'off' ? null : findSSLCerts();

// Only trust X-Forwarded-For when a reverse proxy sits in front. Serving HTTPS directly,
// clients could forge the header and dodge the rate limiters. TRUST_PROXY overrides the default.
function parseTrustProxy(value) {
    if (value === undefined || value === '') return sslCerts ? false : 1;
    if (value === 'true') return true;
    if (value === 'false') return false;
    if (/^\d+$/.test(value)) return Number(value);
    return value;
}
app.set('trust proxy', parseTrustProxy(process.env.TRUST_PROXY));

app.use(express.json({ limit: '5mb' }));

// Rate limiting
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: Number(process.env.AUTH_RATE_LIMIT) || 20, message: { error: 'Too many attempts, try again later' } });
const dropLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 50, message: { error: 'Too many uploads, try again later' } });
const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200, message: { error: 'Too many requests, try again later' } });
app.use('/api/auth/', authLimiter);
app.use('/api/drop/', dropLimiter);
app.use('/api/', apiLimiter);

// --- Security Headers (CSP + hardening) ---
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
const upload = multer({
    storage: dropStorage,
    limits: { fileSize: 50 * 1024 * 1024, files: MAX_DROP_FILES, fields: 10 } // 50MB max per file
});

function removeUploadedFiles(req) {
    const files = req.files || (req.file ? [req.file] : []);
    files.forEach(f => { try { fs.unlinkSync(f.path); } catch { } });
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
async function resolveDropTarget(req, res, next) {
    try {
        if (!isValidUUID(req.params.id)) {
            return res.status(400).json({ error: 'Invalid link format' });
        }
        const target = await findDropRecipient(req.params.id);
        if (!target) {
            return res.status(404).json({ error: 'Recipient or valid link not found' });
        }
        const remaining = target.user.mailbox_quota - await getStorageUsage(target.user.id);
        const declaredSize = parseInt(req.headers['content-length'], 10) || 0;
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
const ENC_NAME_REGEX = /^enc:[A-Za-z0-9+/]+=*:[A-Za-z0-9+/]+=*$/;
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
    res.json({ files: fileHashes });
});

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

        // Validate username format
        if (!/^[a-zA-Z0-9_]{3,32}$/.test(username)) {
            return res.status(400).json({ error: 'Username: 3-32 characters, alphanumeric and underscores only' });
        }

        const existingUser = await db.getUserByUsername(username);
        if (existingUser) {
            return res.status(409).json({ error: 'User already exists' });
        }

        const id = await db.createUser(username, salt, publicKey, encryptedPrivateKey, iv, hashAuthToken(serverAuthHash));
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
            return res.json({ salt: fakeSaltFor(req.params.username) });
        }
        res.json({ salt: user.salt });
    } catch (error) {
        console.error('Salt fetch error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Step 2: Login with Server Auth Hash
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, serverAuthHash, challengeResponse } = req.body;
        if (typeof username !== 'string' || typeof serverAuthHash !== 'string' || !username || !serverAuthHash) {
            return res.status(400).json({ error: 'Missing credentials' });
        }

        const user = await db.getUserByUsername(username);
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        if (user.server_auth_hash === LEGACY_AUTH_MARKER) {
            // Legacy account: only accept the new hash from whoever can decrypt with the account's private key
            const pending = migrationChallenges.get(user.id);
            if (typeof challengeResponse !== 'string' || !pending || pending.expiresAt < Date.now()) {
                return res.json({
                    migrationRequired: true,
                    challenge: createMigrationChallenge(user),
                    encryptedPrivateKey: user.encrypted_private_key,
                    iv: user.iv
                });
            }
            migrationChallenges.delete(user.id);
            if (!safeEqual(pending.expectedResponse, challengeResponse)) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }
            console.log(`[Auth] Legacy account migrated after key-possession proof: ${username}`);
            await db.updateServerAuthHash(user.id, hashAuthToken(serverAuthHash));
        } else if (!verifyAuthHash(user.server_auth_hash, serverAuthHash)) {
            return res.status(401).json({ error: 'Invalid credentials' });
        } else if (!user.server_auth_hash.startsWith(AUTH_HASH_PREFIX)) {
            await db.updateServerAuthHash(user.id, hashAuthToken(serverAuthHash));
        }

        // Update Last Login
        await db.updateLastLogin(user.id);

        // Create session token
        const sessionToken = createSession(user.id);

        res.json({
            id: user.id,
            salt: user.salt,
            encryptedPrivateKey: user.encrypted_private_key,
            iv: user.iv,
            sessionToken
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Server error during login' });
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
app.post('/api/user/:uuid/config', requireAuth, async (req, res) => {
    try {
        if (req.session.userId !== req.params.uuid) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        const { public_link_enabled } = req.body;
        await db.togglePublicLink(req.params.uuid, public_link_enabled);
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
        let { senderName, encryptedSessionKey, encryptedMessage, messageIv } = req.body;
        const files = req.files || [];

        // Keep the name as typed (the UI renders it as text); just cap length and drop control characters
        if (senderName) {
            senderName = String(senderName).replace(/[\u0000-\u001f\u007f]/g, '').trim().substring(0, 64);
        }

        // Validate Quota again with the real sizes (Content-Length may be absent)
        const used = await getStorageUsage(userId);
        const incomingSize = files.reduce((acc, f) => acc + f.size, 0);
        if (used + incomingSize > user.mailbox_quota) {
            removeUploadedFiles(req);
            return res.status(413).json({ error: 'Mailbox quota exceeded' });
        }

        // Consume the one-time token atomically so two concurrent drops can't both use it
        if (isToken && !(await db.consumeToken(req.params.id))) {
            removeUploadedFiles(req);
            return res.status(410).json({ error: 'This link has already been used' });
        }

        // Create the package in db
        const packageId = await db.createPackage(userId, senderName, encryptedSessionKey, encryptedMessage, messageIv);

        // Register files and rename them to standard format
        const encryptedNames = parseEncryptedNames(req.body.fileNames);
        for (let i = 0; i < files.length; i++) {
            const file = files[i];
            const encName = encryptedNames[i];
            const storedName = typeof encName === 'string' && encName.length <= 2048 && ENC_NAME_REGEX.test(encName)
                ? encName
                : file.originalname;
            const packageFileId = await db.addPackageFile(packageId, storedName, file.mimetype, file.size);
            const newPath = path.join(DROP_DIR, `${packageId}_${packageFileId}`);
            fs.renameSync(file.path, newPath);
        }

        res.json({ success: true, packageId });
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

        // Verify ownership
        if (pkg && pkg.user_id !== req.session.userId) {
            return res.status(403).json({ error: 'Forbidden' });
        }

        if (pkg && pkg.files) {
            pkg.files.forEach(f => {
                const filePath = path.join(DROP_DIR, `${packageId}_${f.id}`);
                try { if (fs.existsSync(filePath)) fs.unlinkSync(filePath); } catch { }
            });
        }

        await db.deletePackage(packageId);
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
const shareUpload = multer({ storage: shareStorage, limits: { fileSize: 100 * 1024 * 1024, files: 1, fields: 20 } }); // 100MB max

// 8. Create Share (Upload encrypted file)
app.post('/api/share/:userId', requireAuth, shareUpload.single('file'), async (req, res) => {
    try {
        const { userId } = req.params;
        if (req.session.userId !== userId) {
            removeUploadedFiles(req);
            return res.status(403).json({ error: 'Forbidden' });
        }
        const { encryptedFileKey, keyIv, salt, fileIv, originalName, mimeType, encryptedMessage, messageIv, maxDownloads, expiresIn } = req.body;

        if (!req.file || !encryptedFileKey || !keyIv || !salt || !fileIv || !originalName) {
            removeUploadedFiles(req);
            return res.status(400).json({ error: 'Missing required fields' });
        }

        const token = crypto.randomUUID();

        // Validate Quota (shares count towards the same mailbox quota as drops)
        const user = await db.getUserById(userId);
        if (!user) {
            removeUploadedFiles(req);
            return res.status(404).json({ error: 'User not found' });
        }

        const usedQuota = await getStorageUsage(userId);
        if (usedQuota + req.file.size > user.mailbox_quota) {
            removeUploadedFiles(req);
            return res.status(413).json({ error: 'Storage quota exceeded' });
        }

        // Calculate expiry date
        let expiresAt = null;
        if (expiresIn && expiresIn !== '0') {
            const hours = parseInt(expiresIn);
            if (hours > 0) {
                expiresAt = new Date(Date.now() + hours * 3600000).toISOString();
            }
        }

        // Rename file to token-based name
        const finalPath = path.join(SHARE_DIR, `${token}.enc`);
        fs.renameSync(req.file.path, finalPath);

        await db.createShare(
            userId, token, encryptedFileKey, keyIv, salt, fileIv,
            originalName, mimeType || 'application/octet-stream', req.file.size,
            encryptedMessage || null, messageIv || null,
            parseInt(maxDownloads) || 0, expiresAt
        );

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

        res.json({
            originalName: share.original_name,
            mimeType: share.mime_type,
            size: share.size,
            salt: share.salt,
            keyIv: share.key_iv,
            encryptedFileKey: share.encrypted_file_key,
            fileIv: share.file_iv,
            encryptedMessage: share.encrypted_message,
            messageIv: share.message_iv,
            maxDownloads: share.max_downloads,
            downloadCount: share.download_count,
            expiresAt: share.expires_at,
            createdAt: share.created_at
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

        const filePath = path.join(SHARE_DIR, `${req.params.token}.enc`);
        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ error: 'File not found on disk' });
        }

        // Count the download atomically; fails if a concurrent request took the last one
        if (!(await db.incrementShareDownloads(req.params.token))) {
            return res.status(410).json({ error: 'Download limit reached' });
        }

        res.sendFile(filePath);
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
        // Verify ownership
        const share = await db.getShareByToken(token);
        if (share && share.user_id !== req.session.userId) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        const filePath = path.join(SHARE_DIR, `${token}.enc`);
        try { if (fs.existsSync(filePath)) fs.unlinkSync(filePath); } catch { }
        await db.deleteShare(token);
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
            try { fs.unlinkSync(path.join(SHARE_DIR, `${s.token}.enc`)); } catch { }
            await db.deleteShare(s.token);
        }
    } catch (error) {
        console.error('Share cleanup error:', error);
    }
}
setTimeout(purgeDeadShares, 10 * 1000);
setInterval(purgeDeadShares, 60 * 60 * 1000);

// Upload limit errors (too many files, too large...) as JSON instead of an HTML error page
app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError) {
        const status = err.code === 'LIMIT_FILE_SIZE' || err.code === 'LIMIT_FILE_COUNT' ? 413 : 400;
        return res.status(status).json({ error: `Upload rejected: ${err.message}` });
    }
    console.error('Unhandled error:', err);
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

if (sslCerts) {
    try {
        const options = {
            key: fs.readFileSync(sslCerts.key),
            cert: fs.readFileSync(sslCerts.cert)
        };
        https.createServer(options, app).listen(PORT, () => {
            console.log(`Buzon HTTPS server running at https://localhost:${PORT}`);
            console.log(`  SSL cert: ${path.basename(sslCerts.cert)}, key: ${path.basename(sslCerts.key)}`);
        });
    } catch (err) {
        console.error('SSL certificate error:', err.message);
        console.log('Falling back to HTTP...');
        app.listen(PORT, () => {
            console.log(`Buzon HTTP server running at http://localhost:${PORT}`);
        });
    }
} else {
    // Fallback to HTTP for dev or if running behind a proxy
    app.listen(PORT, () => {
        console.log(`Buzon HTTP server running at http://localhost:${PORT}`);
    });
}
