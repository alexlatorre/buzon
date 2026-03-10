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

// Cleanup expired sessions every hour
setInterval(() => {
    const now = Date.now();
    for (const [token, session] of sessions) {
        if (now - session.createdAt > SESSION_TTL) sessions.delete(token);
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

app.use(express.json({ limit: '5mb' }));

// Rate limiting
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, message: { error: 'Too many attempts, try again later' } });
const dropLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 50, message: { error: 'Too many uploads, try again later' } });
const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200, message: { error: 'Too many requests, try again later' } });
app.use('/api/auth/', authLimiter);
app.use('/api/drop/', dropLimiter);
app.use('/api/', apiLimiter);

// Trust the first reverse proxy to allow rate limiters to see real IPs
// Required because Dockerized apps are usually accessed via an ingress proxy like Nginx/Traefik
app.set('trust proxy', 1);

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

const DROP_DIR = path.join(__dirname, 'data', 'drop');
if (!fs.existsSync(DROP_DIR)) {
    fs.mkdirSync(DROP_DIR, { recursive: true });
}

// Set up file storage for dropped files
const dropStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, DROP_DIR);
    },
    filename: (req, file, cb) => {
        cb(null, `${uuidv4()}_${file.originalname}`);
    }
});
const upload = multer({ storage: dropStorage, limits: { fileSize: 50 * 1024 * 1024 } }); // 50MB max per file

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

        // Validate username format
        if (!/^[a-zA-Z0-9_]{3,32}$/.test(username)) {
            return res.status(400).json({ error: 'Username: 3-32 characters, alphanumeric and underscores only' });
        }

        const existingUser = await db.getUserByUsername(username);
        if (existingUser) {
            return res.status(409).json({ error: 'User already exists' });
        }

        const id = await db.createUser(username, salt, publicKey, encryptedPrivateKey, iv, serverAuthHash);
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
            // Return a fake salt to prevent timing/enumeration attacks
            return res.json({ salt: 'FAKE_SALT_PREVENTS_ENUMERATION_xyz123==' });
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
        const { username, serverAuthHash } = req.body;
        if (!username || !serverAuthHash) return res.status(400).json({ error: 'Missing credentials' });

        const user = await db.getUserByUsername(username);
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Verify Server Auth Hash or perform legacy TOFU migration
        if (user.server_auth_hash === 'LEGACY_MIGRATION_REQUIRED') {
            console.log(`[Auth] Performing Trust-On-First-Use migration for legacy user: ${username}`);
            await db.updateServerAuthHash(user.id, serverAuthHash);
        } else if (user.server_auth_hash !== serverAuthHash) {
            return res.status(401).json({ error: 'Invalid credentials' });
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
        const idOrToken = req.params.id;
        let user = await db.getUserById(idOrToken);

        // If not a user ID, check if it's a valid token
        if (!user || user.public_link_enabled === 0) {
            user = await db.getUserByToken(idOrToken);
        }

        if (!user) {
            return res.status(404).json({ error: 'Valid repository or link not found' });
        }
        res.json({ publicKey: user.public_key });
    } catch (error) {
        console.error('Fetch public key error:', error);
        res.status(500).json({ error: 'Server error fetching public key' });
    }
});

// 3.1 Get User Quota info
app.get('/api/user/:uuid/quota', async (req, res) => {
    try {
        const idOrToken = req.params.uuid;
        let user = await db.getUserById(idOrToken);

        if (!user || user.public_link_enabled === 0) {
            user = await db.getUserByToken(idOrToken);
        }

        if (!user) return res.status(404).json({ error: 'User not found' });

        const usage = await db.getUserMailboxUsage(user.id);
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
app.post('/api/drop/:id', upload.array('files'), async (req, res) => {
    try {
        const idOrToken = req.params.id;
        if (!isValidUUID(idOrToken)) {
            if (req.files) req.files.forEach(f => { try { fs.unlinkSync(f.path); } catch { } });
            return res.status(400).json({ error: 'Invalid link format' });
        }

        let user = await db.getUserById(idOrToken);
        let isToken = false;

        // If not a user ID (or link disabled), check if it's a valid token
        if (!user || user.public_link_enabled === 0) {
            user = await db.getUserByToken(idOrToken);
            isToken = true;
        }

        if (!user) {
            if (req.files) req.files.forEach(f => { try { fs.unlinkSync(f.path); } catch { } });
            return res.status(404).json({ error: 'Recipient or valid link not found' });
        }

        const userId = user.id;
        let { senderName, encryptedSessionKey, encryptedMessage, messageIv } = req.body;
        const files = req.files || [];

        // Sanitize senderName
        if (senderName) {
            senderName = String(senderName).substring(0, 64).replace(/<[^>]*>/g, '');
        }

        // Validate Quota
        const used = await db.getUserMailboxUsage(userId);
        const incomingSize = files.reduce((acc, f) => acc + f.size, 0);
        if (used + incomingSize > user.mailbox_quota) {
            if (req.files) req.files.forEach(f => { try { fs.unlinkSync(f.path); } catch { } });
            return res.status(413).json({ error: 'Mailbox quota exceeded' });
        }

        // Create the package in db
        const packageId = await db.createPackage(userId, senderName, encryptedSessionKey, encryptedMessage, messageIv);

        // Register files and rename them to standard format
        for (const file of files) {
            const packageFileId = await db.addPackageFile(packageId, file.originalname, file.mimetype, file.size);
            const newPath = path.join(DROP_DIR, `${packageId}_${packageFileId}`);
            fs.renameSync(file.path, newPath);
        }

        // Consume token if it was one
        if (isToken) await db.consumeToken(idOrToken);

        res.json({ success: true, packageId });
    } catch (error) {
        console.error('Drop error:', error);
        if (req.files) {
            req.files.forEach(f => { try { fs.unlinkSync(f.path); } catch { } });
        }
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
const SHARE_DIR = path.join(__dirname, 'data', 'shares');
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
const shareUpload = multer({ storage: shareStorage, limits: { fileSize: 100 * 1024 * 1024 } }); // 100MB max

// 8. Create Share (Upload encrypted file)
app.post('/api/share/:userId', requireAuth, shareUpload.single('file'), async (req, res) => {
    try {
        const { userId } = req.params;
        if (req.session.userId !== userId) {
            if (req.file) try { fs.unlinkSync(req.file.path); } catch { }
            return res.status(403).json({ error: 'Forbidden' });
        }
        const { encryptedFileKey, keyIv, salt, fileIv, originalName, mimeType, encryptedMessage, messageIv, maxDownloads, expiresIn } = req.body;

        if (!req.file || !encryptedFileKey || !keyIv || !salt || !fileIv || !originalName) {
            if (req.file) fs.unlinkSync(req.file.path);
            return res.status(400).json({ error: 'Missing required fields' });
        }

        const token = crypto.randomUUID();

        // Validate Quota (shares count towards the same mailbox quota as drops)
        const user = await db.getUserById(userId);
        if (!user) {
            if (req.file) try { fs.unlinkSync(req.file.path); } catch { }
            return res.status(404).json({ error: 'User not found' });
        }

        let usedQuota = await db.getUserMailboxUsage(userId);
        // Also add the active shares to the quota check
        const shares = await db.getSharesByUserId(userId);
        const sharesSize = shares.reduce((acc, s) => acc + s.size, 0);
        usedQuota += sharesSize;

        if (usedQuota + req.file.size > user.mailbox_quota) {
            if (req.file) try { fs.unlinkSync(req.file.path); } catch { }
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
        if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
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

        // Increment download count
        await db.incrementShareDownloads(req.params.token);

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

const sslCerts = findSSLCerts();

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
