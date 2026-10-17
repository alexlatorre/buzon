const Database = require('better-sqlite3');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const fs = require('fs');

const dataDir = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
fs.mkdirSync(dataDir, { recursive: true });
const dbPath = path.join(dataDir, 'buzon.db');
const db = new Database(dbPath);

db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE,
    salt TEXT,
    public_key TEXT,
    encrypted_private_key TEXT,
    iv TEXT,
    server_auth_hash TEXT,
    public_link_enabled INTEGER DEFAULT 1,
    mailbox_quota INTEGER DEFAULT 524288000,
    last_login DATETIME
  );

  CREATE TABLE IF NOT EXISTS packages (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    sender_name TEXT,
    encrypted_session_key TEXT,
    encrypted_message TEXT,
    message_iv TEXT,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS package_files (
    id TEXT PRIMARY KEY,
    package_id TEXT NOT NULL,
    original_name TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    size INTEGER NOT NULL,
    FOREIGN KEY(package_id) REFERENCES packages(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS one_time_links (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    is_used INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS shares (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    encrypted_file_key TEXT NOT NULL,
    key_iv TEXT NOT NULL,
    salt TEXT NOT NULL,
    file_iv TEXT NOT NULL,
    original_name TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    size INTEGER NOT NULL,
    encrypted_message TEXT,
    message_iv TEXT,
    max_downloads INTEGER DEFAULT 0,
    download_count INTEGER DEFAULT 0,
    expires_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
`);

// Dynamic migrations
const migrate = (cmd) => { try { db.exec(cmd); } catch (e) { } };

// Mailbox Quota & Link Management Migrations
const userCols = db.prepare("PRAGMA table_info(users)").all();
if (!userCols.find(c => c.name === 'public_link_enabled')) {
    db.exec("ALTER TABLE users ADD COLUMN public_link_enabled INTEGER DEFAULT 1");
}
if (!userCols.find(c => c.name === 'mailbox_quota')) {
    db.exec("ALTER TABLE users ADD COLUMN mailbox_quota INTEGER DEFAULT 524288000");
}
if (!userCols.find(c => c.name === 'last_login')) {
    db.exec("ALTER TABLE users ADD COLUMN last_login DATETIME");
}
const shareCols = db.prepare("PRAGMA table_info(shares)").all();
if (!shareCols.find(c => c.name === 'download_proof')) {
    db.exec("ALTER TABLE shares ADD COLUMN download_proof TEXT");
}
if (!userCols.find(c => c.name === 'server_auth_hash')) {
    // For existing users, we cannot magically compute the hash because we don't know their masterKey.
    // They will be locked out unless they re-register or we reset their accounts.
    db.exec("ALTER TABLE users ADD COLUMN server_auth_hash TEXT DEFAULT 'LEGACY_MIGRATION_REQUIRED'");
}

module.exports = {
    createUser: async (username, salt, publicKey, encryptedPrivateKey, iv, serverAuthHash) => {
        const id = uuidv4();
        db.prepare(`
            INSERT INTO users (id, username, salt, public_key, encrypted_private_key, iv, server_auth_hash, last_login)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `).run(id, username, salt, publicKey, encryptedPrivateKey, iv, serverAuthHash, new Date().toISOString());
        return id;
    },

    getUserByUsername: async (username) => {
        return db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    },

    getUserById: async (id) => {
        return db.prepare('SELECT * FROM users WHERE id = ?').get(id);
    },

    updateLastLogin: async (userId) => {
        db.prepare('UPDATE users SET last_login = ? WHERE id = ?').run(new Date().toISOString(), userId);
    },

    updateServerAuthHash: async (userId, hash) => {
        db.prepare('UPDATE users SET server_auth_hash = ? WHERE id = ?').run(hash, userId);
    },

    createPackage: async (userId, senderName, encryptedSessionKey, encryptedMessage, messageIv) => {
        const id = uuidv4();
        db.prepare(`
            INSERT INTO packages (id, user_id, sender_name, encrypted_session_key, encrypted_message, message_iv)
            VALUES (?, ?, ?, ?, ?, ?)
        `).run(id, userId, senderName, encryptedSessionKey, encryptedMessage, messageIv);
        return id;
    },

    addPackageFile: async (packageId, originalName, mimeType, size) => {
        const id = uuidv4();
        db.prepare('INSERT INTO package_files (id, package_id, original_name, mime_type, size) VALUES (?, ?, ?, ?, ?)').run(id, packageId, originalName, mimeType, size);
        return id;
    },

    getPackagesByUserId: async (userId) => {
        const packages = db.prepare('SELECT * FROM packages WHERE user_id = ? AND status = ? ORDER BY created_at DESC').all(userId, 'pending');
        for (let pkg of packages) {
            pkg.files = db.prepare('SELECT * FROM package_files WHERE package_id = ?').all(pkg.id);
        }
        return packages;
    },

    getPackageById: async (id) => {
        const pkg = db.prepare('SELECT * FROM packages WHERE id = ?').get(id);
        if (pkg) {
            pkg.files = db.prepare('SELECT * FROM package_files WHERE package_id = ?').all(pkg.id);
        }
        return pkg;
    },

    deletePackage: async (id) => {
        db.prepare('DELETE FROM package_files WHERE package_id = ?').run(id);
        db.prepare('DELETE FROM packages WHERE id = ?').run(id);
    },

    getUserMailboxUsage: async (userId) => {
        // Files plus encrypted messages, so message-only packages also count
        const result = db.prepare(`
            SELECT
                COALESCE((SELECT SUM(pf.size) FROM package_files pf JOIN packages p ON pf.package_id = p.id
                          WHERE p.user_id = ? AND p.status = 'pending'), 0)
              + COALESCE((SELECT SUM(LENGTH(encrypted_message)) FROM packages
                          WHERE user_id = ? AND status = 'pending'), 0) AS totalSize
        `).get(userId, userId);
        return result.totalSize || 0;
    },

    togglePublicLink: async (userId, enabled) => {
        db.prepare('UPDATE users SET public_link_enabled = ? WHERE id = ?').run(enabled ? 1 : 0, userId);
    },

    generateOneTimeLink: async (userId) => {
        const token = uuidv4();
        db.prepare('INSERT INTO one_time_links (token, user_id) VALUES (?, ?)').run(token, userId);
        return token;
    },

    getOneTimeLinks: async (userId) => {
        return db.prepare('SELECT * FROM one_time_links WHERE user_id = ? AND is_used = 0 ORDER BY created_at DESC').all(userId);
    },

    getUserByToken: async (token) => {
        const link = db.prepare('SELECT * FROM one_time_links WHERE token = ? AND is_used = 0').get(token);
        if (!link) return null;
        return db.prepare('SELECT * FROM users WHERE id = ?').get(link.user_id);
    },

    // Returns true only for the request that actually flipped the token to used
    consumeToken: async (token) => {
        return db.prepare('UPDATE one_time_links SET is_used = 1 WHERE token = ? AND is_used = 0').run(token).changes > 0;
    },

    deleteOneTimeLink: async (token, userId) => {
        db.prepare('DELETE FROM one_time_links WHERE token = ? AND user_id = ?').run(token, userId);
    },

    // --- Shares ---
    createShare: async (userId, token, encryptedFileKey, keyIv, salt, fileIv, originalName, mimeType, size, encryptedMessage, messageIv, maxDownloads, expiresAt, downloadProof) => {
        db.prepare(`
            INSERT INTO shares (token, user_id, encrypted_file_key, key_iv, salt, file_iv, original_name, mime_type, size, encrypted_message, message_iv, max_downloads, expires_at, download_proof)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(token, userId, encryptedFileKey, keyIv, salt, fileIv, originalName, mimeType, size, encryptedMessage || null, messageIv || null, maxDownloads || 0, expiresAt || null, downloadProof || null);
        return token;
    },

    getShareByToken: async (token) => {
        return db.prepare('SELECT * FROM shares WHERE token = ?').get(token);
    },

    // Returns false when the download limit was already reached
    incrementShareDownloads: async (token) => {
        return db.prepare('UPDATE shares SET download_count = download_count + 1 WHERE token = ? AND (max_downloads = 0 OR download_count < max_downloads)').run(token).changes > 0;
    },

    // "<packageId>_<fileId>", the on-disk name of every stored drop file
    getAllPackageFileKeys: async () => {
        return db.prepare('SELECT package_id, id FROM package_files').all().map(r => `${r.package_id}_${r.id}`);
    },

    getAllPackageFiles: async () => {
        return db.prepare('SELECT pf.id, pf.package_id, p.created_at FROM package_files pf JOIN packages p ON pf.package_id = p.id').all();
    },

    deletePackageFile: async (id) => {
        db.prepare('DELETE FROM package_files WHERE id = ?').run(id);
    },

    // Gives back a download whose transfer did not complete
    refundShareDownload: async (token) => {
        db.prepare('UPDATE shares SET download_count = download_count - 1 WHERE token = ? AND download_count > 0').run(token);
    },

    getAllShareLimits: async () => {
        return db.prepare('SELECT token, max_downloads, download_count, expires_at FROM shares').all();
    },

    getSharesByUserId: async (userId) => {
        return db.prepare('SELECT token, original_name, mime_type, size, max_downloads, download_count, expires_at, created_at FROM shares WHERE user_id = ? ORDER BY created_at DESC').all(userId);
    },

    deleteShare: async (token) => {
        db.prepare('DELETE FROM shares WHERE token = ?').run(token);
    }
};
