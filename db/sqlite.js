const Database = require('better-sqlite3');
const path = require('path');
const { randomUUID } = require('crypto');

const fs = require('fs');
const { dataLeftovers, lostDatabaseMessage } = require('./leftovers');

const dataDir = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
fs.mkdirSync(dataDir, { recursive: true });
const dbPath = path.join(dataDir, 'buzon.db');
// A new database is normal on a first install, not next to the files of an earlier one
const isNewDatabase = !fs.existsSync(dbPath);
if (isNewDatabase) {
    const found = dataLeftovers(dataDir);
    if (found.length) {
        console.error(lostDatabaseMessage(dbPath, dataDir, found));
        process.exit(1);
    }
}
const db = new Database(dbPath);
if (isNewDatabase) console.log(`[DB] Created a new, empty database at ${dbPath}`);

db.pragma('journal_mode = WAL');
// Explicit, rather than relying on how better-sqlite3 was compiled
db.pragma('foreign_keys = ON');
// Overwrite deleted content instead of leaving it in free pages of the file
db.pragma('secure_delete = ON');

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
// Key derivation of the account's password (see public/crypto.js parseKdf)
if (!userCols.find(c => c.name === 'kdf')) {
    db.exec("ALTER TABLE users ADD COLUMN kdf TEXT NOT NULL DEFAULT 'pbkdf2-sha256:600000'");
}
// Indexes for the lookups done on every request (quota, inbox, shares, one-time links)
db.exec(`
  CREATE INDEX IF NOT EXISTS idx_packages_user_status ON packages(user_id, status);
  CREATE INDEX IF NOT EXISTS idx_package_files_package ON package_files(package_id);
  CREATE INDEX IF NOT EXISTS idx_shares_user ON shares(user_id);
  CREATE INDEX IF NOT EXISTS idx_one_time_links_user ON one_time_links(user_id, is_used);
`);

// Package format: 1 = original, 2 = AAD-bound ciphertexts and raw file bodies
const packageCols = db.prepare("PRAGMA table_info(packages)").all();
if (!packageCols.find(c => c.name === 'format')) {
    db.exec("ALTER TABLE packages ADD COLUMN format INTEGER DEFAULT 1");
}

const shareCols = db.prepare("PRAGMA table_info(shares)").all();
if (!shareCols.find(c => c.name === 'download_proof')) {
    db.exec("ALTER TABLE shares ADD COLUMN download_proof TEXT");
}
// Share format: 1 = name and type in clear, 2 = name sealed with the file key, file key wrapped for the owner
if (!shareCols.find(c => c.name === 'format')) {
    db.exec("ALTER TABLE shares ADD COLUMN format INTEGER DEFAULT 1");
}
if (!shareCols.find(c => c.name === 'owner_key')) {
    db.exec("ALTER TABLE shares ADD COLUMN owner_key TEXT");
}
if (!userCols.find(c => c.name === 'server_auth_hash')) {
    // For existing users, we cannot magically compute the hash because we don't know their masterKey.
    // They will be locked out unless they re-register or we reset their accounts.
    db.exec("ALTER TABLE users ADD COLUMN server_auth_hash TEXT DEFAULT 'LEGACY_MIGRATION_REQUIRED'");
}

module.exports = {
    // Tables are created synchronously above
    ready: Promise.resolve(),

    createUser: async (username, salt, publicKey, encryptedPrivateKey, iv, serverAuthHash, kdf = 'pbkdf2-sha256:600000') => {
        const id = randomUUID();
        db.prepare(`
            INSERT INTO users (id, username, salt, public_key, encrypted_private_key, iv, server_auth_hash, last_login, kdf)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(id, username, salt, publicKey, encryptedPrivateKey, iv, serverAuthHash, new Date().toISOString(), kdf);
        return id;
    },

    getUserByUsername: async (username) => {
        return db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    },

    countUsers: async () => {
        return db.prepare('SELECT COUNT(*) AS n FROM users').get().n;
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

    // Password change: everything the password protects, in one statement, and only while the auth
    // hash is still the one checked (false otherwise)
    updateVault: async (userId, expectedAuthHash, salt, kdf, encryptedPrivateKey, iv, serverAuthHash) => {
        return db.prepare('UPDATE users SET salt = ?, kdf = ?, encrypted_private_key = ?, iv = ?, server_auth_hash = ? WHERE id = ? AND server_auth_hash = ?')
            .run(salt, kdf, encryptedPrivateKey, iv, serverAuthHash, userId, expectedAuthHash).changes > 0;
    },

    // Key rotation, all or nothing: the new public key and vault, and every re-wrapped key (null leaves
    // one as it is). Only while the auth hash is still the one checked ('vault' otherwise) and only if
    // the lists name exactly the user's pending packages and format 2 shares ('lists' otherwise: one
    // left out would no longer open). 'ok' once applied
    rotateKeys: async (userId, expectedAuthHash, vault, packages, shares) => {
        // better-sqlite3 rolls the transaction back when its function throws
        const abort = reason => { throw Object.assign(new Error(reason), { rotationAborted: reason }); };
        // The same keys, each once
        const sameKeys = (stored, given) => {
            const set = new Set(given);
            return stored.length === given.length && set.size === given.length && stored.every(key => set.has(key));
        };
        try {
            db.transaction(() => {
                const updated = db.prepare('UPDATE users SET public_key = ?, salt = ?, kdf = ?, encrypted_private_key = ?, iv = ?, server_auth_hash = ? WHERE id = ? AND server_auth_hash = ?')
                    .run(vault.publicKey, vault.salt, vault.kdf, vault.encryptedPrivateKey, vault.iv, vault.serverAuthHash, userId, expectedAuthHash);
                if (updated.changes === 0) abort('vault');
                const pending = db.prepare("SELECT id FROM packages WHERE user_id = ? AND status = 'pending'").all(userId).map(r => r.id);
                const sealed = db.prepare('SELECT token FROM shares WHERE user_id = ? AND format = 2').all(userId).map(r => r.token);
                if (!sameKeys(pending, packages.map(p => p.id)) || !sameKeys(sealed, shares.map(s => s.token))) abort('lists');
                const setSessionKey = db.prepare('UPDATE packages SET encrypted_session_key = ? WHERE id = ? AND user_id = ?');
                for (const p of packages) if (p.encryptedSessionKey !== null) setSessionKey.run(p.encryptedSessionKey, p.id, userId);
                const setOwnerKey = db.prepare('UPDATE shares SET owner_key = ? WHERE token = ? AND user_id = ?');
                for (const s of shares) if (s.ownerKey !== null) setOwnerKey.run(s.ownerKey, s.token, userId);
            })();
            return 'ok';
        } catch (error) {
            if (error.rotationAborted) return error.rotationAborted;
            throw error;
        }
    },

    createPackage: async (userId, senderName, encryptedSessionKey, encryptedMessage, messageIv, format = 1) => {
        const id = randomUUID();
        db.prepare(`
            INSERT INTO packages (id, user_id, sender_name, encrypted_session_key, encrypted_message, message_iv, format)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `).run(id, userId, senderName, encryptedSessionKey, encryptedMessage, messageIv, format);
        return id;
    },

    addPackageFile: async (packageId, originalName, mimeType, size) => {
        const id = randomUUID();
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
        const token = randomUUID();
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
    createShare: async (userId, token, encryptedFileKey, keyIv, salt, fileIv, originalName, mimeType, size, encryptedMessage, messageIv, maxDownloads, expiresAt, downloadProof, format = 1, ownerKey = null) => {
        db.prepare(`
            INSERT INTO shares (token, user_id, encrypted_file_key, key_iv, salt, file_iv, original_name, mime_type, size, encrypted_message, message_iv, max_downloads, expires_at, download_proof, format, owner_key)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(token, userId, encryptedFileKey, keyIv, salt, fileIv, originalName, mimeType, size, encryptedMessage || null, messageIv || null, maxDownloads || 0, expiresAt || null, downloadProof || null, format, ownerKey);
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

    getAllPackageDates: async () => {
        return db.prepare('SELECT id, created_at FROM packages').all();
    },

    // A used one-time link can never resolve again, so the row is only clutter
    deleteUsedOneTimeLinks: async () => {
        db.prepare('DELETE FROM one_time_links WHERE is_used = 1').run();
    },

    // Fold the WAL back into the database and truncate it, so deleted rows do not linger there
    compact: async () => {
        db.pragma('wal_checkpoint(TRUNCATE)');
    },

    getAllShareLimits: async () => {
        return db.prepare('SELECT token, max_downloads, download_count, expires_at FROM shares').all();
    },

    getSharesByUserId: async (userId) => {
        return db.prepare('SELECT token, original_name, mime_type, size, max_downloads, download_count, expires_at, created_at, format, owner_key FROM shares WHERE user_id = ? ORDER BY created_at DESC').all(userId);
    },

    deleteShare: async (token) => {
        db.prepare('DELETE FROM shares WHERE token = ?').run(token);
    }
};
