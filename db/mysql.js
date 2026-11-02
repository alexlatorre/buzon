// db/mysql.js - MySQL / MariaDB driver for Buzon (same interface as db/sqlite.js)
// Tested against MariaDB 11.4 in strict mode: MYSQL_TEST_URL=mysql://user:pass@host:port npm test

const { randomUUID } = require('crypto');
const mysql = require('mysql2/promise'); // a hard dependency: without it the server must not start
const config = require('../config').db.mysql;
const { dataLeftovers, lostDatabaseMessage } = require('./leftovers');

// Everything in UTC: JS Dates are sent and read as UTC, and the session clock (CURRENT_TIMESTAMP,
// UTC_TIMESTAMP) agrees with it whatever the server's own time zone is
const pool = mysql.createPool({
    host: config.host,
    port: config.port,
    user: config.user,
    password: config.password,
    database: config.database,
    timezone: 'Z',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});
pool.pool.on('connection', connection => connection.query("SET time_zone = '+00:00'"));

// Optional values must be bound as null: mysql2 rejects undefined
const orNull = value => (value === undefined ? null : value);

// Tables, migrations and indexes; server.js waits for this before accepting requests
// Read before server.js writes anything into the data directory (it creates .salt_secret on startup)
const dataDir = process.env.DATA_DIR || require('path').join(__dirname, '..', 'data');
const leftoversAtStart = dataLeftovers(dataDir);

const ready = (async () => {
    const conn = await pool.getConnection();
    try {
        // No users table: a new database, which is normal on a first install, not next to the files
        // of an earlier one (a wrong MYSQL_DATABASE, or a database that was lost)
        const [usersTable] = await conn.query(
            "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users'"
        );
        const isNewDatabase = usersTable.length === 0;
        if (isNewDatabase && leftoversAtStart.length) {
            throw new Error(lostDatabaseMessage(`MySQL database ${config.database}`, dataDir, leftoversAtStart));
        }
        await conn.query(`
            CREATE TABLE IF NOT EXISTS users (
                id VARCHAR(36) PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                salt TEXT NOT NULL,
                public_key TEXT NOT NULL,
                encrypted_private_key TEXT NOT NULL,
                iv TEXT NOT NULL,
                server_auth_hash TEXT NOT NULL,
                public_link_enabled BOOLEAN DEFAULT TRUE,
                mailbox_quota BIGINT DEFAULT 524288000,
                last_login DATETIME
            )
        `);

        await conn.query(`
            CREATE TABLE IF NOT EXISTS packages (
                id VARCHAR(36) PRIMARY KEY,
                user_id VARCHAR(36) NOT NULL,
                sender_name VARCHAR(64),
                encrypted_session_key TEXT NOT NULL,
                encrypted_message MEDIUMTEXT,
                message_iv VARCHAR(255),
                status VARCHAR(20) DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        `);

        await conn.query(`
            CREATE TABLE IF NOT EXISTS package_files (
                id VARCHAR(36) PRIMARY KEY,
                package_id VARCHAR(36) NOT NULL,
                original_name TEXT NOT NULL,
                mime_type VARCHAR(255) NOT NULL,
                size BIGINT NOT NULL,
                FOREIGN KEY (package_id) REFERENCES packages(id) ON DELETE CASCADE
            )
        `);

        await conn.query(`
            CREATE TABLE IF NOT EXISTS one_time_links (
                token VARCHAR(36) PRIMARY KEY,
                user_id VARCHAR(36) NOT NULL,
                is_used BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        `);

        await conn.query(`
            CREATE TABLE IF NOT EXISTS shares (
                token VARCHAR(36) PRIMARY KEY,
                user_id VARCHAR(36) NOT NULL,
                encrypted_file_key TEXT NOT NULL,
                key_iv VARCHAR(255) NOT NULL,
                salt TEXT NOT NULL,
                file_iv VARCHAR(255) NOT NULL,
                original_name TEXT NOT NULL,
                mime_type VARCHAR(255) NOT NULL,
                size BIGINT NOT NULL,
                encrypted_message MEDIUMTEXT,
                message_iv VARCHAR(255),
                max_downloads INT DEFAULT 0,
                download_count INT DEFAULT 0,
                expires_at DATETIME,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        `);
        // Settings changed at runtime by an admin, and invitations: accounts an admin created, reserved
        // until their holder activates them with a one-time token (only its SHA-256 is stored)
        await conn.query(`
            CREATE TABLE IF NOT EXISTS settings (
                \`key\` VARCHAR(64) PRIMARY KEY,
                value VARCHAR(255) NOT NULL
            )
        `);
        await conn.query(`
            CREATE TABLE IF NOT EXISTS activated_invitations (
                token_hash CHAR(64) PRIMARY KEY,
                activated_at DATETIME NOT NULL
            )
        `);
        await conn.query(`
            CREATE TABLE IF NOT EXISTS invitations (
                id VARCHAR(36) PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                role VARCHAR(16) NOT NULL DEFAULT 'user',
                token_hash CHAR(64) UNIQUE NOT NULL,
                expires_at DATETIME NOT NULL,
                created_by VARCHAR(36),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        // Columns added after the first release (CREATE TABLE IF NOT EXISTS won't add them)
        const [cols] = await conn.query(
            "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users'"
        );
        const userCols = cols.map(c => c.COLUMN_NAME);
        const userMigrations = {
            public_link_enabled: 'ALTER TABLE users ADD COLUMN public_link_enabled BOOLEAN DEFAULT TRUE',
            mailbox_quota: 'ALTER TABLE users ADD COLUMN mailbox_quota BIGINT DEFAULT 524288000',
            last_login: 'ALTER TABLE users ADD COLUMN last_login DATETIME',
            kdf: "ALTER TABLE users ADD COLUMN kdf VARCHAR(64) NOT NULL DEFAULT 'pbkdf2-sha256:600000'",
            server_auth_hash: "ALTER TABLE users ADD COLUMN server_auth_hash VARCHAR(255) NOT NULL DEFAULT 'LEGACY_MIGRATION_REQUIRED'",
            // Accounts: role (user/admin), disabled by an admin, creation date (unknown for older accounts)
            role: "ALTER TABLE users ADD COLUMN role VARCHAR(16) NOT NULL DEFAULT 'user'",
            disabled: 'ALTER TABLE users ADD COLUMN disabled TINYINT NOT NULL DEFAULT 0',
            created_at: 'ALTER TABLE users ADD COLUMN created_at DATETIME'
        };
        for (const [col, sql] of Object.entries(userMigrations)) {
            if (!userCols.includes(col)) await conn.query(sql);
        }
        // Package format: 1 = original, 2 = AAD-bound ciphertexts and raw file bodies
        const [packageColRows] = await conn.query(
            "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'packages'"
        );
        if (!packageColRows.some(c => c.COLUMN_NAME === 'format')) {
            await conn.query('ALTER TABLE packages ADD COLUMN format INT DEFAULT 1');
        }
        const [shareColRows] = await conn.query(
            "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'shares'"
        );
        if (!shareColRows.some(c => c.COLUMN_NAME === 'download_proof')) {
            await conn.query('ALTER TABLE shares ADD COLUMN download_proof VARCHAR(64)');
        }
        // Share format: 1 = name and type in clear, 2 = name sealed, file key wrapped for the owner
        if (!shareColRows.some(c => c.COLUMN_NAME === 'format')) {
            await conn.query('ALTER TABLE shares ADD COLUMN format INT DEFAULT 1');
        }
        if (!shareColRows.some(c => c.COLUMN_NAME === 'owner_key')) {
            await conn.query('ALTER TABLE shares ADD COLUMN owner_key TEXT');
        }
        // Indexes for the lookups done on every request (MySQL has no CREATE INDEX IF NOT EXISTS)
        const [indexRows] = await conn.query(
            "SELECT DISTINCT INDEX_NAME FROM INFORMATION_SCHEMA.STATISTICS WHERE TABLE_SCHEMA = DATABASE()"
        );
        const existing = new Set(indexRows.map(r => r.INDEX_NAME));
        const indexes = {
            idx_packages_user_status: 'CREATE INDEX idx_packages_user_status ON packages(user_id, status)',
            idx_package_files_package: 'CREATE INDEX idx_package_files_package ON package_files(package_id)',
            idx_shares_user: 'CREATE INDEX idx_shares_user ON shares(user_id)',
            idx_one_time_links_user: 'CREATE INDEX idx_one_time_links_user ON one_time_links(user_id, is_used)'
        };
        for (const [name, sql] of Object.entries(indexes)) {
            if (!existing.has(name)) await conn.query(sql);
        }
        // Messages may be up to 256 KB of plaintext; TEXT stops at 64 KB
        const [textCols] = await conn.query(
            "SELECT TABLE_NAME, COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() "
            + "AND COLUMN_NAME = 'encrypted_message' AND DATA_TYPE = 'text'"
        );
        for (const col of textCols) {
            await conn.query(`ALTER TABLE ${col.TABLE_NAME} MODIFY encrypted_message MEDIUMTEXT`);
        }
        console.log(isNewDatabase
            ? `[DB] Created the tables in MySQL database ${config.database}, which had none`
            : "MySQL tables synchronized.");
    } finally {
        conn.release();
    }
})();

module.exports = {
    ready,

    // Structural placeholders - Implementation would map SQLite queries to MySQL syntax
    createUser: async (username, salt, publicKey, encryptedPrivateKey, iv, serverAuthHash, kdf = 'pbkdf2-sha256:600000', role = 'user') => {
        const id = randomUUID();
        const now = new Date();
        await pool.execute(
            'INSERT INTO users (id, username, salt, public_key, encrypted_private_key, iv, server_auth_hash, last_login, kdf, role, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [id, username, salt, publicKey, encryptedPrivateKey, iv, serverAuthHash, now, kdf, role, now]
        );
        return id;
    },

    // An invitation's username becomes the account; the invitation is consumed exactly once, and only
    // while it has not expired (null otherwise). Both happen in one transaction.
    createInvitedUser: async (invitationId, tokenHash, username, salt, publicKey, encryptedPrivateKey, iv, serverAuthHash, kdf, role) => {
        const id = randomUUID();
        const now = new Date();
        const conn = await pool.getConnection();
        try {
            await conn.beginTransaction();
            const [used] = await conn.execute('DELETE FROM invitations WHERE id = ? AND username = ? AND expires_at > ?', [invitationId, username, now]);
            if (used.affectedRows !== 1) {
                await conn.rollback();
                return null;
            }
            // Remembered, so the link can say it was already used
            await conn.execute('INSERT INTO activated_invitations (token_hash, activated_at) VALUES (?, ?)', [tokenHash, now]);
            await conn.execute(
                'INSERT INTO users (id, username, salt, public_key, encrypted_private_key, iv, server_auth_hash, last_login, kdf, role, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [id, username, salt, publicKey, encryptedPrivateKey, iv, serverAuthHash, now, kdf, role, now]
            );
            await conn.commit();
            return id;
        } catch (error) {
            await conn.rollback().catch(() => {});
            throw error;
        } finally {
            conn.release();
        }
    },

    // --- Administration ---
    getSetting: async (key) => {
        const [rows] = await pool.execute('SELECT value FROM settings WHERE `key` = ?', [key]);
        return rows.length ? rows[0].value : null;
    },

    setSetting: async (key, value) => {
        await pool.execute('INSERT INTO settings (`key`, value) VALUES (?, ?) ON DUPLICATE KEY UPDATE value = VALUES(value)', [key, value]);
    },

    createInvitation: async (username, role, tokenHash, expiresAt, createdBy) => {
        const id = randomUUID();
        await pool.execute(
            'INSERT INTO invitations (id, username, role, token_hash, expires_at, created_by) VALUES (?, ?, ?, ?, ?, ?)',
            [id, username, role, tokenHash, new Date(expiresAt), createdBy || null]
        );
        return id;
    },

    getInvitationByTokenHash: async (tokenHash) => {
        const [rows] = await pool.execute('SELECT * FROM invitations WHERE token_hash = ?', [tokenHash]);
        return rows[0];
    },

    getInvitationByUsername: async (username) => {
        const [rows] = await pool.execute('SELECT * FROM invitations WHERE username = ?', [username]);
        return rows[0];
    },

    listInvitations: async () => {
        const [rows] = await pool.execute('SELECT id, username, role, expires_at, created_at, created_by FROM invitations ORDER BY created_at DESC');
        return rows;
    },

    wasInvitationActivated: async (tokenHash) => {
        const [rows] = await pool.execute('SELECT 1 FROM activated_invitations WHERE token_hash = ?', [tokenHash]);
        return rows.length > 0;
    },

    deleteInvitation: async (id) => {
        const [result] = await pool.execute('DELETE FROM invitations WHERE id = ?', [id]);
        return result.affectedRows > 0;
    },

    deleteExpiredInvitations: async () => {
        const [result] = await pool.execute('DELETE FROM invitations WHERE expires_at <= ?', [new Date()]);
        return result.affectedRows;
    },

    // Metadata only: never keys, names, messages or contents
    listAccounts: async () => {
        const [rows] = await pool.execute(`
            SELECT u.id, u.username, u.role, u.disabled, u.created_at, u.last_login, u.public_link_enabled,
                (SELECT COUNT(*) FROM packages p WHERE p.user_id = u.id AND p.status = 'pending') AS packages,
                (SELECT COUNT(*) FROM shares s WHERE s.user_id = u.id) AS shares,
                (SELECT COUNT(*) FROM one_time_links o WHERE o.user_id = u.id AND o.is_used = 0) AS one_time_links
            FROM users u ORDER BY u.username
        `);
        return rows.map(r => ({ ...r, packages: Number(r.packages), shares: Number(r.shares), one_time_links: Number(r.one_time_links) }));
    },

    countActiveAdmins: async () => {
        const [rows] = await pool.execute("SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND disabled = 0");
        return Number(rows[0].n);
    },

    setUserDisabled: async (userId, disabled) => {
        await pool.execute('UPDATE users SET disabled = ? WHERE id = ?', [disabled ? 1 : 0, userId]);
    },

    setUserRole: async (userId, role) => {
        await pool.execute('UPDATE users SET role = ? WHERE id = ?', [role, userId]);
    },

    // Rows only (the caller removes the files first): links, shares, packages and the account itself
    deleteUserRows: async (userId) => {
        const conn = await pool.getConnection();
        try {
            await conn.beginTransaction();
            await conn.execute('DELETE FROM one_time_links WHERE user_id = ?', [userId]);
            await conn.execute('DELETE FROM shares WHERE user_id = ?', [userId]);
            await conn.execute('DELETE FROM packages WHERE user_id = ?', [userId]);
            await conn.execute('DELETE FROM users WHERE id = ?', [userId]);
            await conn.commit();
        } catch (error) {
            await conn.rollback().catch(() => {});
            throw error;
        } finally {
            conn.release();
        }
    },

    listActiveOneTimeLinks: async () => {
        const [rows] = await pool.execute('SELECT o.token, o.user_id, o.created_at, u.username FROM one_time_links o JOIN users u ON u.id = o.user_id WHERE o.is_used = 0 ORDER BY o.created_at DESC');
        return rows;
    },

    listAllShares: async () => {
        const [rows] = await pool.execute('SELECT s.token, s.user_id, s.size, s.max_downloads, s.download_count, s.expires_at, s.created_at, u.username FROM shares s JOIN users u ON u.id = s.user_id ORDER BY s.created_at DESC');
        return rows;
    },

    expireShare: async (token) => {
        await pool.execute('UPDATE shares SET expires_at = ? WHERE token = ?', [new Date(), token]);
    },

    deleteOneTimeLinkByToken: async (token) => {
        const [result] = await pool.execute('DELETE FROM one_time_links WHERE token = ?', [token]);
        return result.affectedRows > 0;
    },

    getUserByUsername: async (username) => {
        const [rows] = await pool.execute('SELECT * FROM users WHERE username = ?', [username]);
        return rows[0];
    },

    countUsers: async () => {
        const [rows] = await pool.execute('SELECT COUNT(*) AS n FROM users');
        return Number(rows[0].n);
    },

    getUserById: async (id) => {
        const [rows] = await pool.execute('SELECT * FROM users WHERE id = ?', [id]);
        return rows[0];
    },

    updateLastLogin: async (userId) => {
        await pool.execute('UPDATE users SET last_login = ? WHERE id = ?', [new Date(), userId]);
    },

    updateServerAuthHash: async (userId, hash) => {
        await pool.execute('UPDATE users SET server_auth_hash = ? WHERE id = ?', [hash, userId]);
    },

    // Password change: everything the password protects, in one statement, and only while the auth
    // hash is still the one checked (false otherwise)
    updateVault: async (userId, expectedAuthHash, salt, kdf, encryptedPrivateKey, iv, serverAuthHash) => {
        const [result] = await pool.execute(
            'UPDATE users SET salt = ?, kdf = ?, encrypted_private_key = ?, iv = ?, server_auth_hash = ? WHERE id = ? AND server_auth_hash = ?',
            [salt, kdf, encryptedPrivateKey, iv, serverAuthHash, userId, expectedAuthHash]
        );
        return result.affectedRows > 0;
    },

    // Key rotation, all or nothing: the new public key and vault, and every re-wrapped key (null leaves
    // one as it is). Only while the auth hash is still the one checked ('vault' otherwise) and only if
    // the lists name exactly the user's pending packages and format 2 shares ('lists' otherwise: one
    // left out would no longer open). 'ok' once applied. The user row stays locked until the end, and
    // FOR UPDATE keeps new packages and shares out of the ranges read
    rotateKeys: async (userId, expectedAuthHash, vault, packages, shares) => {
        // The same keys, each once
        const sameKeys = (stored, given) => {
            const set = new Set(given);
            return stored.length === given.length && set.size === given.length && stored.every(key => set.has(key));
        };
        const conn = await pool.getConnection();
        try {
            await conn.beginTransaction();
            const [updated] = await conn.execute(
                'UPDATE users SET public_key = ?, salt = ?, kdf = ?, encrypted_private_key = ?, iv = ?, server_auth_hash = ? WHERE id = ? AND server_auth_hash = ?',
                [vault.publicKey, vault.salt, vault.kdf, vault.encryptedPrivateKey, vault.iv, vault.serverAuthHash, userId, expectedAuthHash]
            );
            if (updated.affectedRows === 0) {
                await conn.rollback();
                return 'vault';
            }
            const [pending] = await conn.execute("SELECT id FROM packages WHERE user_id = ? AND status = 'pending' FOR UPDATE", [userId]);
            const [sealed] = await conn.execute('SELECT token FROM shares WHERE user_id = ? AND format = 2 FOR UPDATE', [userId]);
            if (!sameKeys(pending.map(r => r.id), packages.map(p => p.id)) || !sameKeys(sealed.map(r => r.token), shares.map(s => s.token))) {
                await conn.rollback();
                return 'lists';
            }
            for (const p of packages) {
                if (p.encryptedSessionKey !== null) {
                    await conn.execute('UPDATE packages SET encrypted_session_key = ? WHERE id = ? AND user_id = ?', [p.encryptedSessionKey, p.id, userId]);
                }
            }
            for (const s of shares) {
                if (s.ownerKey !== null) {
                    await conn.execute('UPDATE shares SET owner_key = ? WHERE token = ? AND user_id = ?', [s.ownerKey, s.token, userId]);
                }
            }
            await conn.commit();
            return 'ok';
        } catch (error) {
            await conn.rollback().catch(() => {});
            // InnoDB undid this transaction to break a deadlock (with a package being deleted, say): the
            // page reads the lists again, as when one changed
            if (error.code === 'ER_LOCK_DEADLOCK') return 'lists';
            throw error;
        } finally {
            conn.release();
        }
    },

    createPackage: async (userId, senderName, encryptedSessionKey, encryptedMessage, messageIv, format = 1) => {
        const id = randomUUID();
        await pool.execute(
            'INSERT INTO packages (id, user_id, sender_name, encrypted_session_key, encrypted_message, message_iv, format) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [id, userId, orNull(senderName), encryptedSessionKey, encryptedMessage, messageIv, format]
        );
        return id;
    },

    addPackageFile: async (packageId, originalName, mimeType, size) => {
        const id = randomUUID();
        await pool.execute(
            'INSERT INTO package_files (id, package_id, original_name, mime_type, size) VALUES (?, ?, ?, ?, ?)',
            [id, packageId, originalName, mimeType, size]
        );
        return id;
    },

    getPackagesByUserId: async (userId) => {
        const [packages] = await pool.execute("SELECT * FROM packages WHERE user_id = ? AND status = 'pending' ORDER BY created_at DESC", [userId]);
        for (let pkg of packages) {
            const [files] = await pool.execute('SELECT * FROM package_files WHERE package_id = ?', [pkg.id]);
            pkg.files = files;
        }
        return packages;
    },

    getPackageById: async (id) => {
        const [rows] = await pool.execute('SELECT * FROM packages WHERE id = ?', [id]);
        const pkg = rows[0];
        if (pkg) {
            const [files] = await pool.execute('SELECT * FROM package_files WHERE package_id = ?', [pkg.id]);
            pkg.files = files;
        }
        return pkg;
    },

    deletePackage: async (id) => {
        await pool.execute('DELETE FROM package_files WHERE package_id = ?', [id]);
        await pool.execute('DELETE FROM packages WHERE id = ?', [id]);
    },

    getUserMailboxUsage: async (userId) => {
        // Files plus encrypted messages, so message-only packages also count
        const [rows] = await pool.execute(`
            SELECT
                COALESCE((SELECT SUM(pf.size) FROM package_files pf JOIN packages p ON pf.package_id = p.id
                          WHERE p.user_id = ? AND p.status = 'pending'), 0)
              + COALESCE((SELECT SUM(LENGTH(encrypted_message)) FROM packages
                          WHERE user_id = ? AND status = 'pending'), 0) AS totalSize
        `, [userId, userId]);
        // SUM() comes back as a DECIMAL string from mysql2
        return Number(rows[0].totalSize) || 0;
    },

    togglePublicLink: async (userId, enabled) => {
        await pool.execute('UPDATE users SET public_link_enabled = ? WHERE id = ?', [enabled ? 1 : 0, userId]);
    },

    generateOneTimeLink: async (userId) => {
        const token = randomUUID();
        await pool.execute('INSERT INTO one_time_links (token, user_id) VALUES (?, ?)', [token, userId]);
        return token;
    },

    getOneTimeLinks: async (userId) => {
        const [rows] = await pool.execute('SELECT * FROM one_time_links WHERE user_id = ? AND is_used = 0 ORDER BY created_at DESC', [userId]);
        return rows;
    },

    getUserByToken: async (token) => {
        const [links] = await pool.execute('SELECT * FROM one_time_links WHERE token = ? AND is_used = 0', [token]);
        const link = links[0];
        if (!link) return null;
        return module.exports.getUserById(link.user_id);
    },

    // Returns true only for the request that actually flipped the token to used
    consumeToken: async (token) => {
        const [result] = await pool.execute('UPDATE one_time_links SET is_used = 1 WHERE token = ? AND is_used = 0', [token]);
        return result.affectedRows > 0;
    },

    deleteOneTimeLink: async (token, userId) => {
        await pool.execute('DELETE FROM one_time_links WHERE token = ? AND user_id = ?', [token, userId]);
    },

    // --- Shares ---
    createShare: async (userId, token, encryptedFileKey, keyIv, salt, fileIv, originalName, mimeType, size, encryptedMessage, messageIv, maxDownloads, expiresAt, downloadProof, format = 1, ownerKey = null) => {
        await pool.execute(
            `INSERT INTO shares (token, user_id, encrypted_file_key, key_iv, salt, file_iv, original_name, mime_type, size, encrypted_message, message_iv, max_downloads, expires_at, download_proof, format, owner_key)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [token, userId, encryptedFileKey, keyIv, salt, fileIv, originalName, mimeType, size, encryptedMessage || null, messageIv || null, maxDownloads || 0,
             expiresAt ? new Date(expiresAt) : null, downloadProof || null, format, ownerKey]
        );
        return token;
    },

    getShareByToken: async (token) => {
        const [rows] = await pool.execute('SELECT * FROM shares WHERE token = ?', [token]);
        return rows[0];
    },

    // Returns false when the download limit was already reached
    incrementShareDownloads: async (token) => {
        const [result] = await pool.execute(
            'UPDATE shares SET download_count = download_count + 1 WHERE token = ? AND (max_downloads = 0 OR download_count < max_downloads)',
            [token]
        );
        return result.affectedRows > 0;
    },

    // "<packageId>_<fileId>", the on-disk name of every stored drop file
    getAllPackageFileKeys: async () => {
        const [rows] = await pool.execute('SELECT package_id, id FROM package_files');
        return rows.map(r => `${r.package_id}_${r.id}`);
    },

    getAllPackageFiles: async () => {
        const [rows] = await pool.execute('SELECT pf.id, pf.package_id, p.created_at FROM package_files pf JOIN packages p ON pf.package_id = p.id');
        return rows;
    },

    deletePackageFile: async (id) => {
        await pool.execute('DELETE FROM package_files WHERE id = ?', [id]);
    },

    // Gives back a download whose transfer did not complete
    refundShareDownload: async (token) => {
        await pool.execute('UPDATE shares SET download_count = download_count - 1 WHERE token = ? AND download_count > 0', [token]);
    },

    getAllPackageDates: async () => {
        const [rows] = await pool.execute('SELECT id, created_at FROM packages');
        return rows;
    },

    // A used one-time link can never resolve again, so the row is only clutter
    deleteUsedOneTimeLinks: async () => {
        await pool.execute('DELETE FROM one_time_links WHERE is_used = 1');
    },

    // Nothing to do: MySQL manages its own logs
    compact: async () => {},

    getAllShareLimits: async () => {
        const [rows] = await pool.execute('SELECT token, max_downloads, download_count, expires_at FROM shares');
        return rows;
    },

    getSharesByUserId: async (userId) => {
        const [rows] = await pool.execute(
            'SELECT token, original_name, mime_type, size, max_downloads, download_count, expires_at, created_at, format, owner_key FROM shares WHERE user_id = ? ORDER BY created_at DESC',
            [userId]
        );
        return rows;
    },

    deleteShare: async (token) => {
        await pool.execute('DELETE FROM shares WHERE token = ?', [token]);
    }
};
