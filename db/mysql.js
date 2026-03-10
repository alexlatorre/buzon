// db/mysql.js - MySQL Driver for Buzon
// Note: This requires the 'mysql2' package.
// For now, this is a structural template to prepare for MySQL support.

const { v4: uuidv4 } = require('uuid');
let pool;

try {
    const mysql = require('mysql2/promise');
    const config = require('../config').db.mysql;

    pool = mysql.createPool({
        host: config.host,
        user: config.user,
        password: config.password,
        database: config.database,
        waitForConnections: true,
        connectionLimit: 10,
        queueLimit: 0
    });

    // Initialize tables automatically
    pool.getConnection().then(async (conn) => {
        try {
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
                    encrypted_message TEXT,
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
                    encrypted_message TEXT,
                    message_iv VARCHAR(255),
                    max_downloads INT DEFAULT 0,
                    download_count INT DEFAULT 0,
                    expires_at DATETIME,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            `);
            console.log("MySQL tables synchronized.");
        } catch (err) {
            console.error("Failed to initialize MySQL tables:", err);
        } finally {
            conn.release();
        }
    });

} catch (e) {
    console.warn("MySQL driver 'mysql2' not found. MySQL support will not work until installed.");
}

module.exports = {
    // Structural placeholders - Implementation would map SQLite queries to MySQL syntax
    createUser: async (username, salt, publicKey, encryptedPrivateKey, iv, serverAuthHash) => {
        const id = uuidv4();
        await pool.execute(
            'INSERT INTO users (id, username, salt, public_key, encrypted_private_key, iv, server_auth_hash, last_login) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [id, username, salt, publicKey, encryptedPrivateKey, iv, serverAuthHash, new Date()]
        );
        return id;
    },

    getUserByUsername: async (username) => {
        const [rows] = await pool.execute('SELECT * FROM users WHERE username = ?', [username]);
        return rows[0];
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

    createPackage: async (userId, senderName, encryptedSessionKey, encryptedMessage, messageIv) => {
        const id = uuidv4();
        await pool.execute(
            'INSERT INTO packages (id, user_id, sender_name, encrypted_session_key, encrypted_message, message_iv) VALUES (?, ?, ?, ?, ?, ?)',
            [id, userId, senderName, encryptedSessionKey, encryptedMessage, messageIv]
        );
        return id;
    },

    addPackageFile: async (packageId, originalName, mimeType, size) => {
        const id = uuidv4();
        await pool.execute(
            'INSERT INTO package_files (id, package_id, original_name, mime_type, size) VALUES (?, ?, ?, ?, ?)',
            [id, packageId, originalName, mimeType, size]
        );
        return id;
    },

    getPackagesByUserId: async (userId) => {
        const [packages] = await pool.execute('SELECT * FROM packages WHERE user_id = ? AND status = "pending" ORDER BY created_at DESC', [userId]);
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
        const [rows] = await pool.execute(`
            SELECT SUM(pf.size) as totalSize 
            FROM package_files pf
            JOIN packages p ON pf.package_id = p.id
            WHERE p.user_id = ? AND p.status = 'pending'
        `, [userId]);
        return rows[0].totalSize || 0;
    },

    togglePublicLink: async (userId, enabled) => {
        await pool.execute('UPDATE users SET public_link_enabled = ? WHERE id = ?', [enabled ? 1 : 0, userId]);
    },

    generateOneTimeLink: async (userId) => {
        const token = uuidv4();
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

    consumeToken: async (token) => {
        await pool.execute('UPDATE one_time_links SET is_used = 1 WHERE token = ?', [token]);
    },

    deleteOneTimeLink: async (token, userId) => {
        await pool.execute('DELETE FROM one_time_links WHERE token = ? AND user_id = ?', [token, userId]);
    },

    // --- Shares ---
    createShare: async (userId, token, encryptedFileKey, keyIv, salt, fileIv, originalName, mimeType, size, encryptedMessage, messageIv, maxDownloads, expiresAt) => {
        await pool.execute(
            `INSERT INTO shares (token, user_id, encrypted_file_key, key_iv, salt, file_iv, original_name, mime_type, size, encrypted_message, message_iv, max_downloads, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [token, userId, encryptedFileKey, keyIv, salt, fileIv, originalName, mimeType, size, encryptedMessage || null, messageIv || null, maxDownloads || 0, expiresAt || null]
        );
        return token;
    },

    getShareByToken: async (token) => {
        const [rows] = await pool.execute('SELECT * FROM shares WHERE token = ?', [token]);
        return rows[0];
    },

    incrementShareDownloads: async (token) => {
        await pool.execute('UPDATE shares SET download_count = download_count + 1 WHERE token = ?', [token]);
    },

    getSharesByUserId: async (userId) => {
        const [rows] = await pool.execute(
            'SELECT token, original_name, mime_type, size, max_downloads, download_count, expires_at, created_at FROM shares WHERE user_id = ? ORDER BY created_at DESC',
            [userId]
        );
        return rows;
    },

    deleteShare: async (token) => {
        await pool.execute('DELETE FROM shares WHERE token = ?', [token]);
    }
};
