// Test helpers: boots an isolated server and emulates the browser client with WebCrypto
const { spawn } = require('child_process');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { loadCryptoUtils } = require('./browser-crypto');

const CryptoUtils = loadCryptoUtils();
const subtle = globalThis.crypto.subtle;
const b64 = buf => Buffer.from(buf).toString('base64');
const unb64 = s => new Uint8Array(Buffer.from(s, 'base64'));

function freePort() {
    return new Promise((resolve, reject) => {
        const srv = net.createServer();
        srv.listen(0, () => {
            const { port } = srv.address();
            srv.close(() => resolve(port));
        });
        srv.on('error', reject);
    });
}

// Starts server.js with its own data dir and port; resolves once it is listening
async function startServer(extraEnv = {}) {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'buzon-test-'));
    const port = await freePort();
    const proc = spawn(process.execPath, [path.join(__dirname, '..', 'server.js')], {
        env: { ...process.env, PORT: String(port), DATA_DIR: dataDir, AUTH_RATE_LIMIT: '1000', DB_ENGINE: 'sqlite', TLS: 'off', ...extraEnv },
        stdio: ['ignore', 'pipe', 'pipe']
    });
    let output = '';
    await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`Server did not start:\n${output}`)), 15000);
        const onData = chunk => {
            output += chunk;
            if (output.includes('server running at')) {
                clearTimeout(timer);
                resolve();
            }
        };
        proc.stdout.on('data', onData);
        proc.stderr.on('data', onData);
        proc.on('exit', code => reject(new Error(`Server exited with ${code}:\n${output}`)));
    });
    return {
        base: `http://localhost:${port}`,
        dataDir,
        logs: () => output,
        async stop() {
            proc.kill();
            await new Promise(resolve => proc.once('exit', resolve));
            fs.rmSync(dataDir, { recursive: true, force: true });
        }
    };
}

async function deriveMasterKey(password, salt) {
    const k = await subtle.importKey('raw', new TextEncoder().encode(password), { name: 'PBKDF2' }, false, ['deriveKey']);
    return subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
        k, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
    );
}

async function computeServerAuthHash(masterKey) {
    const raw = new Uint8Array(await subtle.exportKey('raw', masterKey));
    const suffix = new TextEncoder().encode('SERVER_AUTH');
    const combined = new Uint8Array(raw.length + suffix.length);
    combined.set(raw);
    combined.set(suffix, raw.length);
    return b64(await subtle.digest('SHA-256', combined));
}

async function aesEncrypt(key, data) {
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
    return { ciphertext: b64(await subtle.encrypt({ name: 'AES-GCM', iv }, key, data)), iv: b64(iv) };
}

const aesDecrypt = (key, ciphertext, iv) => subtle.decrypt({ name: 'AES-GCM', iv: unb64(iv) }, key, unb64(ciphertext));

function client(base) {
    async function json(method, url, body, token) {
        const res = await fetch(base + url, {
            method,
            headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
            body: body ? JSON.stringify(body) : undefined
        });
        return { status: res.status, data: await res.json().catch(() => null) };
    }

    // Same steps as handleRegister in public/app.js (RSA-2048 to keep tests fast)
    async function register(username, password) {
        const salt = globalThis.crypto.getRandomValues(new Uint8Array(16));
        const masterKey = await deriveMasterKey(password, salt);
        const keyPair = await subtle.generateKey(
            { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
            true, ['encrypt', 'decrypt']
        );
        const publicKey = b64(await subtle.exportKey('spki', keyPair.publicKey));
        const pkcs8 = b64(await subtle.exportKey('pkcs8', keyPair.privateKey));
        const encPriv = await aesEncrypt(masterKey, new TextEncoder().encode(pkcs8));
        const serverAuthHash = await computeServerAuthHash(masterKey);
        const res = await json('POST', '/api/auth/register', {
            username, salt: b64(salt), publicKey, encryptedPrivateKey: encPriv.ciphertext, iv: encPriv.iv, serverAuthHash
        });
        return { res, user: { id: res.data && res.data.userId, username, password, publicKey, privateKey: keyPair.privateKey, serverAuthHash } };
    }

    // Same steps as handleLogin in public/app.js, including the legacy migration challenge
    async function login(username, password) {
        const salt = await json('GET', `/api/auth/salt/${encodeURIComponent(username)}`);
        const masterKey = await deriveMasterKey(password, unb64(salt.data.salt));
        const serverAuthHash = await computeServerAuthHash(masterKey);
        let res = await json('POST', '/api/auth/login', { username, serverAuthHash });
        if (res.data && res.data.migrationRequired) {
            const pkcs8 = new TextDecoder().decode(await aesDecrypt(masterKey, res.data.encryptedPrivateKey, res.data.iv));
            const privateKey = await subtle.importKey('pkcs8', unb64(pkcs8), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
            const challengeResponse = await CryptoUtils.answerMigrationChallenge(privateKey, res.data.challenge);
            res = await json('POST', '/api/auth/login', { username, serverAuthHash, challengeId: res.data.challengeId, challengeResponse });
        }
        return res;
    }

    // Same steps as public/drop.js (format 2, through the real crypto.js); extra: more form fields
    async function drop(linkId, publicKeyB64, files, senderName = 'Tester', extra = {}) {
        const publicKey = await subtle.importKey('spki', unb64(publicKeyB64), { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt']);
        const pkg = await CryptoUtils.encryptDropPackage(publicKey, 'hello',
            files.map(f => ({ name: f.name, data: new TextEncoder().encode(f.content) })));
        const form = new FormData();
        form.append('format', '2');
        form.append('senderName', senderName);
        form.append('encryptedSessionKey', pkg.encryptedSessionKey);
        form.append('encryptedMessage', pkg.encryptedMessage);
        form.append('messageIv', pkg.messageIv);
        pkg.bodies.forEach(body => form.append('files', new Blob([body], { type: 'application/octet-stream' }), 'encrypted.bin'));
        form.append('fileNames', JSON.stringify(pkg.names));
        for (const [k, v] of Object.entries(extra)) form.append(k, v);
        const res = await fetch(`${base}/api/drop/${linkId}`, { method: 'POST', body: form });
        return { status: res.status, data: await res.json().catch(() => null), sessionKey: pkg.sessionKey };
    }

    // Field sizes match public/app.js: wrapped AES-256 key (32 + 16 tag), 12-byte IVs, 16-byte salt
    const randomB64 = bytes => b64(globalThis.crypto.getRandomValues(new Uint8Array(bytes)));
    function shareFields({ maxDownloads = 0, expiresIn = '0' } = {}) {
        return {
            encryptedFileKey: randomB64(48), keyIv: randomB64(12), salt: randomB64(16), fileIv: randomB64(12),
            originalName: 'x.bin', mimeType: 'application/octet-stream', maxDownloads: String(maxDownloads), expiresIn: String(expiresIn)
        };
    }

    async function share(userId, token, { size = 100, maxDownloads = 0, expiresIn = '0', fields: override = {}, extra = [] } = {}) {
        const form = new FormData();
        form.append('file', new Blob([new Uint8Array(size)]), 'encrypted.bin');
        const fields = { ...shareFields({ maxDownloads, expiresIn }), ...override };
        for (const [k, v] of Object.entries(fields)) if (v !== undefined) form.append(k, v);
        for (const [k, v] of extra) form.append(k, v);
        const res = await fetch(`${base}/api/share/${userId}`, { method: 'POST', headers: { Authorization: `Bearer ${token}` }, body: form });
        return { status: res.status, data: await res.json().catch(() => null) };
    }

    // What handleRotateKeys in public/app.js sends (RSA-2048 to keep tests fast): the answer to a
    // rotation challenge, a new key pair, its private key under the same password with a new salt, and
    // every pending package key and format 2 share owner key wrapped again from user.privateKey (null
    // where it does not open). Also returns the new key pair
    async function rotationBody(user, token) {
        const salt = await json('GET', `/api/auth/salt/${encodeURIComponent(user.username)}`);
        const currentServerAuthHash = await computeServerAuthHash(await deriveMasterKey(user.password, unb64(salt.data.salt)));
        const pair = await subtle.generateKey(
            { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
            true, ['encrypt', 'decrypt']
        );
        const newSalt = globalThis.crypto.getRandomValues(new Uint8Array(16));
        const masterKey = await deriveMasterKey(user.password, newSalt);
        const encPriv = await aesEncrypt(masterKey, new TextEncoder().encode(b64(await subtle.exportKey('pkcs8', pair.privateKey))));
        const packages = [];
        for (const pkg of (await json('GET', `/api/packages/${user.id}`, null, token)).data) {
            packages.push({ id: pkg.id, encryptedSessionKey: await CryptoUtils.rewrapPackageKey(user.privateKey, pair.publicKey, pkg) });
        }
        const shares = [];
        for (const s of (await json('GET', `/api/shares/${user.id}`, null, token)).data) {
            if (Number(s.format) === 2) shares.push({ token: s.token, ownerKey: await CryptoUtils.rewrapShareOwnerKey(user.privateKey, pair.publicKey, s.owner_key) });
        }
        // Proof of holding the current private key
        const challenge = (await json('POST', '/api/auth/rotate-keys/challenge', null, token)).data;
        const challengeResponse = await CryptoUtils.answerRotationChallenge(user.privateKey, challenge.challenge);
        const body = {
            currentServerAuthHash, challengeId: challenge.challengeId, challengeResponse,
            publicKey: b64(await subtle.exportKey('spki', pair.publicKey)), salt: b64(newSalt), kdf: 'pbkdf2-sha256:600000',
            encryptedPrivateKey: encPriv.ciphertext, iv: encPriv.iv, serverAuthHash: await computeServerAuthHash(masterKey), packages, shares
        };
        return { body, privateKey: pair.privateKey, publicKey: body.publicKey };
    }

    return { json, register, login, drop, share, shareFields, rotationBody };
}


// Runs server.js from a copy outside the repo, so local certificates there are not picked up.
// `files` adds files to the copy (e.g. certificates); TLS and TRUST_PROXY are unset unless given.
async function startServerCopy(env, files = {}) {
    const repo = path.join(__dirname, '..');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'buzon-copy-'));
    for (const item of ['server.js', 'config.js', 'db.js', 'db', 'public']) {
        fs.cpSync(path.join(repo, item), path.join(dir, item), { recursive: true });
    }
    for (const [name, content] of Object.entries(files)) {
        fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
        fs.writeFileSync(path.join(dir, name), content);
    }
    const port = await freePort();
    const childEnv = { ...process.env, PORT: String(port), DATA_DIR: path.join(dir, 'data'), NODE_PATH: path.join(repo, 'node_modules'), DB_ENGINE: 'sqlite', ...env };
    for (const key of ['TLS', 'TRUST_PROXY']) if (!(key in env)) delete childEnv[key];
    const proc = spawn(process.execPath, ['server.js'], { cwd: dir, env: childEnv, stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '';
    const exited = new Promise(resolve => proc.on('exit', code => resolve(code)));
    const started = await new Promise(resolve => {
        const onData = chunk => { output += chunk; if (output.includes('server running at')) resolve(true); };
        proc.stdout.on('data', onData);
        proc.stderr.on('data', onData);
        exited.then(() => resolve(false));
    });
    return {
        started, exited, dir, output: () => output, base: `http://localhost:${port}`,
        async stop() {
            if (started) { proc.kill(); await exited; }
            fs.rmSync(dir, { recursive: true, force: true });
        }
    };
}

module.exports = { startServer, startServerCopy, client, aesDecrypt, b64 };
