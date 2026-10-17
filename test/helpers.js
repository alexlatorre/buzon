// Test helpers: boots an isolated server and emulates the browser client with WebCrypto
const { spawn } = require('child_process');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');

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
        return { res, user: { id: res.data && res.data.userId, username, password, publicKey, serverAuthHash } };
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
            const nonce = await subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, unb64(res.data.challenge));
            res = await json('POST', '/api/auth/login', { username, serverAuthHash, challengeResponse: b64(nonce) });
        }
        return res;
    }

    // Same steps as public/drop.js
    async function drop(linkId, publicKeyB64, files, senderName = 'Tester') {
        const publicKey = await subtle.importKey('spki', unb64(publicKeyB64), { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt']);
        const sessionKey = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
        const message = await aesEncrypt(sessionKey, new TextEncoder().encode('hello'));
        const form = new FormData();
        form.append('senderName', senderName);
        form.append('encryptedSessionKey', b64(await subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, await subtle.exportKey('raw', sessionKey))));
        form.append('encryptedMessage', message.ciphertext);
        form.append('messageIv', message.iv);
        const names = [];
        for (const f of files) {
            const enc = await aesEncrypt(sessionKey, new TextEncoder().encode(f.content));
            const name = await aesEncrypt(sessionKey, new TextEncoder().encode(f.name));
            names.push(`enc:${name.iv}:${name.ciphertext}`);
            const payload = JSON.stringify({ ...enc, filename: f.name, mimeType: 'text/plain' });
            form.append('files', new Blob([payload], { type: 'application/json' }), 'encrypted.bin');
        }
        form.append('fileNames', JSON.stringify(names));
        const res = await fetch(`${base}/api/drop/${linkId}`, { method: 'POST', body: form });
        return { status: res.status, data: await res.json().catch(() => null), sessionKey };
    }

    async function share(userId, token, { size = 100, maxDownloads = 0, expiresIn = '0' } = {}) {
        const form = new FormData();
        form.append('file', new Blob([new Uint8Array(size)]), 'encrypted.bin');
        const fields = { encryptedFileKey: 'a', keyIv: 'b', salt: 'c', fileIv: 'd', originalName: 'x.bin', maxDownloads: String(maxDownloads), expiresIn };
        for (const [k, v] of Object.entries(fields)) form.append(k, v);
        const res = await fetch(`${base}/api/share/${userId}`, { method: 'POST', headers: { Authorization: `Bearer ${token}` }, body: form });
        return { status: res.status, data: await res.json().catch(() => null) };
    }

    return { json, register, login, drop, share };
}

module.exports = { startServer, client, aesDecrypt, b64 };
