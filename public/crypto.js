// crypto.js - Front-End Cryptography utilities based on WebCrypto API

const CryptoUtils = {
    // Convert ArrayBuffer to Base64
    bufferToBase64: function (buffer) {
        const bytes = new Uint8Array(buffer);
        const binString = Array.from(bytes, (byte) =>
            String.fromCodePoint(byte)
        ).join("");
        return window.btoa(binString);
    },

    // Convert Base64 to ArrayBuffer
    base64ToBuffer: function (base64) {
        const binString = window.atob(base64);
        return Uint8Array.from(binString, (m) => m.codePointAt(0)).buffer;
    },

    // Derive an AES-GCM Master Key from a Password and Salt using PBKDF2
    // extractable: only the login master key needs it (computeServerAuthHash reads its raw bytes)
    deriveMasterKey: async function (password, saltBuffer, extractable = true) {
        const encoder = new TextEncoder();
        const passKey = await window.crypto.subtle.importKey(
            "raw",
            encoder.encode(password),
            { name: "PBKDF2" },
            false,
            ["deriveKey"]
        );

        return await window.crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: saltBuffer,
                iterations: 600000, // Secure iteration count
                hash: "SHA-256"
            },
            passKey,
            { name: "AES-GCM", length: 256 },
            extractable,
            ["encrypt", "decrypt"]
        );
    },

    // Generate an RSA-OAEP Key Pair (4096 bits)
    generateRSAKeyPair: async function () {
        return await window.crypto.subtle.generateKey(
            {
                name: "RSA-OAEP",
                modulusLength: 4096,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256",
            },
            true,
            ["encrypt", "decrypt"]
        );
    },

    // Export PublicKey to Base64 SPKI
    exportPublicKey: async function (publicKey) {
        const exported = await window.crypto.subtle.exportKey("spki", publicKey);
        return this.bufferToBase64(exported);
    },

    // Import PublicKey from Base64 SPKI
    importPublicKey: async function (base64Spki) {
        const buffer = this.base64ToBuffer(base64Spki);
        return await window.crypto.subtle.importKey(
            "spki",
            buffer,
            { name: "RSA-OAEP", hash: "SHA-256" },
            true,
            ["encrypt"]
        );
    },

    // Export PrivateKey to Base64 PKCS8
    exportPrivateKey: async function (privateKey) {
        const exported = await window.crypto.subtle.exportKey("pkcs8", privateKey);
        return this.bufferToBase64(exported);
    },

    // Import PrivateKey from Base64 PKCS8
    importPrivateKey: async function (base64Pkcs8) {
        const buffer = this.base64ToBuffer(base64Pkcs8);
        return await window.crypto.subtle.importKey(
            "pkcs8",
            buffer,
            { name: "RSA-OAEP", hash: "SHA-256" },
            false, // never exported again once in memory
            ["decrypt"]
        );
    },

    // Encrypt data with Master Key (AES-GCM)
    encryptSymmetric: async function (masterKey, dataBuffer) {
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            masterKey,
            dataBuffer
        );
        return {
            ciphertext: this.bufferToBase64(encrypted),
            iv: this.bufferToBase64(iv)
        };
    },

    // Decrypt data with Master Key (AES-GCM)
    decryptSymmetric: async function (masterKey, cipherBase64, ivBase64) {
        const encryptedBuffer = this.base64ToBuffer(cipherBase64);
        const ivBuffer = this.base64ToBuffer(ivBase64);

        return await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: ivBuffer },
            masterKey,
            encryptedBuffer
        );
    },

    // Encrypt with RSA Public Key
    encryptAsymmetric: async function (publicKey, dataBuffer) {
        const encrypted = await window.crypto.subtle.encrypt(
            { name: "RSA-OAEP" },
            publicKey,
            dataBuffer
        );
        return this.bufferToBase64(encrypted);
    },

    // Decrypt with RSA Private Key
    decryptAsymmetric: async function (privateKey, cipherBase64) {
        const encryptedBuffer = this.base64ToBuffer(cipherBase64);
        return await window.crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            privateKey,
            encryptedBuffer
        );
    },

    // Generate random bytes for Salt
    generateSalt: function (length = 16) {
        const salt = window.crypto.getRandomValues(new Uint8Array(length));
        return this.bufferToBase64(salt);
    },

    // Generate a random AES-GCM session key
    generateSessionKey: async function () {
        return await window.crypto.subtle.generateKey(
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );
    },

    // Export SessionKey to Raw Base64
    exportSessionKey: async function (sessionKey) {
        const exported = await window.crypto.subtle.exportKey("raw", sessionKey);
        return this.bufferToBase64(exported);
    },

    // Import SessionKey from Raw Base64
    importSessionKey: async function (base64Raw) {
        const buffer = this.base64ToBuffer(base64Raw);
        return await window.crypto.subtle.importKey(
            "raw",
            buffer,
            { name: "AES-GCM" },
            false, // only used to decrypt the package
            ["encrypt", "decrypt"]
        );
    },

    // Compute Server Authentication Hash from Master Key
    computeServerAuthHash: async function (masterKey) {
        const rawKey = await window.crypto.subtle.exportKey("raw", masterKey);
        const encoder = new TextEncoder();
        const suffix = encoder.encode("SERVER_AUTH");

        // Concatenate rawKey + "SERVER_AUTH"
        const combined = new Uint8Array(rawKey.byteLength + suffix.byteLength);
        combined.set(new Uint8Array(rawKey), 0);
        combined.set(suffix, rawKey.byteLength);

        const hashBuffer = await window.crypto.subtle.digest("SHA-256", combined);
        return this.bufferToBase64(hashBuffer);
    },

    // Recipient key fingerprint for drop links ("#k=..."): base64url SHA-256 of the SPKI public key,
    // cut to 22 characters (~128 bits). The fragment never reaches the server, so a sender can check
    // that the public key the server hands out is really the recipient's.
    publicKeyFingerprint: async function (spkiBase64) {
        const digest = new Uint8Array(await window.crypto.subtle.digest("SHA-256", this.base64ToBuffer(spkiBase64)));
        return this.bufferToBase64(digest).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "").slice(0, 22);
    },

    // The recipient computes it from their private key, which the server cannot forge: the public
    // half (n, e) is read from the private key and re-encoded as SPKI
    fingerprintFromPkcs8: async function (base64Pkcs8) {
        const subtle = window.crypto.subtle;
        const params = { name: "RSA-OAEP", hash: "SHA-256" };
        const privateKey = await subtle.importKey("pkcs8", this.base64ToBuffer(base64Pkcs8), params, true, ["decrypt"]);
        const { n, e } = await subtle.exportKey("jwk", privateKey);
        const publicKey = await subtle.importKey("jwk", { kty: "RSA", n, e, alg: "RSA-OAEP-256", ext: true }, params, true, ["encrypt"]);
        return this.publicKeyFingerprint(this.bufferToBase64(await subtle.exportKey("spki", publicKey)));
    },

    verifyRecipientKey: async function (spkiBase64, expectedFingerprint) {
        if (typeof expectedFingerprint !== "string" || expectedFingerprint.length !== 22) return false;
        return (await this.publicKeyFingerprint(spkiBase64)) === expectedFingerprint;
    },

    // Builds a drop link with the key fingerprint. Both parts are checked so that a value coming from
    // the server (the account id, a one-time token) cannot inject its own "#k=" into the link.
    dropLink: function (origin, linkId, fingerprint) {
        if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(linkId)) throw new Error("Invalid link id");
        if (!/^[A-Za-z0-9_-]{22}$/.test(fingerprint)) throw new Error("Invalid key fingerprint");
        return `${origin}/drop.html?id=${linkId}#k=${fingerprint}`;
    },

    // Reads the fragment of a drop link: the fingerprint, null when there is none (old links), or
    // false when it is anything other than exactly "#k=<22 characters>"
    parseKeyFragment: function (hash) {
        if (!hash || hash === "#") return null;
        const match = /^#k=([A-Za-z0-9_-]{22})$/.exec(hash);
        return match ? match[1] : false;
    },

    // Drop attachments: the stored payload holds only the encrypted bytes and their IV. The name
    // travels separately as "enc:<iv>:<ciphertext>" and the type is never sent, so nothing readable
    // about the file reaches the server.
    encryptDropFile: async function (sessionKey, fileBuffer, fileName) {
        const body = await this.encryptSymmetric(sessionKey, fileBuffer);
        // Pad the name with NULs to a multiple of 256 bytes so its ciphertext does not reveal its length
        const nameBytes = new TextEncoder().encode(fileName);
        const paddedName = new Uint8Array(Math.max(256, Math.ceil(nameBytes.length / 256) * 256));
        paddedName.set(nameBytes);
        const name = await this.encryptSymmetric(sessionKey, paddedName);
        return {
            payload: JSON.stringify({ ciphertext: body.ciphertext, iv: body.iv }),
            encryptedName: `enc:${name.iv}:${name.ciphertext}`
        };
    },

    decryptDropFile: async function (sessionKey, payloadText) {
        const payload = JSON.parse(payloadText);
        return this.decryptSymmetric(sessionKey, payload.ciphertext, payload.iv);
    },

    // Name shown in the inbox and used for the download. Encrypted names are "enc:<iv>:<ciphertext>";
    // anything else was stored before names were encrypted.
    decryptDropName: async function (sessionKey, storedName) {
        const match = /^enc:([A-Za-z0-9+/]+=*):([A-Za-z0-9+/]+=*)$/.exec(String(storedName || ""));
        let name;
        if (match) {
            try {
                name = new TextDecoder().decode(await this.decryptSymmetric(sessionKey, match[2], match[1]));
            } catch (e) {
                return "encrypted-file";
            }
            name = name.replace(/\0+$/, "");
        } else {
            name = this.fixLatin1Name(String(storedName || ""));
        }
        return this.cleanFileName(name);
    },

    // Old plaintext names went through multer, which reads UTF-8 names as latin1 ("nÃ³minas")
    fixLatin1Name: function (name) {
        if (!/[\u0080-\u00ff]/.test(name) || /[^\u0000-\u00ff]/.test(name)) return name;
        try {
            return new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(name, c => c.charCodeAt(0)));
        } catch (e) {
            return name;
        }
    },

    // The sender chooses the name: drop invisible and bidi control characters (U+202E can show
    // "reportexe.pdf" for "report<U+202E>fdp.exe") and collapse whitespace used to push the real
    // extension out of view
    cleanFileName: function (name) {
        const cleaned = name.replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, "").replace(/\s+/gu, " ").trim();
        return cleaned || "file";
    },

    // Share downloads: only someone who unwrapped the file key with the password can compute this,
    // so holding the link alone cannot use up the download limit. The server stores the hash, which
    // reveals nothing about the 256-bit key. Must match server.js.
    SHARE_DOWNLOAD_PREFIX: "shadowdrop/share-download/v1",

    shareDownloadProof: async function (rawFileKey) {
        const prefix = new TextEncoder().encode(this.SHARE_DOWNLOAD_PREFIX);
        const key = new Uint8Array(rawFileKey);
        const combined = new Uint8Array(prefix.byteLength + key.byteLength);
        combined.set(prefix, 0);
        combined.set(key, prefix.byteLength);
        return this.bufferToBase64(await window.crypto.subtle.digest("SHA-256", combined));
    },

    // Legacy account migration: prove we hold the private key without becoming a decryption oracle.
    // The challenge is only decrypted under its own OAEP label, so ciphertexts made without it (package
    // session keys) fail here, and the server only gets back a hash of the nonce, never the plaintext.
    // Both strings must match server.js.
    MIGRATION_CHALLENGE_LABEL: "shadowdrop/migration-challenge/v1",
    MIGRATION_RESPONSE_PREFIX: "shadowdrop/migration-response/v1",

    answerMigrationChallenge: async function (privateKey, challengeBase64) {
        const encoder = new TextEncoder();
        const nonce = new Uint8Array(await window.crypto.subtle.decrypt(
            { name: "RSA-OAEP", label: encoder.encode(this.MIGRATION_CHALLENGE_LABEL) },
            privateKey,
            this.base64ToBuffer(challengeBase64)
        ));
        if (nonce.byteLength !== 32) throw new Error("Unexpected migration challenge");

        const prefix = encoder.encode(this.MIGRATION_RESPONSE_PREFIX);
        const combined = new Uint8Array(prefix.byteLength + nonce.byteLength);
        combined.set(prefix, 0);
        combined.set(nonce, prefix.byteLength);
        return this.bufferToBase64(await window.crypto.subtle.digest("SHA-256", combined));
    }
};
