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

    // Login salt from the server, checked before the password touches it: a malicious server could
    // send a short or degenerate salt so that the auth hashes it collects become precomputable. A
    // well-formed salt shared by every account cannot be told apart here: the pin below covers that
    checkLoginSalt: function (salt) {
        if (typeof salt !== "string" || !/^[A-Za-z0-9+/]{21}[AQgw]==$/.test(salt)) {
            throw new Error("The server sent an invalid login salt.");
        }
        const bytes = new Uint8Array(this.base64ToBuffer(salt));
        if (bytes.every(b => b === bytes[0])) throw new Error("The server sent an invalid login salt.");
        return bytes.buffer;
    },

    // Login parameters last used for a username in this browser (trust on first use). A change means
    // the password was changed elsewhere, or the server is substituting them. Stored under a hash of
    // the username (lower-cased: MySQL matches usernames without case); storage may be missing or
    // blocked, and the server itself can wipe it (Clear-Site-Data), so a missing pin is not proof
    loginPinKey: async function (username) {
        const digest = await window.crypto.subtle.digest("SHA-256", new TextEncoder().encode("shadowdrop/login-pin/v1|" + username.toLowerCase()));
        return "shadowdrop.login." + Array.from(new Uint8Array(digest).slice(0, 16), b => b.toString(16).padStart(2, "0")).join("");
    },

    pinnedLogin: async function (storage, username) {
        try {
            return storage.getItem(await this.loginPinKey(username));
        } catch (e) {
            return null;
        }
    },

    pinLogin: async function (storage, username, value) {
        try {
            storage.setItem(await this.loginPinKey(username), value);
        } catch (e) {
            // No storage: the next login from this browser is trusted on first use again
        }
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

    // The public half (n, e) of a private key: the user's own public key, read from the private key so
    // the server cannot substitute it
    publicKeyFromPkcs8: async function (base64Pkcs8) {
        const subtle = window.crypto.subtle;
        const params = { name: "RSA-OAEP", hash: "SHA-256" };
        const privateKey = await subtle.importKey("pkcs8", this.base64ToBuffer(base64Pkcs8), params, true, ["decrypt"]);
        const { n, e } = await subtle.exportKey("jwk", privateKey);
        return subtle.importKey("jwk", { kty: "RSA", n, e, alg: "RSA-OAEP-256", ext: true }, params, true, ["encrypt"]);
    },

    // The recipient computes it from their private key, which the server cannot forge
    fingerprintFromPkcs8: async function (base64Pkcs8) {
        const publicKey = await this.publicKeyFromPkcs8(base64Pkcs8);
        return this.publicKeyFingerprint(this.bufferToBase64(await window.crypto.subtle.exportKey("spki", publicKey)));
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

    // --- Drop packages, format 2 ---
    // Every AES-GCM ciphertext is bound to its role with associated data, so a server cannot move a
    // message, a name or a file body into another slot: the message carries a manifest of random file
    // ids, each name carries its file's id, and each body is bound to that id. Bodies travel as raw
    // bytes (IV || ciphertext), not base64. Format 1 packages (no AAD, JSON bodies) still open.
    DROP_V2: {
        SESSION_KEY_LABEL: "shadowdrop/drop/v2/session-key",
        MESSAGE: "shadowdrop/drop/v2/message",
        NAME: "shadowdrop/drop/v2/name",
        BODY: "shadowdrop/drop/v2/body/",
        MAX_FILES: 20, // same as the server's MAX_DROP_FILES
        MAX_MESSAGE_BYTES: 256 * 1024 // same as the server's MAX_MESSAGE_BYTES
    },

    // The sender name the way the server stores it (control characters removed, 64 characters), so the
    // copy sealed in the message can be compared with the one the inbox lists
    cleanSenderName: function (name) {
        return String(name ?? "").replace(/[\x00-\x1f\x7f]/g, "").trim().substring(0, 64);
    },

    aesGcmEncrypt: async function (key, data, aad) {
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const ciphertext = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv, additionalData: new TextEncoder().encode(aad) }, key, data);
        return { iv, ciphertext: new Uint8Array(ciphertext) };
    },

    aesGcmDecrypt: async function (key, iv, ciphertext, aad) {
        return window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv, additionalData: new TextEncoder().encode(aad) }, key, ciphertext);
    },

    // Pads with NULs to a multiple of 256 bytes so a ciphertext does not reveal the name's length
    padTo256: function (bytes) {
        const padded = new Uint8Array(Math.max(256, Math.ceil(bytes.length / 256) * 256));
        padded.set(bytes);
        return padded;
    },

    randomId: function () {
        return this.bufferToBase64(window.crypto.getRandomValues(new Uint8Array(16))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    },

    // Sender side: everything the server stores for one package. files: [{ name, data: ArrayBuffer }];
    // sender: the name the sender typed, sealed in the message so the server cannot change it unnoticed
    encryptDropPackage: async function (publicKey, text, files, sender) {
        const encoder = new TextEncoder();
        const sessionKey = await this.generateSessionKey();
        const rawKey = await window.crypto.subtle.exportKey("raw", sessionKey);
        const wrapped = await window.crypto.subtle.encrypt(
            { name: "RSA-OAEP", label: encoder.encode(this.DROP_V2.SESSION_KEY_LABEL) }, publicKey, rawKey);

        const ids = files.map(() => this.randomId());
        const message = await this.aesGcmEncrypt(sessionKey, encoder.encode(JSON.stringify({ text, sender: sender === undefined ? null : this.cleanSenderName(sender), files: ids })), this.DROP_V2.MESSAGE);

        const names = [];
        const bodies = [];
        for (let i = 0; i < files.length; i++) {
            const name = await this.aesGcmEncrypt(sessionKey,
                this.padTo256(encoder.encode(JSON.stringify({ name: files[i].name, id: ids[i] }))), this.DROP_V2.NAME);
            names.push(`enc2:${this.bufferToBase64(name.iv)}:${this.bufferToBase64(name.ciphertext)}`);
            const body = await this.aesGcmEncrypt(sessionKey, files[i].data, this.DROP_V2.BODY + ids[i]);
            const blob = new Uint8Array(12 + body.ciphertext.length);
            blob.set(body.iv, 0);
            blob.set(body.ciphertext, 12);
            bodies.push(blob);
        }
        return {
            format: 2,
            sessionKey,
            encryptedSessionKey: this.bufferToBase64(wrapped),
            encryptedMessage: this.bufferToBase64(message.ciphertext),
            messageIv: this.bufferToBase64(message.iv),
            names,
            bodies
        };
    },

    // Recipient side: session key and message of a package; fileIds is the sender's manifest and
    // sender the sealed sender name (both null for format 1, which has neither)
    openDropPackage: async function (privateKey, pkg) {
        const format = Number(pkg.format) === 2 ? 2 : 1;
        const params = format === 2
            ? { name: "RSA-OAEP", label: new TextEncoder().encode(this.DROP_V2.SESSION_KEY_LABEL) }
            : { name: "RSA-OAEP" };
        const rawKey = await window.crypto.subtle.decrypt(params, privateKey, this.base64ToBuffer(pkg.encrypted_session_key));
        const sessionKey = await this.importSessionKey(this.bufferToBase64(rawKey));
        if (format === 1) {
            const text = new TextDecoder().decode(await this.decryptSymmetric(sessionKey, pkg.encrypted_message, pkg.message_iv));
            return { format, sessionKey, text, sender: null, fileIds: null };
        }
        const plain = await this.aesGcmDecrypt(sessionKey, this.base64ToBuffer(pkg.message_iv),
            this.base64ToBuffer(pkg.encrypted_message), this.DROP_V2.MESSAGE);
        const { text, sender = null, files } = JSON.parse(new TextDecoder().decode(plain));
        if (typeof text !== "string" || (sender !== null && typeof sender !== "string")
            || !Array.isArray(files) || files.length > this.DROP_V2.MAX_FILES || files.some(id => typeof id !== "string")) {
            throw new Error("Malformed package");
        }
        return { format, sessionKey, text, sender, fileIds: files };
    },

    // Name and id of a stored file: "enc2:" (format 2), "enc:" (format 1) or a pre-encryption name.
    // In a format 2 package anything but "enc2:" was not written by the sender and is not shown
    decryptDropEntry: async function (sessionKey, storedName, format) {
        const match = /^enc2:([A-Za-z0-9+/]+=*):([A-Za-z0-9+/]+=*)$/.exec(String(storedName || ""));
        if (!match && Number(format) === 2) return { name: "encrypted-file", id: null };
        if (!match) return { name: await this.decryptDropName(sessionKey, storedName), id: null };
        try {
            const plain = await this.aesGcmDecrypt(sessionKey, this.base64ToBuffer(match[1]),
                this.base64ToBuffer(match[2]), this.DROP_V2.NAME);
            const entry = JSON.parse(new TextDecoder().decode(plain).replace(/\0+$/, ""));
            return { name: this.cleanFileName(String(entry.name)), id: String(entry.id) };
        } catch (e) {
            return { name: "encrypted-file", id: null };
        }
    },

    // Format 2: files the server lists vs the sender's encrypted manifest. Counts files the sender
    // attached that are missing, and files listed that the sender did not attach (or listed twice).
    manifestProblems: function (fileIds, listedIds) {
        if (!fileIds) return { missing: 0, unexpected: 0 };
        return {
            missing: fileIds.filter(id => !listedIds.includes(id)).length,
            unexpected: listedIds.filter((id, i) => !id || !fileIds.includes(id) || listedIds.indexOf(id) !== i).length
        };
    },

    // Format 2: what the server lists against what was sealed in the package. Worded neutrally: the
    // sender writes the manifest too, so a mismatch does not say who changed what
    packageWarning: function (opened, listedIds, listedSender) {
        if (!opened.fileIds) return null;
        const { missing, unexpected } = this.manifestProblems(opened.fileIds, listedIds);
        const parts = [];
        if (missing) parts.push(`${missing} attachment(s) in the sealed list are missing`);
        if (unexpected) parts.push(`${unexpected} attachment(s) are not in the sealed list`);
        if (opened.sender !== null && opened.sender !== (listedSender || "")) parts.push("the sender name listed in the inbox is not the sealed one");
        return parts.length ? `This package does not match what was sealed when it was sent: ${parts.join("; ")}.` : null;
    },

    // Decrypted bytes of a stored file body
    decryptDropBody: async function (sessionKey, bodyBuffer, format, fileId) {
        if (Number(format) === 2) {
            const bytes = new Uint8Array(bodyBuffer);
            if (!fileId || bytes.length < 28) throw new Error("Malformed file");
            return this.aesGcmDecrypt(sessionKey, bytes.slice(0, 12), bytes.slice(12), this.DROP_V2.BODY + fileId);
        }
        const payload = JSON.parse(new TextDecoder().decode(bodyBuffer));
        return this.decryptSymmetric(sessionKey, payload.ciphertext, payload.iv);
    },

    // Format 1 names: "enc:<iv>:<ciphertext>"; anything else was stored before names were encrypted
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
    },

    // --- Shares, format 2 ---
    // The file name is sealed with a name key derived from the share's file key (HKDF), so neither the
    // server nor whoever holds the link learns it before the password. The owner keeps only that name
    // key, wrapped with their own public key (under its own OAEP label), to list their shares by name:
    // someone who takes over the account learns the names, not the contents.
    SHARE_V2: {
        NAME: "shadowdrop/share/v2/name",
        NAME_KEY_INFO: "shadowdrop/share/v2/name-key",
        OWNER_KEY_LABEL: "shadowdrop/share/v2/owner-name-key"
    },

    // Raw bytes of the name key derived from the raw file key
    shareNameKeyBytes: async function (rawFileKey) {
        const base = await window.crypto.subtle.importKey("raw", rawFileKey, "HKDF", false, ["deriveBits"]);
        return window.crypto.subtle.deriveBits(
            { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: new TextEncoder().encode(this.SHARE_V2.NAME_KEY_INFO) }, base, 256);
    },

    importShareNameKey: function (rawNameKey, usages) {
        return window.crypto.subtle.importKey("raw", rawNameKey, { name: "AES-GCM" }, false, usages);
    },

    sealShareName: async function (rawFileKey, name) {
        const nameKey = await this.importShareNameKey(await this.shareNameKeyBytes(rawFileKey), ["encrypt"]);
        const sealed = await this.aesGcmEncrypt(nameKey,
            this.padTo256(new TextEncoder().encode(JSON.stringify({ name }))), this.SHARE_V2.NAME);
        return `enc2:${this.bufferToBase64(sealed.iv)}:${this.bufferToBase64(sealed.ciphertext)}`;
    },

    // The sealed name, or "encrypted-file" when it does not open with this name key
    openSealedShareName: async function (nameKey, sealed) {
        const match = /^enc2:([A-Za-z0-9+/]+=*):([A-Za-z0-9+/]+=*)$/.exec(String(sealed || ""));
        try {
            const plain = await this.aesGcmDecrypt(nameKey, this.base64ToBuffer(match[1]),
                this.base64ToBuffer(match[2]), this.SHARE_V2.NAME);
            return this.cleanFileName(String(JSON.parse(new TextDecoder().decode(plain).replace(/\0+$/, "")).name));
        } catch (e) {
            return "encrypted-file";
        }
    },

    // Link side, after the password: the name from the raw file key
    openShareName: async function (rawFileKey, sealed) {
        return this.openSealedShareName(await this.importShareNameKey(await this.shareNameKeyBytes(rawFileKey), ["decrypt"]), sealed);
    },

    wrapShareNameKeyForOwner: async function (ownerPublicKey, rawFileKey) {
        const wrapped = await window.crypto.subtle.encrypt(
            { name: "RSA-OAEP", label: new TextEncoder().encode(this.SHARE_V2.OWNER_KEY_LABEL) }, ownerPublicKey, await this.shareNameKeyBytes(rawFileKey));
        return this.bufferToBase64(wrapped);
    },

    // Owner side: the name of one of their format 2 shares
    ownerShareName: async function (privateKey, wrappedNameKey, sealed) {
        try {
            const raw = await window.crypto.subtle.decrypt(
                { name: "RSA-OAEP", label: new TextEncoder().encode(this.SHARE_V2.OWNER_KEY_LABEL) }, privateKey, this.base64ToBuffer(wrappedNameKey));
            return this.openSealedShareName(await this.importShareNameKey(raw, ["decrypt"]), sealed);
        } catch (e) {
            return "encrypted-file";
        }
    }
};
