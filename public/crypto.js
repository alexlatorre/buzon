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
    deriveMasterKey: async function (password, saltBuffer) {
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
            true,
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
            true,
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
            true,
            ["encrypt", "decrypt"]
        );
    }
};
