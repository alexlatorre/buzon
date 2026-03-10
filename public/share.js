// share.js — Secure File Share Download Logic
// Uses PBKDF2 + AES-GCM to decrypt shared files in the browser.

(function () {
    const TOKEN = new URLSearchParams(window.location.search).get('token');

    const loadingEl = document.getElementById('share-loading');
    const errorEl = document.getElementById('share-error');
    const errorMsg = document.getElementById('share-error-msg');
    const formEl = document.getElementById('share-form');
    const successEl = document.getElementById('share-success');
    const filenameEl = document.getElementById('share-filename');
    const filesizeEl = document.getElementById('share-filesize');
    const messageBoxEl = document.getElementById('share-message-box');
    const messageEl = document.getElementById('share-message');
    const limitsEl = document.getElementById('share-limits');
    const passwordInput = document.getElementById('share-password');
    const btnDownload = document.getElementById('btn-share-download');
    const msgEl = document.getElementById('share-msg');

    let shareMeta = null;

    function showMsg(msg, type = 'info') {
        msgEl.textContent = msg;
        msgEl.className = `msg ${type}`;
    }

    function formatSize(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / 1048576).toFixed(1) + ' MB';
    }

    function showError(msg) {
        loadingEl.classList.add('hidden');
        formEl.classList.add('hidden');
        errorEl.classList.remove('hidden');
        errorMsg.textContent = msg;
    }

    function showForm() {
        loadingEl.classList.add('hidden');
        formEl.classList.remove('hidden');
    }

    // Base64 helpers
    function base64ToBuffer(b64) {
        const bin = atob(b64);
        const buf = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
        return buf;
    }

    function bufferToBase64(buf) {
        const bytes = new Uint8Array(buf);
        let bin = '';
        for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
        return btoa(bin);
    }

    // Derive AES key from password + salt using PBKDF2
    async function deriveKey(password, saltB64) {
        const enc = new TextEncoder();
        const salt = base64ToBuffer(saltB64);
        const keyMaterial = await window.crypto.subtle.importKey(
            'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
        );
        return window.crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['decrypt']
        );
    }

    // Decrypt AES-GCM
    async function decryptAES(key, ciphertextB64, ivB64) {
        const iv = base64ToBuffer(ivB64);
        const ciphertext = base64ToBuffer(ciphertextB64);
        return window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            key,
            ciphertext
        );
    }

    // Load share metadata
    async function loadMeta() {
        if (!TOKEN) return showError('No se especificó un token de descarga.');

        try {
            const res = await fetch(`/api/share/${TOKEN}/meta`);
            const data = await res.json();

            if (!res.ok) {
                return showError(data.error || 'Enlace no disponible');
            }

            shareMeta = data;

            // Show file info
            filenameEl.textContent = data.originalName;
            filesizeEl.textContent = formatSize(data.size);

            // Show limits info
            let limitsHtml = '';
            if (data.maxDownloads > 0) {
                const remaining = data.maxDownloads - data.downloadCount;
                limitsHtml += `<span class="share-limit-item">📥 ${remaining} descarga${remaining !== 1 ? 's' : ''} restante${remaining !== 1 ? 's' : ''}</span>`;
            }
            if (data.expiresAt) {
                const expDate = new Date(data.expiresAt);
                const now = new Date();
                const hoursLeft = Math.max(0, Math.round((expDate - now) / 3600000));
                if (hoursLeft <= 24) {
                    limitsHtml += `<span class="share-limit-item">⏰ Expira en ${hoursLeft}h</span>`;
                } else {
                    const daysLeft = Math.round(hoursLeft / 24);
                    limitsHtml += `<span class="share-limit-item">⏰ Expira en ${daysLeft} día${daysLeft !== 1 ? 's' : ''}</span>`;
                }
            }
            if (limitsHtml) limitsEl.innerHTML = limitsHtml;

            showForm();
        } catch (e) {
            console.error(e);
            showError('Error de conexión al servidor.');
        }
    }

    // Decrypt and download
    async function handleDownload() {
        const password = passwordInput.value;
        if (!password) return showMsg('Introduce la contraseña de desbloqueo.', 'error');
        if (!shareMeta) return;

        btnDownload.disabled = true;
        btnDownload.textContent = '🔐 Derivando clave...';
        showMsg('', 'info');

        try {
            // 1. Derive key from password
            const derivedKey = await deriveKey(password, shareMeta.salt);

            // 2. Decrypt the AES file key
            btnDownload.textContent = '🔑 Descifrando clave...';
            let fileKeyRaw;
            try {
                fileKeyRaw = await decryptAES(derivedKey, shareMeta.encryptedFileKey, shareMeta.keyIv);
            } catch (e) {
                btnDownload.disabled = false;
                btnDownload.textContent = '🔓 Descifrar y Descargar';
                return showMsg('Contraseña incorrecta.', 'error');
            }

            // 3. Import the file key
            const fileKey = await window.crypto.subtle.importKey(
                'raw', fileKeyRaw, { name: 'AES-GCM' }, false, ['decrypt']
            );

            // 4. Download the encrypted file
            btnDownload.textContent = '📥 Descargando fichero cifrado...';
            const fileRes = await fetch(`/api/share/${TOKEN}/download`);
            if (!fileRes.ok) {
                const errData = await fileRes.json().catch(() => ({}));
                throw new Error(errData.error || 'Error descargando fichero');
            }
            const encryptedBlob = await fileRes.arrayBuffer();

            // 5. Decrypt the file
            btnDownload.textContent = '🔓 Descifrando fichero...';
            const fileIv = base64ToBuffer(shareMeta.fileIv);
            const decryptedBuffer = await window.crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: fileIv },
                fileKey,
                encryptedBlob
            );

            // 6. Decrypt message if present
            if (shareMeta.encryptedMessage && shareMeta.messageIv) {
                try {
                    const msgBuffer = await decryptAES(derivedKey, shareMeta.encryptedMessage, shareMeta.messageIv);
                    const message = new TextDecoder().decode(msgBuffer);
                    if (message) {
                        messageEl.textContent = message;
                        messageBoxEl.classList.remove('hidden');
                    }
                } catch (e) {
                    // Message decryption failed — not critical
                    console.warn('Could not decrypt message:', e);
                }
            }

            // 7. Trigger download
            const blob = new Blob([decryptedBuffer], { type: shareMeta.mimeType || 'application/octet-stream' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = shareMeta.originalName;
            document.body.appendChild(a);
            a.click();
            a.remove();
            URL.revokeObjectURL(url);

            // Show success
            formEl.classList.add('hidden');
            successEl.classList.remove('hidden');

        } catch (error) {
            console.error('Download error:', error);
            showMsg(error.message || 'Error al descifrar el archivo.', 'error');
            btnDownload.disabled = false;
            btnDownload.textContent = '🔓 Descifrar y Descargar';
        }
    }

    // Event listeners
    btnDownload.addEventListener('click', handleDownload);
    passwordInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') handleDownload();
    });

    // Init
    loadMeta();
})();
