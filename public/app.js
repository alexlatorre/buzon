// app.js - Receiver Dashboard Logic

// Global State
let currentUser = {
    id: null,
    masterKey: null,
    privateKey: null
};

let currentPackages = [];
let selectedPackage = null;
let currentPackageSessionKey = null;

// DOM Elements
const authPanel = document.getElementById('auth-panel');
const dashPanel = document.getElementById('dashboard-panel');
const sysStatus = document.getElementById('system-status');
const authMsg = document.getElementById('auth-msg');
const dropLink = document.getElementById('drop-link');
const togglePublicLink = document.getElementById('toggle-public-link');
const btnGenOTL = document.getElementById('btn-gen-otl');
const otlListUI = document.getElementById('otl-list');
const pkgList = document.getElementById('package-list');

// Buttons
const btnLogin = document.getElementById('btn-login');
const btnRegister = document.getElementById('btn-register');
const btnLogout = document.getElementById('btn-logout');
const btnRefresh = document.getElementById('btn-refresh');

// Modal
const modal = document.getElementById('package-modal');
const btnCloseModal = document.getElementById('btn-close-modal');
const btnDownloadAll = document.getElementById('btn-download-all');
const btnDestroy = document.getElementById('btn-destroy');

function showMsg(msg, type = 'info') {
    authMsg.textContent = msg;
    authMsg.className = `msg ${type}`;
}

async function handleRegister() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;

    if (!username || password.length < 8) return showMsg('Username and password (min 8) required.', 'error');

    try {
        showMsg('Generating RSA-4096 key pair... (might take a few seconds)', 'info');

        // 1. Generate Salt and derive Master Key
        const saltBase64 = CryptoUtils.generateSalt();
        const saltBuffer = CryptoUtils.base64ToBuffer(saltBase64);
        const masterKey = await CryptoUtils.deriveMasterKey(password, saltBuffer);

        // 2. Generate RSA Key Pair
        const keyPair = await CryptoUtils.generateRSAKeyPair();
        const pubKeyBase64 = await CryptoUtils.exportPublicKey(keyPair.publicKey);
        const privKeyBase64 = await CryptoUtils.exportPrivateKey(keyPair.privateKey);

        // 3. Encrypt Private Key with Master Key
        const privKeyBuffer = new TextEncoder().encode(privKeyBase64);
        const encryptedPrivResult = await CryptoUtils.encryptSymmetric(masterKey, privKeyBuffer);

        // 4. Send to Server
        showMsg('Uploading vault to server...', 'info');
        const res = await fetch('/api/auth/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username,
                salt: saltBase64,
                publicKey: pubKeyBase64,
                encryptedPrivateKey: encryptedPrivResult.ciphertext,
                iv: encryptedPrivResult.iv
            })
        });

        const data = await res.json();
        if (res.ok) {
            showMsg('Vault created. You may now login.', 'success');
            document.getElementById('password').value = ''; // clear for safety
        } else {
            showMsg('Error: ' + data.error, 'error');
        }

    } catch (error) {
        console.error(error);
        showMsg('Crypto failure during registration.', 'error');
    }
}

async function handleLogin() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;

    if (!username || !password) return showMsg('Username and password required.', 'error');

    try {
        showMsg('Authenticating...', 'info');

        // 1. Fetch encrypted details from server
        const res = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });

        const data = await res.json();
        if (!res.ok) throw new Error(data.error);

        // 2. Derive Master Key
        showMsg('Deriving master key...', 'info');
        const saltBuffer = CryptoUtils.base64ToBuffer(data.salt);
        const masterKey = await CryptoUtils.deriveMasterKey(password, saltBuffer);

        // 3. Decrypt Private Key
        showMsg('Decrypting private key in memory...', 'info');
        let privKeyBuffer;
        try {
            console.log("MasterKey used:", masterKey);
            console.log("EncPrivKey base64 length:", data.encryptedPrivateKey.length);
            console.log("IV base64:", data.iv);
            privKeyBuffer = await CryptoUtils.decryptSymmetric(masterKey, data.encryptedPrivateKey, data.iv);
            console.log("Decrypted privKeyBuffer byteLength:", privKeyBuffer.byteLength);
        } catch (e) {
            console.error("AES Decryption Error:", e);
            throw new Error('Invalid master password.');
        }

        const privKeyBase64 = new TextDecoder().decode(privKeyBuffer);
        const privateKey = await CryptoUtils.importPrivateKey(privKeyBase64);

        // 4. Setup Global state and transition
        currentUser = {
            id: data.id,
            masterKey,
            privateKey
        };

        const dropUrl = `${window.location.protocol}//${window.location.host}/drop.html?id=${data.id}`;
        dropLink.href = dropUrl;
        dropLink.textContent = dropUrl;

        authPanel.classList.remove('active');
        authPanel.classList.add('hidden');
        dashPanel.classList.remove('hidden');
        dashPanel.classList.add('active');

        sysStatus.textContent = 'System: Online';
        sysStatus.className = 'status-online';

        fetchPackages();
        updateQuotaDisplay(); // Fetch quota and config on login
        fetchOneTimeLinks(); // Fetch OTLs on login

    } catch (error) {
        console.error(error);
        showMsg(error.message, 'error');
    }
}

function secureLogout() {
    try {
        // 1. Wipe sensitive keys from memory
        currentUser = {
            id: null,
            masterKey: null,
            privateKey: null
        };
        currentPackages = [];
        selectedPackage = null;
        currentPackageSessionKey = null;

        // 2. Clear form fields
        document.getElementById('password').value = '';
        document.getElementById('username').value = '';

        // 3. Switch panels
        dashPanel.classList.remove('active');
        dashPanel.classList.add('hidden');
        authPanel.classList.remove('hidden');
        authPanel.classList.add('active');

        // 4. Update status
        sysStatus.textContent = 'System: Offline';
        sysStatus.className = 'status-offline';
        showMsg('Vault locked and memory wiped.', 'info');
        closeModal();
    } catch (e) {
        // Force logout even if something fails
        console.error('Logout error:', e);
        window.location.reload();
    }
}

async function fetchPackages() {
    if (!currentUser.id) return;

    btnRefresh.textContent = 'Scanning...';
    try {
        const res = await fetch(`/api/packages/${currentUser.id}`);
        const data = await res.json();
        if (res.ok) {
            currentPackages = data;
            renderPackages();
        }
    } catch (e) {
        console.error('Error fetching packages', e);
    }
    btnRefresh.textContent = 'Refresh Inbox';
}

function renderPackages() {
    pkgList.innerHTML = '';
    if (currentPackages.length === 0) {
        pkgList.innerHTML = `
            <div class="empty-state">
                <p class="text-muted">No secure packages found in your vault.</p>
            </div>
        `;
        return;
    }

    currentPackages.forEach(pkg => {
        const date = new Date(pkg.created_at);
        const formattedDate = date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
        const formattedTime = date.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });

        const div = document.createElement('div');
        div.className = 'package-item';
        div.onclick = () => openPackage(pkg.id);

        div.innerHTML = `
            <div class="package-avatar">
                <span class="avatar-icon">✉</span>
            </div>
            <div class="package-info">
                <div class="package-header">
                    <span class="package-sender">${pkg.sender_email}</span>
                    <span class="package-date">${formattedDate} at ${formattedTime}</span>
                </div>
                <div class="package-subheader">
                    <span class="package-message-peek">Encrypted message (E2E)</span>
                    <span class="package-files-count">
                        <svg class="icon-file" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path>
                            <polyline points="13 2 13 9 20 9"></polyline>
                        </svg>
                        ${pkg.files.length} file${pkg.files.length !== 1 ? 's' : ''}
                    </span>
                </div>
            </div>
            <div class="package-actions">
                <span class="chevron-right">›</span>
            </div>
        `;
        pkgList.appendChild(div);
    });
}

async function openPackage(id) {
    const pkg = currentPackages.find(p => p.id === id);
    if (!pkg) return;

    selectedPackage = pkg;
    try {
        // 1. Decrypt Session Key using RSA Private Key
        const sessionKeyBuffer = await CryptoUtils.decryptAsymmetric(currentUser.privateKey, pkg.encrypted_session_key);
        // 2. Import Session Key
        const sessionKeyBase64 = CryptoUtils.bufferToBase64(sessionKeyBuffer);
        currentPackageSessionKey = await CryptoUtils.importSessionKey(sessionKeyBase64);

        // 3. Decrypt Message using Session Key
        const msgBuffer = await CryptoUtils.decryptSymmetric(currentPackageSessionKey, pkg.encrypted_message, pkg.message_iv);
        const message = new TextDecoder().decode(msgBuffer);

        // 4. Fill Modal
        document.getElementById('modal-sender').textContent = pkg.sender_email;
        document.getElementById('modal-date').textContent = new Date(pkg.created_at).toLocaleString();
        document.getElementById('modal-message').textContent = message;

        const fileList = document.getElementById('modal-files');
        fileList.innerHTML = '';

        if (pkg.files.length === 0) {
            fileList.innerHTML = '<li>No attachments</li>';
            btnDownloadAll.style.display = 'none';
        } else {
            pkg.files.forEach(f => {
                const li = document.createElement('li');
                li.className = 'modal-file-item';

                const fileInfo = document.createElement('div');
                fileInfo.className = 'modal-file-info';
                fileInfo.innerHTML = `
                    <span class="file-icon">📄</span>
                    <span class="file-name">${f.original_name}</span>
                    <span class="file-size">(${(f.size / 1024).toFixed(2)} KB)</span>
                `;

                const downloadBtn = document.createElement('button');
                downloadBtn.className = 'btn-icon-download';
                downloadBtn.innerHTML = '↓';
                downloadBtn.title = 'Download this file';
                downloadBtn.onclick = () => downloadFile(f);

                li.appendChild(fileInfo);
                li.appendChild(downloadBtn);
                fileList.appendChild(li);
            });
            btnDownloadAll.style.display = 'block';
            btnDownloadAll.textContent = 'Decrypt & Download All';
        }

        modal.classList.remove('hidden');

    } catch (error) {
        console.error(error);
        alert('Error: Failed to decrypt package. Invalid key or corrupted data.');
    }
}

function closeModal() {
    modal.classList.add('hidden');
    selectedPackage = null;
    currentPackageSessionKey = null;
}

async function destroyPackage() {
    if (!selectedPackage) return;

    btnDestroy.textContent = 'Destroying...';
    try {
        const res = await fetch(`/api/package/${selectedPackage.id}`, { method: 'DELETE' });
        if (res.ok) {
            closeModal();
            await fetchPackages(); // Ensure packages are re-fetched and rendered
            updateQuotaDisplay(); // Update quota after packages are rendered
        }
    } catch (error) {
        console.error(error);
        alert('Failed to destroy package');
    }
    btnDestroy.textContent = 'Destroy Package';
}

async function updateQuotaDisplay() {
    if (!currentUser) return;
    try {
        const res = await fetch(`/api/user/${currentUser.id}/quota`);
        const data = await res.json();
        if (res.ok) {
            const usageMB = (data.usage / (1024 * 1024)).toFixed(1);
            const quotaMB = (data.quota / (1024 * 1024)).toFixed(0);
            const percent = Math.min(100, (data.usage / data.quota) * 100);

            const fill = document.getElementById('quota-fill');
            const quotaText = document.getElementById('quota-text');

            if (fill) fill.style.width = `${percent}%`;
            if (quotaText) quotaText.textContent = `${usageMB} / ${quotaMB} MB used`;

            // Set toggle state
            if (togglePublicLink) {
                togglePublicLink.checked = data.publicLinkEnabled;
                dropLink.parentElement.style.opacity = data.publicLinkEnabled ? '1' : '0.4';
                dropLink.style.pointerEvents = data.publicLinkEnabled ? 'auto' : 'none';
            }

            // Color feedback
            if (fill) {
                if (percent > 90) fill.style.background = 'var(--danger-color)';
                else if (percent > 70) fill.style.background = '#ff9500'; // Orange
                else fill.style.background = 'var(--accent-color)';
            }
        }
    } catch (e) {
        console.error('Failed to update quota display', e);
    }
}

async function downloadFile(f) {
    if (!selectedPackage || !currentPackageSessionKey) return;

    try {
        const res = await fetch(`/api/package/${selectedPackage.id}/file/${f.id}`);
        if (!res.ok) throw new Error('Download failed');

        const fileBlob = await res.blob();
        const fileBuffer = await fileBlob.arrayBuffer();

        const jsonStr = new TextDecoder().decode(fileBuffer);
        const payload = JSON.parse(jsonStr);

        const decryptedBuffer = await CryptoUtils.decryptSymmetric(currentPackageSessionKey, payload.ciphertext, payload.iv);

        // Metadata restoration
        const resolvedFilename = payload.filename || f.original_name;
        const resolvedMime = payload.mimeType || f.mime_type || 'application/octet-stream';

        const decBlob = new Blob([decryptedBuffer], { type: resolvedMime });
        const url = URL.createObjectURL(decBlob);
        const a = document.createElement('a');
        a.href = url;
        a.download = resolvedFilename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
    } catch (e) {
        console.error(e);
        alert(`Failed to decrypt file: ${f.original_name}`);
    }
}

async function downloadFiles() {
    if (!selectedPackage || !currentPackageSessionKey) return;

    btnDownloadAll.textContent = 'Decrypting...';
    // Download each file, decrypt it and trigger download in browser
    for (let i = 0; i < selectedPackage.files.length; i++) {
        await downloadFile(selectedPackage.files[i]);
    }

    btnDownloadAll.textContent = 'Decrypt & Download All';

    // Auto destroy after successful download
    if (confirm("Files downloaded. Do you want to destroy the package from the server now?")) {
        destroyPackage();
    }
}

// Event Listeners
btnRegister.addEventListener('click', handleRegister);
btnLogin.addEventListener('click', handleLogin);
btnLogout.addEventListener('click', secureLogout);
btnRefresh.addEventListener('click', fetchPackages);
btnCloseModal.addEventListener('click', closeModal);
btnDestroy.addEventListener('click', destroyPackage);
btnDownloadAll.addEventListener('click', downloadFiles);

dropLink.addEventListener('click', (e) => {
    e.preventDefault();
    const url = dropLink.href;
    navigator.clipboard.writeText(url).then(() => {
        const originalText = dropLink.textContent;
        dropLink.textContent = 'Copied to clipboard!';
        dropLink.style.color = '#34c759';
        setTimeout(() => {
            dropLink.textContent = originalText;
            dropLink.style.color = '';
        }, 2000);
    }).catch(err => {
        console.error('Failed to copy: ', err);
    });
});

// Link Management Logic
togglePublicLink.addEventListener('change', async () => {
    if (!currentUser) return;
    try {
        const enabled = togglePublicLink.checked;
        await fetch(`/api/user/${currentUser.id}/config`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ publicLinkEnabled: enabled })
        });
        updateQuotaDisplay(); // Refresh UI bits
    } catch (e) {
        console.error('Failed to toggle public link', e);
    }
});

btnGenOTL.addEventListener('click', async () => {
    if (!currentUser) return;
    try {
        const res = await fetch(`/api/user/${currentUser.id}/one-time-link`, { method: 'POST' });
        const data = await res.json();
        if (res.ok) {
            fetchOneTimeLinks();
        }
    } catch (e) {
        console.error('Failed to generate OTL', e);
    }
});

async function fetchOneTimeLinks() {
    if (!currentUser) return;
    try {
        const res = await fetch(`/api/user/${currentUser.id}/one-time-links`);
        const links = await res.json();
        if (res.ok) {
            renderOneTimeLinks(links);
        }
    } catch (e) {
        console.error('Failed to fetch OTLs', e);
    }
}

function renderOneTimeLinks(links) {
    otlListUI.innerHTML = '';
    if (links.length === 0) {
        otlListUI.innerHTML = '<div class="quota-label" style="text-align:center; padding:10px;">No active tokens</div>';
        return;
    }

    links.forEach(l => {
        const item = document.createElement('div');
        item.className = 'otl-item';
        item.innerHTML = `
            <span class="otl-token" title="Click to copy">${l.token.substring(0, 14)}...</span>
            <div class="otl-actions">
                <button class="btn-icon-mini copy-otl" title="Copy Link">📋</button>
                <button class="btn-icon-mini delete-otl" title="Delete Token">×</button>
            </div>
        `;

        // Copy functionality
        item.querySelector('.copy-otl').onclick = (e) => {
            e.stopPropagation();
            const url = `${window.location.origin}/drop.html?id=${l.token}`;
            navigator.clipboard.writeText(url).then(() => {
                const btn = item.querySelector('.copy-otl');
                btn.textContent = "✓";
                setTimeout(() => btn.textContent = "📋", 1500);
            });
        };

        // Delete functionality
        item.querySelector('.delete-otl').onclick = async (e) => {
            e.stopPropagation();
            if (confirm("Delete this one-time link?")) {
                try {
                    const res = await fetch(`/api/user/${currentUser.id}/one-time-link/${l.token}`, { method: 'DELETE' });
                    if (res.ok) fetchOneTimeLinks();
                } catch (err) {
                    console.error('Failed to delete OTL', err);
                }
            }
        };

        otlListUI.appendChild(item);
    });
}

// Boss Key (Double ESC)
let escCount = 0;
let escTimer = null;
window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        escCount++;
        if (escCount >= 2) {
            secureLogout();
            escCount = 0;
        }
        clearTimeout(escTimer);
        escTimer = setTimeout(() => { escCount = 0; }, 500);
    }
});
