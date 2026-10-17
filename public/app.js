// app.js - Receiver Dashboard Logic

// Global State
let currentUser = {
    id: null,
    masterKey: null,
    privateKey: null,
    sessionToken: null
};

let currentPackages = [];
let selectedPackage = null;

// SQLite returns "YYYY-MM-DD HH:MM:SS" in UTC without a zone marker; read it as UTC, not local time
function parseServerDate(value) {
    if (typeof value === 'string' && /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(value)) {
        return new Date(value.replace(' ', 'T') + 'Z');
    }
    return new Date(value);
}

// Dates are always shown as yyyy/mm/dd HH:MM (24h, local time)
function formatDateTime(date, withSeconds = false) {
    const pad = n => String(n).padStart(2, '0');
    const day = `${date.getFullYear()}/${pad(date.getMonth() + 1)}/${pad(date.getDate())}`;
    const time = `${pad(date.getHours())}:${pad(date.getMinutes())}` + (withSeconds ? `:${pad(date.getSeconds())}` : '');
    return `${day} ${time}`;
}
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

        // 2. Compute Server Auth Hash
        const serverAuthHash = await CryptoUtils.computeServerAuthHash(masterKey);

        // 3. Generate RSA Key Pair
        const keyPair = await CryptoUtils.generateRSAKeyPair();
        const pubKeyBase64 = await CryptoUtils.exportPublicKey(keyPair.publicKey);
        const privKeyBase64 = await CryptoUtils.exportPrivateKey(keyPair.privateKey);

        // 4. Encrypt Private Key with Master Key
        const privKeyBuffer = new TextEncoder().encode(privKeyBase64);
        const encryptedPrivResult = await CryptoUtils.encryptSymmetric(masterKey, privKeyBuffer);

        // 5. Send to Server
        showMsg('Uploading vault to server...', 'info');
        const res = await fetch('/api/auth/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username,
                salt: saltBase64,
                publicKey: pubKeyBase64,
                encryptedPrivateKey: encryptedPrivResult.ciphertext,
                iv: encryptedPrivResult.iv,
                serverAuthHash: serverAuthHash
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

// Decrypts the stored PKCS8 private key with the password-derived master key
async function decryptPrivateKey(masterKey, encryptedPrivateKey, iv) {
    let privKeyBuffer;
    try {
        privKeyBuffer = await CryptoUtils.decryptSymmetric(masterKey, encryptedPrivateKey, iv);
    } catch (e) {
        throw new Error('Invalid master password.');
    }
    return CryptoUtils.importPrivateKey(new TextDecoder().decode(privKeyBuffer));
}

async function postLogin(body) {
    const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Invalid credentials');
    return data;
}

async function handleLogin() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;

    if (!username || !password) return showMsg('Username and password required.', 'error');

    try {
        showMsg('Authenticating...', 'info');

        // 1. Fetch user salt from server
        const saltRes = await fetch(`/api/auth/salt/${encodeURIComponent(username)}`);
        const saltData = await saltRes.json();

        if (!saltRes.ok) throw new Error('Invalid credentials'); // Mask user existence

        // 2. Derive Master Key and Server Auth Hash
        showMsg('Deriving master key...', 'info');
        const saltBuffer = CryptoUtils.base64ToBuffer(saltData.salt);
        const masterKey = await CryptoUtils.deriveMasterKey(password, saltBuffer);
        const serverAuthHash = await CryptoUtils.computeServerAuthHash(masterKey);

        // 3. Authenticate with server using Server Auth Hash
        showMsg('Verifying credentials...', 'info');
        let data = await postLogin({ username, serverAuthHash });

        // Legacy account: prove we hold the private key so the server accepts our auth hash
        if (data.migrationRequired) {
            showMsg('Upgrading legacy account...', 'info');
            const legacyKey = await decryptPrivateKey(masterKey, data.encryptedPrivateKey, data.iv);
            let challengeResponse;
            try {
                challengeResponse = await CryptoUtils.answerMigrationChallenge(legacyKey, data.challenge);
            } catch (e) {
                throw new Error('Could not verify the legacy account upgrade.');
            }
            data = await postLogin({ username, serverAuthHash, challengeId: data.challengeId, challengeResponse });
            // Expired challenge or server restart between the two steps: ask the user to try again
            if (!data.sessionToken) throw new Error('Could not verify the legacy account upgrade. Please try again.');
        }

        // 4. Decrypt Private Key
        showMsg('Decrypting private key in memory...', 'info');
        const privateKey = await decryptPrivateKey(masterKey, data.encryptedPrivateKey, data.iv);

        // 4. Setup Global state and transition
        currentUser = {
            id: data.id,
            masterKey,
            privateKey,
            sessionToken: data.sessionToken
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
        fetchShares();

    } catch (error) {
        console.error(error);
        showMsg(error.message, 'error');
    }
}

function secureLogout() {
    try {
        // Call logout API
        if (currentUser && currentUser.sessionToken) {
            fetch('/api/auth/logout', {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${currentUser.sessionToken}` }
            }).catch(e => console.error('Logout API error', e));
        }

        // 1. Wipe sensitive keys from memory
        currentUser = {
            id: null,
            masterKey: null,
            privateKey: null,
            sessionToken: null
        };
        currentPackages = [];
        selectedPackage = null;
        currentPackageSessionKey = null;
        shareListUI.replaceChildren();

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
        const res = await fetch(`/api/packages/${currentUser.id}`, {
            headers: { 'Authorization': `Bearer ${currentUser.sessionToken}` }
        });
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
        const formattedDate = formatDateTime(parseServerDate(pkg.created_at));

        const div = document.createElement('div');
        div.className = 'package-item';
        div.onclick = () => openPackage(pkg.id);

        div.innerHTML = `
            <div class="package-avatar">
                <span class="avatar-icon">✉</span>
            </div>
            <div class="package-info">
                <div class="package-header">
                    <span class="package-sender"></span>
                    <span class="package-date">${formattedDate}</span>
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
        // Sender name is chosen by whoever dropped the package: never parse it as HTML
        div.querySelector('.package-sender').textContent = pkg.sender_name || 'Anonymous';
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
        document.getElementById('modal-sender').textContent = pkg.sender_name || 'Anonymous';
        document.getElementById('modal-date').textContent = formatDateTime(parseServerDate(pkg.created_at), true);
        document.getElementById('modal-message').textContent = message;

        const fileList = document.getElementById('modal-files');
        fileList.innerHTML = '';

        if (pkg.files.length === 0) {
            fileList.innerHTML = '<li>No attachments</li>';
            btnDownloadAll.style.display = 'none';
        } else {
            for (const f of pkg.files) {
                f.displayName = await decryptFileName(f.original_name);
            }
            pkg.files.forEach(f => {
                const li = document.createElement('li');
                li.className = 'modal-file-item';

                const fileInfo = document.createElement('div');
                fileInfo.className = 'modal-file-info';
                fileInfo.innerHTML = `
                    <span class="file-icon">📄</span>
                    <span class="file-name"></span>
                    <span class="file-size">(${(f.size / 1024).toFixed(2)} KB)</span>
                `;
                const nameEl = fileInfo.querySelector('.file-name');
                nameEl.textContent = f.displayName;
                nameEl.title = f.displayName;

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
        // Corrupted, or junk sent through the drop link: still open the modal so it can be destroyed,
        // otherwise it would sit in the inbox and count against the quota for good
        console.error(error);
        currentPackageSessionKey = null;
        document.getElementById('modal-sender').textContent = pkg.sender_name || 'Anonymous';
        document.getElementById('modal-date').textContent = formatDateTime(parseServerDate(pkg.created_at), true);
        document.getElementById('modal-message').textContent =
            'This package could not be decrypted with your key (corrupted or not meant for you). You can destroy it.';
        document.getElementById('modal-files').replaceChildren();
        btnDownloadAll.style.display = 'none';
        modal.classList.remove('hidden');
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
        const res = await fetch(`/api/package/${selectedPackage.id}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${currentUser.sessionToken}` }
        });
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
        const res = await fetch(`/api/user/${currentUser.id}/config`, {
            headers: { 'Authorization': `Bearer ${currentUser.sessionToken}` }
        });
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
        const res = await fetch(`/api/package/${selectedPackage.id}/file/${f.id}`, {
            headers: { 'Authorization': `Bearer ${currentUser.sessionToken}` }
        });
        if (!res.ok) throw new Error('Download failed');

        const decryptedBuffer = await CryptoUtils.decryptDropFile(currentPackageSessionKey, await res.text());

        // Save under the decrypted name shown in the inbox, never under a name or type taken from the
        // stored payload, and with a neutral type so the browser never renders the file itself
        const decBlob = new Blob([decryptedBuffer], { type: 'application/octet-stream' });
        const url = URL.createObjectURL(decBlob);
        const a = document.createElement('a');
        a.href = url;
        a.download = f.displayName;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
    } catch (e) {
        console.error(e);
        alert(`Failed to decrypt file: ${f.displayName}`);
    }
}

// Drop pages send file names encrypted with the package session key ("enc:<iv>:<ciphertext>");
// older packages still have them in clear text
async function decryptFileName(storedName) {
    return CryptoUtils.decryptDropName(currentPackageSessionKey, storedName);
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

// Password Strength Meter
function evaluatePassword(pw) {
    let score = 0;
    if (!pw) return { score: 0, label: '', level: '' };

    // Length scoring
    if (pw.length >= 8) score += 1;
    if (pw.length >= 12) score += 1;
    if (pw.length >= 16) score += 1;
    if (pw.length >= 24) score += 1;

    // Character variety
    if (/[a-z]/.test(pw)) score += 1;
    if (/[A-Z]/.test(pw)) score += 1;
    if (/[0-9]/.test(pw)) score += 1;
    if (/[^a-zA-Z0-9]/.test(pw)) score += 1;

    // Variety of unique chars
    const unique = new Set(pw).size;
    if (unique >= 8) score += 1;
    if (unique >= 12) score += 1;

    // Normalize to 0-4
    const level = Math.min(4, Math.floor(score / 2.5));
    const levels = [
        { label: 'Muy débil', level: 'pw-very-weak' },
        { label: 'Débil', level: 'pw-weak' },
        { label: 'Aceptable', level: 'pw-fair' },
        { label: 'Fuerte', level: 'pw-strong' },
        { label: 'Muy fuerte', level: 'pw-very-strong' }
    ];

    return { score: level, ...levels[level] };
}

function updatePasswordStrength() {
    const pw = document.getElementById('password').value;
    const container = document.getElementById('pw-strength');
    const fill = document.getElementById('pw-strength-fill');
    const label = document.getElementById('pw-strength-label');

    if (!pw) {
        container.classList.add('hidden');
        return;
    }

    container.classList.remove('hidden');
    const result = evaluatePassword(pw);
    const percent = ((result.score + 1) / 5) * 100;

    fill.style.width = percent + '%';
    fill.className = 'pw-strength-fill ' + result.level;
    label.textContent = result.label;
    label.className = 'pw-strength-label ' + result.level;
}

// Event Listeners
document.getElementById('password').addEventListener('input', updatePasswordStrength);
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
        const res = await fetch(`/api/user/${currentUser.id}/config`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${currentUser.sessionToken}`
            },
            body: JSON.stringify({ publicLinkEnabled: enabled })
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
    } catch (e) {
        console.error('Failed to toggle public link', e);
        alert('Could not change the public link. Please try again.');
    }
    updateQuotaDisplay(); // Show the state the server actually has
});

btnGenOTL.addEventListener('click', async () => {
    if (!currentUser) return;
    try {
        const res = await fetch(`/api/user/${currentUser.id}/one-time-link`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${currentUser.sessionToken}` }
        });
        const data = await res.json();
        if (res.ok) {
            fetchOneTimeLinks();
        }
    } catch (e) {
        console.error('Failed to generate OTL', e);
    }
});

// --- My Shares: list, copy link, delete (shares count against the quota) ---
const shareListUI = document.getElementById('share-list');

async function fetchShares() {
    if (!currentUser || !currentUser.id) return;
    try {
        const res = await fetch(`/api/shares/${currentUser.id}`, {
            headers: { 'Authorization': `Bearer ${currentUser.sessionToken}` }
        });
        if (res.ok) renderShares(await res.json());
    } catch (e) {
        console.error('Failed to fetch shares', e);
    }
}

function renderShares(shares) {
    shareListUI.replaceChildren();
    if (shares.length === 0) {
        const empty = document.createElement('div');
        empty.className = 'quota-label';
        empty.style.textAlign = 'center';
        empty.style.padding = '10px';
        empty.textContent = 'No active shares';
        shareListUI.appendChild(empty);
        return;
    }

    shares.forEach(s => {
        const item = document.createElement('div');
        item.className = 'otl-item share-item';

        const info = document.createElement('div');
        info.className = 'share-item-info';
        const name = document.createElement('div');
        name.className = 'share-item-name';
        name.textContent = s.original_name;
        const meta = document.createElement('div');
        meta.className = 'share-item-meta';
        const downloads = s.max_downloads > 0 ? `${s.download_count}/${s.max_downloads} downloads` : `${s.download_count} downloads`;
        const expiry = s.expires_at ? `expires ${formatDateTime(parseServerDate(s.expires_at))}` : 'no expiry';
        meta.textContent = `${(s.size / (1024 * 1024)).toFixed(1)} MB · ${downloads} · ${expiry}`;
        info.append(name, meta);

        const actions = document.createElement('div');
        actions.className = 'otl-actions';
        const copyBtn = document.createElement('button');
        copyBtn.className = 'btn-icon-mini';
        copyBtn.title = 'Copy link';
        copyBtn.textContent = '📋';
        copyBtn.onclick = () => {
            navigator.clipboard.writeText(`${window.location.origin}/share.html?token=${s.token}`)
                .then(() => { copyBtn.textContent = '✓'; setTimeout(() => copyBtn.textContent = '📋', 1500); })
                .catch(() => alert('Could not copy the link.'));
        };
        const deleteBtn = document.createElement('button');
        deleteBtn.className = 'btn-icon-mini delete-otl';
        deleteBtn.title = 'Delete share';
        deleteBtn.textContent = '×';
        deleteBtn.onclick = async () => {
            if (!confirm('Delete this share? The link will stop working.')) return;
            try {
                const res = await fetch(`/api/share/${s.token}`, {
                    method: 'DELETE',
                    headers: { 'Authorization': `Bearer ${currentUser.sessionToken}` }
                });
                if (!res.ok) throw new Error(`HTTP ${res.status}`);
            } catch (err) {
                console.error('Failed to delete share', err);
                alert('Could not delete the share.');
            }
            fetchShares();
            updateQuotaDisplay();
        };
        actions.append(copyBtn, deleteBtn);

        item.append(info, actions);
        shareListUI.appendChild(item);
    });
}

async function fetchOneTimeLinks() {
    if (!currentUser) return;
    try {
        const res = await fetch(`/api/user/${currentUser.id}/one-time-links`, {
            headers: { 'Authorization': `Bearer ${currentUser.sessionToken}` }
        });
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
                    const res = await fetch(`/api/user/${currentUser.id}/one-time-link/${l.token}`, {
                        method: 'DELETE',
                        headers: { 'Authorization': `Bearer ${currentUser.sessionToken}` }
                    });
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

// Mobile Sidebar Toggle
const btnMenu = document.getElementById('btn-menu');
const sidebar = document.getElementById('sidebar');
const sidebarOverlay = document.getElementById('sidebar-overlay');

function toggleSidebar() {
    sidebar.classList.toggle('sidebar-open');
    sidebarOverlay.classList.toggle('active');
}

if (btnMenu) btnMenu.addEventListener('click', toggleSidebar);
if (sidebarOverlay) sidebarOverlay.addEventListener('click', toggleSidebar);

// ========================
// SECURE FILE SHARING
// ========================

const shareModal = document.getElementById('share-modal');
const btnOpenShare = document.getElementById('btn-open-share');
const btnCloseShare = document.getElementById('btn-close-share');
const btnShareUpload = document.getElementById('btn-share-upload');
const btnCopyShare = document.getElementById('btn-copy-share');
const shareStepForm = document.getElementById('share-step-form');
const shareStepResult = document.getElementById('share-step-result');
const shareFooterForm = document.getElementById('share-footer-form');
const shareUploadMsg = document.getElementById('share-upload-msg');
const shareResultLink = document.getElementById('share-result-link');
// Anyone holding the link gets the salt and wrapped key and can guess offline, so short passwords fall fast
const MIN_SHARE_PASSWORD_LENGTH = 12;
const sharePwInput = document.getElementById('share-pw');
const sharePwStrength = document.getElementById('share-pw-strength');
const sharePwFill = document.getElementById('share-pw-fill');
const shareDropArea = document.getElementById('share-drop-area');
const shareDropText = document.getElementById('share-drop-text');
const shareFileInput = document.getElementById('share-file');

function openShareModal() {
    shareModal.classList.remove('hidden');
    shareStepForm.classList.remove('hidden');
    shareStepResult.classList.add('hidden');
    shareFooterForm.classList.remove('hidden');
    shareUploadMsg.textContent = '';
    shareUploadMsg.className = 'msg';
    shareFileInput.value = '';
    sharePwInput.value = '';
    document.getElementById('share-note').value = '';
    sharePwStrength.classList.add('hidden');
    btnShareUpload.disabled = false;
    btnShareUpload.textContent = '🔐 Encrypt & Share';
    if (shareDropText) shareDropText.textContent = 'Click or drag a file here';
    if (shareDropArea) shareDropArea.classList.remove('drop-active');
    // Close sidebar on mobile
    if (sidebar && sidebar.classList.contains('sidebar-open')) toggleSidebar();
}

function closeShareModal() {
    shareModal.classList.add('hidden');
}

// Drag & Drop for share file zone
if (shareDropArea && shareFileInput) {
    shareDropArea.addEventListener('click', () => shareFileInput.click());

    shareDropArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        shareDropArea.classList.add('drop-active');
    });

    shareDropArea.addEventListener('dragleave', () => {
        shareDropArea.classList.remove('drop-active');
    });

    shareDropArea.addEventListener('drop', (e) => {
        e.preventDefault();
        shareDropArea.classList.remove('drop-active');
        if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
            shareFileInput.files = e.dataTransfer.files;
            shareDropText.textContent = '📎 ' + e.dataTransfer.files[0].name;
        }
    });

    shareFileInput.addEventListener('change', () => {
        if (shareFileInput.files.length > 0) {
            shareDropText.textContent = '📎 ' + shareFileInput.files[0].name;
        }
    });
}

// Share password strength meter
if (sharePwInput) {
    sharePwInput.addEventListener('input', function () {
        const val = this.value;
        if (!val) { sharePwStrength.classList.add('hidden'); return; }
        sharePwStrength.classList.remove('hidden');
        const result = evaluatePassword(val);
        const colors = ['pw-very-weak', 'pw-weak', 'pw-fair', 'pw-strong', 'pw-very-strong'];
        const widths = [15, 35, 55, 75, 100];
        sharePwFill.style.width = widths[result.level] + '%';
        sharePwFill.className = 'pw-strength-fill ' + colors[result.level];
    });
}

if (btnOpenShare) btnOpenShare.addEventListener('click', (e) => { e.preventDefault(); openShareModal(); });
if (btnCloseShare) btnCloseShare.addEventListener('click', closeShareModal);

// Close share modal on overlay click
if (shareModal) {
    shareModal.addEventListener('click', function (e) {
        if (e.target === shareModal) closeShareModal();
    });
}

// Share upload flow
async function handleShareUpload() {
    const fileInput = document.getElementById('share-file');
    const password = sharePwInput.value;
    const note = document.getElementById('share-note').value.trim();
    const expiresIn = document.getElementById('share-expiry').value;
    const maxDownloads = document.getElementById('share-max-dl').value;

    if (!fileInput.files || !fileInput.files.length) {
        shareUploadMsg.textContent = 'Please select a file.';
        shareUploadMsg.className = 'msg error';
        return;
    }
    if (!password || password.length < MIN_SHARE_PASSWORD_LENGTH) {
        shareUploadMsg.textContent = `Use at least ${MIN_SHARE_PASSWORD_LENGTH} characters: anyone with the link can try to guess the password offline.`;
        shareUploadMsg.className = 'msg error';
        return;
    }

    const file = fileInput.files[0];
    btnShareUpload.disabled = true;
    shareUploadMsg.className = 'msg info';

    try {
        // 1. Read file
        btnShareUpload.textContent = '📖 Reading file...';
        const fileBuffer = await file.arrayBuffer();

        // 2. Generate AES key and encrypt file
        btnShareUpload.textContent = '🔒 Encrypting file...';
        const aesKey = await CryptoUtils.generateSessionKey();
        const fileIv = window.crypto.getRandomValues(new Uint8Array(12));
        const encryptedFile = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: fileIv },
            aesKey,
            fileBuffer
        );

        // 3. Derive key from password
        btnShareUpload.textContent = '🔑 Deriving key...';
        const salt = CryptoUtils.generateSalt(16);
        const saltBuffer = CryptoUtils.base64ToBuffer(salt);
        const derivedKey = await CryptoUtils.deriveMasterKey(password, saltBuffer);

        // 4. Export and wrap AES key with derived key
        const rawKey = await window.crypto.subtle.exportKey('raw', aesKey);
        const keyIv = window.crypto.getRandomValues(new Uint8Array(12));
        const wrappedKey = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: keyIv },
            derivedKey,
            rawKey
        );

        // 5. Encrypt message if present
        let encryptedMessage = null;
        let messageIv = null;
        if (note) {
            const enc = new TextEncoder();
            const msgResult = await CryptoUtils.encryptSymmetric(derivedKey, enc.encode(note));
            encryptedMessage = msgResult.ciphertext;
            messageIv = msgResult.iv;
        }

        // 6. Build FormData and upload
        btnShareUpload.textContent = '📤 Uploading...';
        const encryptedBlob = new Blob([encryptedFile], { type: 'application/octet-stream' });
        const formData = new FormData();
        formData.append('file', encryptedBlob, 'encrypted.bin');
        formData.append('encryptedFileKey', CryptoUtils.bufferToBase64(wrappedKey));
        formData.append('keyIv', CryptoUtils.bufferToBase64(keyIv));
        formData.append('salt', salt);
        formData.append('fileIv', CryptoUtils.bufferToBase64(fileIv));
        formData.append('originalName', file.name);
        formData.append('mimeType', file.type || 'application/octet-stream');
        formData.append('maxDownloads', maxDownloads);
        formData.append('expiresIn', expiresIn);
        formData.append('downloadProof', await CryptoUtils.shareDownloadProof(rawKey));
        if (encryptedMessage) {
            formData.append('encryptedMessage', encryptedMessage);
            formData.append('messageIv', messageIv);
        }

        const res = await fetch(`/api/share/${currentUser.id}`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${currentUser.sessionToken}` },
            body: formData
        });
        const data = await res.json();

        if (!res.ok) throw new Error(data.error || 'Upload failed');

        // 7. Show result
        const shareUrl = `${window.location.origin}/share.html?token=${data.token}`;
        shareResultLink.value = shareUrl;
        shareStepForm.classList.add('hidden');
        shareFooterForm.classList.add('hidden');
        shareStepResult.classList.remove('hidden');
        fetchShares();
        updateQuotaDisplay();

    } catch (error) {
        console.error('Share upload error:', error);
        shareUploadMsg.textContent = error.message || 'Error encrypting/uploading the file.';
        shareUploadMsg.className = 'msg error';
        btnShareUpload.disabled = false;
        btnShareUpload.textContent = '🔐 Encrypt & Share';
    }
}

if (btnShareUpload) btnShareUpload.addEventListener('click', handleShareUpload);

// Copy share link
if (btnCopyShare) {
    btnCopyShare.addEventListener('click', function () {
        shareResultLink.select();
        navigator.clipboard.writeText(shareResultLink.value).then(() => {
            btnCopyShare.textContent = '✅ Copied!';
            setTimeout(() => { btnCopyShare.textContent = '📋 Copy Link'; }, 2000);
        });
    });
}

