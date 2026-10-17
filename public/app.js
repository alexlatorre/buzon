// app.js - Receiver Dashboard Logic

// Global State
let currentUser = {
    id: null,
    privateKey: null,
    sessionToken: null
};

let currentPackages = [];
let selectedPackage = null;
// Bumped when this session's keys change (key rotation): a list fetched before holds the old wrapped keys
let keyGeneration = 0;

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

// localStorage can be missing or throw (private windows, blocked site data)
function loginStorage() {
    try {
        return window.localStorage;
    } catch (e) {
        return null;
    }
}

// Salt and key derivation of an account, checked before the password is used with them: well-formed,
// and the same as on the last login from this browser (asks otherwise). A server that omits the key
// derivation gets the default, which is never weaker than the minimum
async function checkedLoginParams(username) {
    const res = await fetch(`/api/auth/salt/${encodeURIComponent(username)}`);
    const data = await res.json();
    if (!res.ok) throw new Error('Invalid credentials'); // Mask user existence
    const kdf = data.kdf === undefined ? CryptoUtils.KDF_DEFAULT : data.kdf;
    const salt = CryptoUtils.checkLoginSalt(data.salt);
    const iterations = CryptoUtils.parseKdf(kdf);
    const params = CryptoUtils.loginParams(kdf, data.salt);
    const pinned = await CryptoUtils.pinnedLogin(loginStorage(), username);
    if (pinned && !CryptoUtils.sameLoginParams(pinned, params) && !confirm(LOGIN_PARAMS_CHANGED)) {
        throw new Error('Login cancelled: the login parameters changed.');
    }
    return { salt, iterations, params, firstLogin: !pinned, saltBase64: data.salt, kdf };
}

const LOGIN_PARAMS_CHANGED = 'The server sent different login parameters for this account than on your last login in this browser.\n\n'
    + 'That is expected only if you changed your password or rotated your keys on another device, or the account was deleted and created again. If not, cancel: '
    + 'the server may be trying to collect a hash of your password.\n\nContinue?';

async function handleRegister() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;

    if (!username || password.length < 8) return showMsg('Username and password (min 8) required.', 'error');

    try {
        showMsg('Generating RSA-4096 key pair... (might take a few seconds)', 'info');

        // 1. Generate Salt and derive Master Key (the key derivation is stored with the account)
        const kdf = CryptoUtils.KDF_DEFAULT;
        const saltBase64 = CryptoUtils.generateSalt();
        const saltBuffer = CryptoUtils.base64ToBuffer(saltBase64);
        const masterKey = await CryptoUtils.deriveMasterKey(password, saltBuffer, true, CryptoUtils.parseKdf(kdf));

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
                kdf,
                publicKey: pubKeyBase64,
                encryptedPrivateKey: encryptedPrivResult.ciphertext,
                iv: encryptedPrivResult.iv,
                serverAuthHash: serverAuthHash
            })
        });

        const data = await res.json();
        if (res.ok) {
            await CryptoUtils.pinLogin(loginStorage(), username, CryptoUtils.loginParams(kdf, saltBase64));
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

// Decrypts the stored PKCS8 private key with the password-derived master key. Also returns the key
// fingerprint for drop links, computed from the private key so the server cannot forge it.
async function decryptPrivateKey(masterKey, encryptedPrivateKey, iv) {
    let privKeyBuffer;
    try {
        privKeyBuffer = await CryptoUtils.decryptSymmetric(masterKey, encryptedPrivateKey, iv);
    } catch (e) {
        throw new Error('Invalid master password.');
    }
    const pkcs8 = new TextDecoder().decode(privKeyBuffer);
    return {
        privateKey: await CryptoUtils.importPrivateKey(pkcs8),
        publicKey: await CryptoUtils.publicKeyFromPkcs8(pkcs8),
        fingerprint: await CryptoUtils.fingerprintFromPkcs8(pkcs8)
    };
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

        // 1. Fetch the salt and key derivation, checked before the password is used with them
        const params = await checkedLoginParams(username);

        // 2. Derive Master Key and Server Auth Hash. Without a pin there is nothing to compare the salt
        // with (new browser, cleared storage, or storage wiped by the server): say so
        showMsg(params.firstLogin ? 'Deriving master key... First login for this account in this browser.' : 'Deriving master key...', 'info');
        const masterKey = await CryptoUtils.deriveMasterKey(password, params.salt, true, params.iterations);
        const serverAuthHash = await CryptoUtils.computeServerAuthHash(masterKey);

        // 3. Authenticate with server using Server Auth Hash
        showMsg('Verifying credentials...', 'info');
        let data = await postLogin({ username, serverAuthHash });

        // Legacy account: prove we hold the private key so the server accepts our auth hash
        if (data.migrationRequired) {
            showMsg('Upgrading legacy account...', 'info');
            const { privateKey: legacyKey } = await decryptPrivateKey(masterKey, data.encryptedPrivateKey, data.iv);
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
        const { privateKey, publicKey, fingerprint } = await decryptPrivateKey(masterKey, data.encryptedPrivateKey, data.iv);
        // The key decrypted, so these are the account's real parameters: remember them for the next login
        await CryptoUtils.pinLogin(loginStorage(), username, params.params);

        // 4. Setup Global state and transition. The master key and the password are not kept:
        // only the private key (not exportable) and the session token are needed from here on
        // Kept for a password change: the encrypted private key (ciphertext only) and the salt and key
        // derivation checked above
        currentUser = {
            id: data.id,
            username,
            encryptedPrivateKey: data.encryptedPrivateKey,
            privateKeyIv: data.iv,
            vaultParams: { salt: params.salt, iterations: params.iterations },
            privateKey,
            publicKey,
            keyFingerprint: fingerprint,
            sessionToken: data.sessionToken
        };
        document.getElementById('password').value = '';

        // "#k=" lets senders check the key the server gives them; the fragment is never sent to the server
        const dropUrl = CryptoUtils.dropLink(window.location.origin, data.id, fingerprint);
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

// Authenticated request: on 401 (session expired after 24 h, or the server restarted) go back to the
// login screen and say why, instead of leaving a dashboard where nothing works. A long operation passes
// the account it started for, so a logout and a new login meanwhile never lend it the new session
async function authFetch(url, options = {}, user = currentUser) {
    const res = await fetch(url, {
        ...options,
        headers: { ...(options.headers || {}), 'Authorization': `Bearer ${user.sessionToken}` }
    });
    if (res.status === 401 && user === currentUser && currentUser.sessionToken) {
        secureLogout();
        showMsg('Session expired. Please log in again.', 'error');
        throw new Error('Session expired');
    }
    return res;
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
            privateKey: null,
            sessionToken: null
        };
        currentPackages = [];
        selectedPackage = null;
        currentPackageSessionKey = null;
        shareListUI.replaceChildren();

        // 2. Clear form fields and everything decrypted or personal that is still in the page
        document.getElementById('password').value = '';
        document.getElementById('username').value = '';
        document.getElementById('modal-sender').textContent = '';
        document.getElementById('modal-date').textContent = '';
        document.getElementById('modal-message').textContent = '';
        showPackageWarning(null);
        document.getElementById('modal-files').replaceChildren();
        pkgList.replaceChildren();
        otlListUI.replaceChildren();
        dropLink.href = '#';
        dropLink.textContent = '';
        document.getElementById('share-pw').value = '';
        document.getElementById('share-note').value = '';
        shareResultLink.value = '';
        closePasswordModal();
        resetRotateModal();
        // Close the mobile drawer, or it greets the next person who logs in
        sidebar.classList.remove('sidebar-open');
        sidebarOverlay.classList.remove('active');

        // 3. Switch panels
        dashPanel.classList.remove('active');
        dashPanel.classList.add('hidden');
        authPanel.classList.remove('hidden');
        authPanel.classList.add('active');

        // 4. Update status
        sysStatus.textContent = 'System: Offline';
        sysStatus.className = 'status-offline';
        showMsg('Vault locked: keys dropped and decrypted content cleared from the page.', 'info');
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
    fetchOneTimeLinks(); // a link may have been used since the last refresh
    const generation = keyGeneration;
    try {
        const res = await authFetch(`/api/packages/${currentUser.id}`, {
            headers: { 'Authorization': `Bearer ${currentUser.sessionToken}` }
        });
        const data = await res.json();
        if (res.ok && generation === keyGeneration) {
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
        const senderEl = div.querySelector('.package-sender');
        senderEl.textContent = pkg.sender_name || 'Anonymous';
        // Anyone with the link can type any name
        senderEl.title = 'Sender name as typed by the sender, not verified';
        pkgList.appendChild(div);
    });
}

async function openPackage(id) {
    const pkg = currentPackages.find(p => p.id === id);
    if (!pkg) return;

    selectedPackage = pkg;
    try {
        // 1-3. Unwrap the session key and decrypt the message (and, in format 2, the file manifest)
        const opened = await CryptoUtils.openDropPackage(currentUser.privateKey, pkg);
        currentPackageSessionKey = opened.sessionKey;
        const message = opened.text;

        // 4. Fill Modal (format 2: the sender name sealed in the package, not the one the server lists)
        document.getElementById('modal-sender').textContent = opened.sender ?? (pkg.sender_name || 'Anonymous');
        document.getElementById('modal-date').textContent = formatDateTime(parseServerDate(pkg.created_at), true);
        document.getElementById('modal-message').textContent = message;

        const fileList = document.getElementById('modal-files');
        fileList.innerHTML = '';

        if (pkg.files.length === 0) {
            fileList.innerHTML = '<li>No attachments</li>';
            btnDownloadAll.style.display = 'none';
        } else {
            for (const f of pkg.files) {
                const entry = await CryptoUtils.decryptDropEntry(currentPackageSessionKey, f.original_name, opened.format);
                f.displayName = entry.name;
                f.fileId = entry.id;
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

        // Format 2: the files and sender name the server lists must match the ones sealed by the sender
        showPackageWarning(CryptoUtils.packageWarning(opened, pkg.files.map(f => f.fileId), pkg.sender_name));

        modal.classList.remove('hidden');

    } catch (error) {
        // Corrupted, or junk sent through the drop link: still open the modal so it can be destroyed,
        // otherwise it would sit in the inbox and count against the quota for good
        console.error(error);
        currentPackageSessionKey = null;
        showPackageWarning(null);
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
        const res = await authFetch(`/api/package/${selectedPackage.id}`, {
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
        const res = await authFetch(`/api/user/${currentUser.id}/config`, {
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
        const res = await authFetch(`/api/package/${selectedPackage.id}/file/${f.id}`, {
            headers: { 'Authorization': `Bearer ${currentUser.sessionToken}` }
        });
        if (!res.ok) throw new Error('Download failed');

        const decryptedBuffer = await CryptoUtils.decryptDropBody(currentPackageSessionKey, await res.arrayBuffer(), selectedPackage.format, f.fileId);

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
        return true;
    } catch (e) {
        console.error(e);
        if (currentUser.sessionToken) alert(`Failed to decrypt file: ${f.displayName}`);
        return false;
    }
}

// Shown apart from the message, so the sender's text can neither hide it nor imitate it
function showPackageWarning(text) {
    const el = document.getElementById('modal-warning');
    el.textContent = text ? `⚠ ${text}` : '';
    el.classList.toggle('hidden', !text);
}

async function downloadFiles() {
    if (!selectedPackage || !currentPackageSessionKey) return;

    btnDownloadAll.textContent = 'Decrypting...';
    // Download each file, decrypt it and trigger download in browser
    let failed = 0;
    for (let i = 0; i < selectedPackage.files.length; i++) {
        if (!(await downloadFile(selectedPackage.files[i]))) failed++;
    }

    btnDownloadAll.textContent = 'Decrypt & Download All';

    // Offer to destroy only when every file made it to the user's disk
    if (failed === 0 && confirm("Files downloaded. Do you want to destroy the package from the server now?")) {
        destroyPackage();
    } else if (failed > 0 && currentUser.sessionToken) {
        alert(`${failed} file(s) could not be downloaded. The package was kept on the server.`);
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
        const res = await authFetch(`/api/user/${currentUser.id}/config`, {
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
        const res = await authFetch(`/api/user/${currentUser.id}/one-time-link`, {
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
    const generation = keyGeneration;
    try {
        const res = await authFetch(`/api/shares/${currentUser.id}`, {
            headers: { 'Authorization': `Bearer ${currentUser.sessionToken}` }
        });
        const shares = res.ok ? await res.json() : null;
        if (shares && generation === keyGeneration) renderShares(shares);
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
        name.textContent = Number(s.format) === 2 ? '…' : s.original_name;
        if (Number(s.format) === 2) {
            CryptoUtils.ownerShareName(currentUser.privateKey, s.owner_key, s.original_name).then(n => { name.textContent = n; });
        }
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
                const res = await authFetch(`/api/share/${s.token}`, {
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
        const res = await authFetch(`/api/user/${currentUser.id}/one-time-links`, {
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
            const url = CryptoUtils.dropLink(window.location.origin, l.token, currentUser.keyFingerprint);
            navigator.clipboard.writeText(url).then(() => {
                const btn = item.querySelector('.copy-otl');
                btn.textContent = "✓";
                setTimeout(() => btn.textContent = "📋", 1500);
            }).catch(() => alert(`Could not copy. The link is:
${url}`));
        };

        // Delete functionality
        item.querySelector('.delete-otl').onclick = async (e) => {
            e.stopPropagation();
            if (confirm("Delete this one-time link?")) {
                try {
                    const res = await authFetch(`/api/user/${currentUser.id}/one-time-link/${l.token}`, {
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

// --- Change password ---
// The same private key is re-encrypted under a key derived from the new password (new salt, current
// key derivation); the key pair, packages and shares stay as they are. The server also wants the
// current password's auth hash, so a stolen session token alone cannot change it.
const passwordModal = document.getElementById('password-modal');
const pwMsg = document.getElementById('pw-msg');
const btnChangePassword = document.getElementById('btn-change-password');
const MIN_ACCOUNT_PASSWORD_LENGTH = 8; // as in handleRegister
// A password change and a key rotation both replace the vault: only one at a time
let changingPassword = false;

function setPasswordMsg(text, type = 'info') {
    pwMsg.textContent = text;
    pwMsg.className = text ? `msg ${type}` : 'msg';
}

function closePasswordModal() {
    for (const id of ['pw-current', 'pw-new', 'pw-confirm']) document.getElementById(id).value = '';
    passwordModal.classList.add('hidden');
}

function openPasswordModal() {
    closePasswordModal();
    setPasswordMsg('');
    btnChangePassword.disabled = false;
    passwordModal.classList.remove('hidden');
}

async function handleChangePassword() {
    const current = document.getElementById('pw-current').value;
    const next = document.getElementById('pw-new').value;
    const repeat = document.getElementById('pw-confirm').value;
    if (!current) return setPasswordMsg('Enter your current password.', 'error');
    if (next.length < MIN_ACCOUNT_PASSWORD_LENGTH) return setPasswordMsg(`The new password needs at least ${MIN_ACCOUNT_PASSWORD_LENGTH} characters.`, 'error');
    if (next !== repeat) return setPasswordMsg('The new passwords do not match.', 'error');
    if (next === current) return setPasswordMsg('The new password is the same as the current one.', 'error');
    if (rotatingKeys) return setPasswordMsg('Wait until the key rotation finishes.', 'error');
    if (changingPassword) return;

    changingPassword = true;
    btnChangePassword.disabled = true;
    // The account this change is for: a logout while it runs must not write into the next session
    const user = currentUser;
    let pkcs8Bytes = null;
    try {
        // 1. The current password must decrypt the stored private key to the key this session uses,
        // with the salt and key derivation checked at login (nothing new is asked from the server)
        setPasswordMsg('Checking the current password...', 'info');
        const oldKey = await CryptoUtils.deriveMasterKey(current, user.vaultParams.salt, true, user.vaultParams.iterations);
        const currentServerAuthHash = await CryptoUtils.computeServerAuthHash(oldKey);
        try {
            pkcs8Bytes = new Uint8Array(await CryptoUtils.decryptSymmetric(oldKey, user.encryptedPrivateKey, user.privateKeyIv));
        } catch (e) {
            throw new Error('The current password is wrong.');
        }
        if (await CryptoUtils.fingerprintFromPkcs8(new TextDecoder().decode(pkcs8Bytes)) !== user.keyFingerprint) {
            throw new Error('The current password is wrong.');
        }

        // 2. Re-encrypt the same private key under the new password
        setPasswordMsg('Re-encrypting your private key...', 'info');
        const kdf = CryptoUtils.KDF_DEFAULT;
        const salt = CryptoUtils.generateSalt();
        const newKey = await CryptoUtils.deriveMasterKey(next, CryptoUtils.base64ToBuffer(salt), true, CryptoUtils.parseKdf(kdf));
        const encrypted = await CryptoUtils.encryptSymmetric(newKey, pkcs8Bytes);
        const serverAuthHash = await CryptoUtils.computeServerAuthHash(newKey);

        const res = await authFetch('/api/auth/password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ currentServerAuthHash, salt, kdf, encryptedPrivateKey: encrypted.ciphertext, iv: encrypted.iv, serverAuthHash })
        }, user);
        const data = await res.json().catch(() => ({}));
        if (res.status === 403) throw new Error('The current password is wrong.');
        if (!res.ok) throw new Error(data.error || 'Could not change the password.');

        await CryptoUtils.pinLogin(loginStorage(), user.username, CryptoUtils.loginParams(kdf, salt));
        user.encryptedPrivateKey = encrypted.ciphertext;
        user.privateKeyIv = encrypted.iv;
        user.vaultParams = { salt: CryptoUtils.base64ToBuffer(salt), iterations: CryptoUtils.parseKdf(kdf) };
        if (user !== currentUser) return; // logged out meanwhile: the change is done, nothing to show
        for (const id of ['pw-current', 'pw-new', 'pw-confirm']) document.getElementById(id).value = '';
        setPasswordMsg('Password changed. Use the new one from now on; your other sessions were logged out.', 'success');
    } catch (error) {
        console.error('Change password error:', error);
        if (error.message !== 'Session expired') setPasswordMsg(error.message || 'Could not change the password.', 'error');
    } finally {
        if (pkcs8Bytes) pkcs8Bytes.fill(0);
        changingPassword = false;
        btnChangePassword.disabled = false;
    }
}

document.getElementById('btn-open-password').addEventListener('click', (e) => { e.preventDefault(); openPasswordModal(); });
document.getElementById('btn-close-password').addEventListener('click', closePasswordModal);
btnChangePassword.addEventListener('click', handleChangePassword);

// --- Rotate keys ---
// A new key pair replaces the current one, so an old copy of the encrypted private key (with the
// password it was under) opens nothing that arrives later, nor the keys stored from now on. Only small
// keys move: each pending package's session key and each format 2 share's owner name key are
// unwrapped with the current private key and wrapped again for the new public key under the same
// label; file bodies, names and messages stay as they are. The new private key is encrypted under the
// same password with a new salt. The server applies it all at once, only if the lists cover every
// pending package and format 2 share; if one arrives or goes meanwhile, the lists are read again.
const rotateModal = document.getElementById('rotate-modal');
const rotateMsg = document.getElementById('rotate-msg');
const rotateResult = document.getElementById('rotate-result');
const rotateNewLink = document.getElementById('rotate-new-link');
const btnRotateKeys = document.getElementById('btn-rotate-keys');
const btnCopyRotate = document.getElementById('btn-copy-rotate');
const btnReplaceOtl = document.getElementById('btn-replace-otl');
const ROTATION_ATTEMPTS = 3;
const ROTATION_SALT_CHECKS = 3;
const ROTATION_SALT_DELAY_MS = 1000;
// A share wraps its owner key for the public key of the moment: none starts during a rotation, and a
// rotation does not start while one is uploading
let rotatingKeys = false;
let sharesUploading = 0;

function setRotateMsg(text, type = 'info') {
    rotateMsg.textContent = text;
    rotateMsg.className = text ? `msg ${type}` : 'msg';
}

// Everything the modal shows, cleared (logout)
function resetRotateModal() {
    document.getElementById('rotate-pw').value = '';
    setRotateMsg('');
    rotateNewLink.value = '';
    rotateResult.classList.add('hidden');
    btnReplaceOtl.classList.add('hidden');
    rotateModal.classList.add('hidden');
}

// Closing only hides it: a rotation still running, and its outcome (the new link, the button that
// replaces one-time links), are there when it opens again
function closeRotateModal() {
    document.getElementById('rotate-pw').value = '';
    rotateModal.classList.add('hidden');
}

function openRotateModal() {
    if (!rotatingKeys) btnRotateKeys.disabled = false;
    rotateModal.classList.remove('hidden');
    if (sidebar && sidebar.classList.contains('sidebar-open')) toggleSidebar();
}

// Every pending package key and format 2 share owner key, as the server lists them now, wrapped again
// for newPublicKey. One the current private key cannot open goes as null: the server leaves it as it is
async function rewrapForRotation(user, newPublicKey) {
    const [pkgRes, shareRes] = await Promise.all([authFetch(`/api/packages/${user.id}`, {}, user), authFetch(`/api/shares/${user.id}`, {}, user)]);
    if (!pkgRes.ok || !shareRes.ok) throw new Error('Could not read your packages and shares.');
    const packages = [];
    const shares = [];
    let kept = 0;
    for (const pkg of await pkgRes.json()) {
        const encryptedSessionKey = await CryptoUtils.rewrapPackageKey(user.privateKey, newPublicKey, pkg);
        if (encryptedSessionKey === null) kept++;
        packages.push({ id: pkg.id, encryptedSessionKey });
    }
    for (const share of await shareRes.json()) {
        if (Number(share.format) !== 2) continue; // format 1 shares hold nothing wrapped for the account
        const ownerKey = await CryptoUtils.rewrapShareOwnerKey(user.privateKey, newPublicKey, share.owner_key);
        if (ownerKey === null) kept++;
        shares.push({ token: share.token, ownerKey });
    }
    return { packages, shares, kept };
}

// The answer to a rotation challenge: only the current private key opens it
async function rotationProof(user) {
    const res = await authFetch('/api/auth/rotate-keys/challenge', { method: 'POST' }, user);
    const data = await res.json().catch(() => ({}));
    if (!res.ok || typeof data.challenge !== 'string') throw new Error(data.error || 'Could not start the key rotation.');
    let challengeResponse;
    try {
        challengeResponse = await CryptoUtils.answerRotationChallenge(user.privateKey, data.challenge);
    } catch (e) {
        throw new Error('Could not prove that this session holds your current key. Log out and in again, then retry.');
    }
    return { challengeId: data.challengeId, challengeResponse };
}

// After an answer that got lost: whether the server has the new vault, told by the account's salt
// (true, false, or null when that cannot be told either). The request may still be running there, so
// an unchanged salt is read again a few times before it counts
async function rotationApplied(user, newSalt) {
    const oldSalt = CryptoUtils.bufferToBase64(user.vaultParams.salt);
    for (let check = 1; ; check++) {
        let salt = null;
        try {
            const res = await fetch(`/api/auth/salt/${encodeURIComponent(user.username)}`);
            if (res.ok) salt = (await res.json()).salt;
        } catch (e) {
            // unknown: counts as neither
        }
        if (salt === newSalt) return true;
        if (salt !== oldSalt) return null;
        if (check === ROTATION_SALT_CHECKS) return false;
        await new Promise(resolve => setTimeout(resolve, ROTATION_SALT_DELAY_MS));
    }
}

async function handleRotateKeys() {
    const password = document.getElementById('rotate-pw').value;
    if (!password) return setRotateMsg('Enter your password.', 'error');
    if (rotatingKeys) return;
    if (sharesUploading > 0) return setRotateMsg('Wait until your share upload finishes.', 'error');
    if (changingPassword) return setRotateMsg('Wait until the password change finishes.', 'error');

    rotatingKeys = true;
    btnRotateKeys.disabled = true;
    rotateResult.classList.add('hidden');
    // The account this rotation is for: a logout while it runs must not write into the next session
    const user = currentUser;
    // Progress and errors only while this rotation's session is the one shown
    const say = (text, type) => { if (user === currentUser) setRotateMsg(text, type); };
    let pkcs8Bytes = null;
    try {
        // 1. The password must decrypt the stored private key to the key this session uses, with the
        // salt and key derivation checked at login
        say('Checking the password...', 'info');
        const masterKey = await CryptoUtils.deriveMasterKey(password, user.vaultParams.salt, true, user.vaultParams.iterations);
        const currentServerAuthHash = await CryptoUtils.computeServerAuthHash(masterKey);
        let currentPkcs8;
        try {
            currentPkcs8 = new Uint8Array(await CryptoUtils.decryptSymmetric(masterKey, user.encryptedPrivateKey, user.privateKeyIv));
        } catch (e) {
            throw new Error('The password is wrong.');
        }
        const currentFingerprint = await CryptoUtils.fingerprintFromPkcs8(new TextDecoder().decode(currentPkcs8));
        currentPkcs8.fill(0);
        if (currentFingerprint !== user.keyFingerprint) throw new Error('The password is wrong.');

        // 2. The new key pair, its private key encrypted under the same password with a new salt
        say('Generating a new RSA-4096 key pair... (might take a few seconds)', 'info');
        const pair = await CryptoUtils.generateRSAKeyPair();
        const publicKey = await CryptoUtils.exportPublicKey(pair.publicKey);
        const pkcs8 = await CryptoUtils.exportPrivateKey(pair.privateKey);
        pkcs8Bytes = new TextEncoder().encode(pkcs8);
        const kdf = CryptoUtils.KDF_DEFAULT;
        const salt = CryptoUtils.generateSalt();
        const vaultKey = await CryptoUtils.deriveMasterKey(password, CryptoUtils.base64ToBuffer(salt), true, CryptoUtils.parseKdf(kdf));
        const encrypted = await CryptoUtils.encryptSymmetric(vaultKey, pkcs8Bytes);
        const serverAuthHash = await CryptoUtils.computeServerAuthHash(vaultKey);
        // Ready before anything is sent: once the server has the new keys, this session has them too
        const next = {
            privateKey: await CryptoUtils.importPrivateKey(pkcs8),
            publicKey: await CryptoUtils.publicKeyFromPkcs8(pkcs8),
            keyFingerprint: await CryptoUtils.fingerprintFromPkcs8(pkcs8)
        };

        // 3. Every package and share key moved to the new public key, read again if the lists changed.
        // Each attempt also proves this session holds the current private key (a fresh challenge)
        let kept = 0;
        for (let attempt = 1; ; attempt++) {
            say('Moving your package and share keys to the new key pair...', 'info');
            const lists = await rewrapForRotation(user, pair.publicKey);
            const proof = await rotationProof(user);
            let res = null;
            let data = {};
            try {
                res = await authFetch('/api/auth/rotate-keys', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        currentServerAuthHash, ...proof, publicKey, salt, kdf, encryptedPrivateKey: encrypted.ciphertext, iv: encrypted.iv,
                        serverAuthHash, packages: lists.packages, shares: lists.shares
                    })
                }, user);
                data = await res.json().catch(() => ({}));
            } catch (e) {
                if (e.message === 'Session expired') throw e;
            }
            // No answer, a server or proxy error page, or a success that is not the server's: the
            // rotation may have gone through anyway
            if (!res || res.status >= 500 || (res.ok && data.success !== true)) {
                const applied = await rotationApplied(user, salt);
                if (applied === false) throw new Error('The server could not rotate the keys. Nothing changed: try again.');
                if (applied === null) {
                    if (user === currentUser) {
                        secureLogout();
                        showMsg('The connection failed while your keys were rotated. Log in again: if the login says the parameters changed, that is the rotation.', 'error');
                    }
                    return;
                }
            } else if (!res.ok) {
                if (res.status === 409 && data.code === 'lists-changed') {
                    if (attempt < ROTATION_ATTEMPTS) continue;
                    throw new Error('Packages kept arriving while the keys were being moved. Turn off the public link for a moment and try again.');
                }
                if (res.status === 403 && data.code === 'key-proof') throw new Error('Could not prove that this session holds your current key. Log out and in again, then retry.');
                if (res.status === 403) throw new Error('The password is wrong.');
                if (res.status === 413) throw new Error('Too many packages to move at once: destroy some and try again.');
                throw new Error(data.error || 'Could not rotate the keys.');
            }
            kept = lists.kept;
            break;
        }

        // 4. The new keys from here on; the pin follows the new salt even if this session has ended
        await CryptoUtils.pinLogin(loginStorage(), user.username, CryptoUtils.loginParams(kdf, salt));
        if (user !== currentUser) return; // logged out meanwhile: the rotation is done, nothing to show
        Object.assign(user, next, {
            encryptedPrivateKey: encrypted.ciphertext,
            privateKeyIv: encrypted.iv,
            vaultParams: { salt: CryptoUtils.base64ToBuffer(salt), iterations: CryptoUtils.parseKdf(kdf) }
        });
        const dropUrl = CryptoUtils.dropLink(window.location.origin, user.id, user.keyFingerprint);
        dropLink.href = dropUrl;
        dropLink.textContent = dropUrl;
        rotateNewLink.value = dropUrl;
        rotateResult.classList.remove('hidden');
        document.getElementById('rotate-pw').value = '';
        // The list in memory holds the old wrapped keys: drop it before anything opens from it, and
        // any list still on its way
        keyGeneration++;
        currentPackages = [];
        fetchPackages();
        fetchShares();
        // Every link given out carries the old fingerprint: say which ones stop working
        const unused = await unusedOneTimeLinks(user).catch(() => null);
        if (user !== currentUser) return;
        const otlText = unused === null ? ' and any one-time links you gave out'
            : unused.length ? ` and your ${unused.length} unused one-time link(s) (copy them again from the sidebar, or replace them with new ones)` : '';
        btnReplaceOtl.classList.toggle('hidden', !(unused && unused.length));
        setRotateMsg(`Keys rotated. Your new key fingerprint is ${user.keyFingerprint}. These links no longer work on the send page: `
            + `your public drop link${otlText}. Share the new link below. Your other sessions were logged out.`
            + (kept ? ` ${kept} key(s) that your previous key could not open were left as they were.` : ''), 'success');
    } catch (error) {
        console.error('Rotate keys error:', error);
        if (error.message !== 'Session expired') say(error.message || 'Could not rotate the keys.', 'error');
    } finally {
        if (pkcs8Bytes) pkcs8Bytes.fill(0);
        rotatingKeys = false;
        btnRotateKeys.disabled = false;
    }
}

async function unusedOneTimeLinks(user) {
    const res = await authFetch(`/api/user/${user.id}/one-time-links`, {}, user);
    if (!res.ok) throw new Error('Could not read your one-time links.');
    return res.json();
}

// One-time links keep their token through a rotation; new ones make those already given out unusable
async function replaceOneTimeLinks() {
    const user = currentUser;
    btnReplaceOtl.disabled = true;
    try {
        const links = await unusedOneTimeLinks(user);
        for (const link of links) {
            const created = await authFetch(`/api/user/${user.id}/one-time-link`, { method: 'POST' }, user);
            if (!created.ok) throw new Error('Could not create a one-time link.');
            const removed = await authFetch(`/api/user/${user.id}/one-time-link/${link.token}`, { method: 'DELETE' }, user);
            if (!removed.ok) throw new Error('Could not delete a one-time link.');
        }
        if (user !== currentUser) return;
        btnReplaceOtl.classList.add('hidden');
        setRotateMsg(`${links.length} one-time link(s) replaced: the old ones no longer work. Copy the new ones from the sidebar.`, 'success');
    } catch (error) {
        console.error('Replace one-time links error:', error);
        if (error.message !== 'Session expired') setRotateMsg(error.message, 'error');
    } finally {
        btnReplaceOtl.disabled = false;
        fetchOneTimeLinks();
    }
}

document.getElementById('btn-open-rotate').addEventListener('click', (e) => { e.preventDefault(); openRotateModal(); });
btnReplaceOtl.addEventListener('click', replaceOneTimeLinks);
document.getElementById('btn-close-rotate').addEventListener('click', closeRotateModal);
btnRotateKeys.addEventListener('click', handleRotateKeys);
btnCopyRotate.addEventListener('click', () => {
    rotateNewLink.select();
    navigator.clipboard.writeText(rotateNewLink.value).then(() => {
        btnCopyRotate.textContent = '✅ Copied!';
        setTimeout(() => { btnCopyRotate.textContent = '📋 Copy Link'; }, 2000);
    }).catch(() => {
        // The link is still selected: let the user copy it by hand
        btnCopyRotate.textContent = 'Press Ctrl+C to copy';
        setTimeout(() => { btnCopyRotate.textContent = '📋 Copy Link'; }, 3000);
    });
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
document.getElementById('nav-inbox').addEventListener('click', (e) => {
    e.preventDefault();
    if (sidebar.classList.contains('sidebar-open')) toggleSidebar();
});
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

    if (rotatingKeys) {
        shareUploadMsg.textContent = 'Wait until the key rotation finishes.';
        shareUploadMsg.className = 'msg error';
        return;
    }

    const file = fileInput.files[0];
    btnShareUpload.disabled = true;
    shareUploadMsg.className = 'msg info';

    sharesUploading++;
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
        const derivedKey = await CryptoUtils.deriveMasterKey(password, saltBuffer, false);

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
        // Format 2: the name is sealed with a key derived from the file key, and the owner keeps only
        // that name key, wrapped with their own public key, to list the share by name. No type is sent.
        formData.append('format', '2');
        formData.append('originalName', await CryptoUtils.sealShareName(rawKey, file.name));
        formData.append('ownerKey', await CryptoUtils.wrapShareNameKeyForOwner(currentUser.publicKey, rawKey));
        formData.append('maxDownloads', maxDownloads);
        formData.append('expiresIn', expiresIn);
        formData.append('downloadProof', await CryptoUtils.shareDownloadProof(rawKey));
        if (encryptedMessage) {
            formData.append('encryptedMessage', encryptedMessage);
            formData.append('messageIv', messageIv);
        }

        const res = await authFetch(`/api/share/${currentUser.id}`, {
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
    } finally {
        sharesUploading--;
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
        }).catch(() => {
            // The link is still selected: let the user copy it by hand
            btnCopyShare.textContent = 'Press Ctrl+C to copy';
            setTimeout(() => { btnCopyShare.textContent = '📋 Copy Link'; }, 3000);
        });
    });
}

