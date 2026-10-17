// drop.js - Secure Sender Interface

const urlParams = new URLSearchParams(window.location.search);
const targetUserId = urlParams.get('id');
// Recipient key fingerprint from the link fragment (#k=...), which the server never sees:
// a string, null for links without one, false when the fragment is malformed
const expectedKeyFingerprint = CryptoUtils.parseKeyFragment(window.location.hash);
const LINK_ID_FORMAT = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const statusMsg = document.getElementById('status-msg');
const sysStatus = document.getElementById('system-status');
const btnSubmit = document.getElementById('btn-submit');
const fileInput = document.getElementById('file-input');
const fileDropArea = document.getElementById('file-drop-area');
const fileListUI = document.getElementById('file-list');

const dropPanel = document.getElementById('drop-panel');
const successPanel = document.getElementById('success-panel');

let targetPublicKey = null;
let selectedFiles = [];

function showMsg(msg, type = 'info') {
    statusMsg.textContent = msg;
    statusMsg.className = `msg ${type}`;
}

async function fetchPublicKey() {
    if (!targetUserId || !LINK_ID_FORMAT.test(targetUserId) || expectedKeyFingerprint === false) {
        sysStatus.textContent = 'Error: this link is malformed';
        sysStatus.className = 'status-offline';
        showMsg('This link is not valid. Ask the recipient to send it again.', 'error');
        return;
    }

    try {
        const res = await fetch(`/api/user/${targetUserId}/public-key`);
        const data = await res.json();
        if (res.ok) {
            // A key that does not match the link could be the server's own: never encrypt to it
            const verified = expectedKeyFingerprint !== null && await CryptoUtils.verifyRecipientKey(data.publicKey, expectedKeyFingerprint);
            if (expectedKeyFingerprint !== null && !verified) {
                sysStatus.textContent = 'Error: recipient key does not match the link';
                sysStatus.className = 'status-offline';
                showMsg('The key provided by the server is not the one in this link. Nothing was sent. Ask the recipient for a new link.', 'error');
                return;
            }
            targetPublicKey = await CryptoUtils.importPublicKey(data.publicKey);
            // Show the fingerprint in use so the sender can compare it with the one the recipient gave them
            sysStatus.textContent = verified ? `Status: Recipient key verified (${expectedKeyFingerprint}), ready to transmit` : 'Status: Ready to transmit';
            sysStatus.className = 'status-online';
            if (!verified) {
                showMsg('This link has no key fingerprint, so the recipient key cannot be verified. Ask the recipient for a current link if you can.', 'info');
            }
            btnSubmit.disabled = false;
        } else {
            throw new Error(data.error);
        }
    } catch (err) {
        console.error(err);
        sysStatus.textContent = 'Error: Failed to retrieve public key';
        sysStatus.className = 'status-offline';
        showMsg('The requested vault does not exist or is offline.', 'error');
    }
}

// File Selection Logic
fileDropArea.addEventListener('click', () => fileInput.click());

fileDropArea.addEventListener('dragover', (e) => {
    e.preventDefault();
    fileDropArea.style.borderColor = 'var(--text-color)';
});

fileDropArea.addEventListener('dragleave', () => {
    fileDropArea.style.borderColor = 'var(--accent-color)';
});

fileDropArea.addEventListener('drop', (e) => {
    e.preventDefault();
    fileDropArea.style.borderColor = 'var(--accent-color)';
    handleFiles(e.dataTransfer.files);
});

fileInput.addEventListener('change', (e) => {
    handleFiles(e.target.files);
});

function handleFiles(files) {
    for (let i = 0; i < files.length; i++) {
        selectedFiles.push(files[i]);
    }
    updateFileList();
}

function updateFileList() {
    fileListUI.innerHTML = '';
    selectedFiles.forEach((file, index) => {
        const li = document.createElement('li');
        li.textContent = `${file.name} (${(file.size / 1024).toFixed(2)} KB)`;

        const removeBtn = document.createElement('span');
        removeBtn.textContent = ' [REMOVE]';
        removeBtn.style.color = 'var(--danger-color)';
        removeBtn.style.cursor = 'pointer';
        removeBtn.onclick = (e) => {
            e.stopPropagation();
            selectedFiles.splice(index, 1);
            updateFileList();
        };

        li.appendChild(removeBtn);
        fileListUI.appendChild(li);
    });
}

// Encryption and Upload
btnSubmit.addEventListener('click', async () => {
    const senderNameInput = CryptoUtils.cleanSenderName(document.getElementById('sender-name').value) || 'Anonymous';
    const message = document.getElementById('message').value;

    if (!message && selectedFiles.length === 0) {
        return showMsg('Please enter a message or select files.', 'error');
    }

    try {
        btnSubmit.disabled = true;

        // 0. Pre-check Quota
        showMsg('Checking recipient mailbox capacity...', 'info');
        const quotaRes = await fetch(`/api/user/${targetUserId}/quota`);
        const quotaData = await quotaRes.json();

        if (quotaRes.ok) {
            // Stored size: each file grows by its IV and tag (28 bytes)
            const incomingSize = selectedFiles.reduce((acc, f) => acc + f.size + 28, 0);
            if (incomingSize > quotaData.remaining) {
                const remainingMB = (quotaData.remaining / (1024 * 1024)).toFixed(1);
                throw new Error(`Mailbox quota exceeded. Recipient only has ${remainingMB} MB available.`);
            }
        }

        // 1. Encrypt everything locally (format 2: every piece bound to its role, raw file bytes)
        showMsg(selectedFiles.length > 0 ? `Encrypting message and ${selectedFiles.length} file(s) locally...` : 'Encrypting message...', 'info');
        const files = [];
        for (const file of selectedFiles) {
            files.push({ name: file.name, data: await file.arrayBuffer() });
        }
        const pkg = await CryptoUtils.encryptDropPackage(targetPublicKey, message, files, senderNameInput);
        // The message carries the file list and the sender name too: say so here, not with a 400
        if (CryptoUtils.base64ToBuffer(pkg.encryptedMessage).byteLength > CryptoUtils.DROP_V2.MAX_MESSAGE_BYTES + 16) {
            throw new Error('The message is too long.');
        }

        // 2. Only ciphertext goes to the server; file names are inside the encrypted names
        const formData = new FormData();
        formData.append('format', '2');
        formData.append('senderName', senderNameInput);
        formData.append('encryptedSessionKey', pkg.encryptedSessionKey);
        formData.append('encryptedMessage', pkg.encryptedMessage);
        formData.append('messageIv', pkg.messageIv);
        pkg.bodies.forEach(body => formData.append('files', new Blob([body], { type: 'application/octet-stream' }), 'encrypted.bin'));
        formData.append('fileNames', JSON.stringify(pkg.names));

        // 3. Transmit to Server
        showMsg('Transmitting secure payload to the server...', 'info');
        const res = await fetch(`/api/drop/${targetUserId}`, {
            method: 'POST',
            body: formData
        });

        const data = await res.json();
        if (res.ok) {
            dropPanel.classList.remove('active');
            dropPanel.classList.add('hidden');
            successPanel.classList.remove('hidden');
            successPanel.classList.add('active');
        } else {
            throw new Error(data.error);
        }

    } catch (error) {
        console.error(error);
        showMsg('Transmission failed: ' + error.message, 'error');
        btnSubmit.disabled = false;
    }
});

// The CSP blocks inline handlers, so the button is wired here
document.getElementById('btn-send-another').addEventListener('click', () => window.location.reload());

// Initialize
fetchPublicKey();
