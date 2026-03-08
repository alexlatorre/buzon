// drop.js - Secure Sender Interface

const urlParams = new URLSearchParams(window.location.search);
const targetUserId = urlParams.get('id');

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
    if (!targetUserId) {
        sysStatus.textContent = 'Error: Missing target UUID in URL';
        sysStatus.className = 'status-offline';
        return;
    }

    try {
        const res = await fetch(`/api/user/${targetUserId}/public-key`);
        const data = await res.json();
        if (res.ok) {
            targetPublicKey = await CryptoUtils.importPublicKey(data.publicKey);
            sysStatus.textContent = 'Status: Ready to transmit';
            sysStatus.className = 'status-online';
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
    const senderNameInput = document.getElementById('sender-name').value.trim() || 'Anonymous';
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
            const incomingSize = selectedFiles.reduce((acc, f) => acc + f.size, 0);
            if (incomingSize > quotaData.remaining) {
                const remainingMB = (quotaData.remaining / (1024 * 1024)).toFixed(1);
                throw new Error(`Mailbox quota exceeded. Recipient only has ${remainingMB} MB available.`);
            }
        }

        // 1. Generate AES-GCM Session Key
        const senderName = senderNameInput;
        const sessionKey = await CryptoUtils.generateSessionKey();

        // 2. Encrypt Message
        showMsg('Encrypting message...', 'info');
        const encodedMessage = new TextEncoder().encode(message);
        const encryptedMessage = await CryptoUtils.encryptSymmetric(sessionKey, encodedMessage);

        // 3. Encrypt the Session Key using the Target's RSA Public Key
        showMsg('Encrypting session key via target public key...', 'info');
        const sessionKeyRaw = await window.crypto.subtle.exportKey("raw", sessionKey);
        const encryptedSessionKey = await CryptoUtils.encryptAsymmetric(targetPublicKey, sessionKeyRaw);

        // 4. Create FormData payload
        const formData = new FormData();
        formData.append('senderName', senderName);
        formData.append('encryptedSessionKey', encryptedSessionKey);
        formData.append('encryptedMessage', encryptedMessage.ciphertext);
        formData.append('messageIv', encryptedMessage.iv);

        // 5. Encrypt all Files iteratively
        if (selectedFiles.length > 0) {
            showMsg(`Encrypting ${selectedFiles.length} file(s) locally...`, 'info');
        }
        for (let i = 0; i < selectedFiles.length; i++) {
            const file = selectedFiles[i];
            const arrayBuffer = await file.arrayBuffer();
            const encObj = await CryptoUtils.encryptSymmetric(sessionKey, arrayBuffer);

            const payloadStr = JSON.stringify({
                ciphertext: encObj.ciphertext,
                iv: encObj.iv,
                filename: file.name,
                mimeType: file.type
            });
            const blob = new Blob([payloadStr], { type: 'application/json' });
            // Keep original file name but with the encrypted blob content
            formData.append('files', blob, file.name);
        }

        // 6. Transmit to Server
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

// Initialize
fetchPublicKey();
