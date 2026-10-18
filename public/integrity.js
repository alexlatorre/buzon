// integrity.js - Client-Side File Integrity Verification
// Independently computes SHA-256 hashes of loaded files and compares with
// server-reported hashes AND previously stored localStorage hashes.

const IntegrityCheck = {
    STORAGE_KEY: 'shadowdrop_file_hashes',
    CRITICAL_FILES: ['app.js', 'crypto.js', 'integrity.js', 'share.js', 'drop.js', 'style.css', 'index.html', 'about.html', 'drop.html', 'share.html'],
    GITHUB_REPO: 'https://github.com/alexlatorre/buzon',
    GITHUB_BRANCH: 'master',
    indicator: null,
    detailsPanel: null,
    detailsVisible: false,

    // Every value put into markup goes through this: file names and hashes come from the server and
    // from localStorage, and none of them should be able to add markup to the page
    esc(value) {
        return String(value).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
    },

    // Same yyyy/mm/dd HH:MM format as the inbox (app.js loads after this file)
    formatDateTime(date) {
        const pad = n => String(n).padStart(2, '0');
        return `${date.getFullYear()}/${pad(date.getMonth() + 1)}/${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
    },

    // SHA-256 (hex) of bytes, or of a string's UTF-8 encoding
    async sha256(data) {
        const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
        const hash = await window.crypto.subtle.digest('SHA-256', bytes);
        return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
    },

    // Short fingerprint of the whole set: a digest over every "file:hash", so any file changes it
    async fingerprintOf(hashes) {
        const lines = Object.keys(hashes).sort().map(file => `${file}:${hashes[file]}`).join(';');
        if (!lines) return '...';
        return (await this.sha256(lines)).substring(0, 8).toUpperCase();
    },

    // Fetch a file and hash its raw bytes, exactly as the server does (text() would drop a BOM)
    async hashFile(filename) {
        try {
            const res = await fetch(`/${filename}`, { cache: 'no-store' });
            if (!res.ok) return null;
            return await this.sha256(await res.arrayBuffer());
        } catch {
            return null;
        }
    },

    // Get stored hashes from localStorage
    getStoredHashes() {
        try {
            const data = localStorage.getItem(this.STORAGE_KEY);
            return data ? JSON.parse(data) : null;
        } catch {
            return null;
        }
    },

    // Save hashes to localStorage
    storeHashes(hashes) {
        try {
            localStorage.setItem(this.STORAGE_KEY, JSON.stringify({
                hashes,
                timestamp: new Date().toISOString()
            }));
        } catch { /* localStorage could be disabled */ }
    },

    // Create the UI indicator element
    createIndicator() {
        const el = document.createElement('div');
        el.id = 'integrity-indicator';
        el.className = 'integrity-badge';
        el.title = 'Verificando integridad...';
        el.innerHTML = '<span class="integrity-icon">🔄</span><span class="integrity-label">Verificando...</span>';
        el.style.cursor = 'pointer';
        el.addEventListener('click', () => this.toggleDetails());
        this.indicator = el;
        return el;
    },

    // Create the expandable details panel
    createDetailsPanel() {
        const panel = document.createElement('div');
        panel.id = 'integrity-details';
        panel.className = 'integrity-details hidden';
        panel.innerHTML = '<div class="integrity-details-loading">Calculando hashes...</div>';
        this.detailsPanel = panel;
        return panel;
    },

    // Toggle the details panel
    toggleDetails() {
        if (!this.detailsPanel) return;
        this.detailsVisible = !this.detailsVisible;
        if (this.detailsVisible) {
            this.detailsPanel.classList.remove('hidden');
            this.detailsPanel.style.maxHeight = this.detailsPanel.scrollHeight + 'px';
        } else {
            this.detailsPanel.classList.add('hidden');
            this.detailsPanel.style.maxHeight = '0';
        }
    },

    // Render the details panel content
    renderDetails(details) {
        if (!this.detailsPanel) return;

        const stored = this.getStoredHashes();
        let html = '<div class="integrity-details-inner">';

        // Status header
        html += `<div class="integrity-status-row">
            <span class="integrity-status-text">${this.esc(details.statusText || 'Unknown')}</span>
        </div>`;

        // File hash table
        if (details.clientHashes) {
            html += '<div class="integrity-hash-table">';
            html += '<div class="integrity-hash-header">SHA-256 Fingerprints <span class="integrity-hash-hint">(compare with source code)</span></div>';

            for (const [file, hash] of Object.entries(details.clientHashes)) {
                const isChanged = details.changedFiles && details.changedFiles.includes(file);
                const storedHash = stored && stored.hashes && stored.hashes[file];
                const statusIcon = isChanged ? '⚠️' : '✓';
                const statusClass = isChanged ? 'integrity-hash-changed' : 'integrity-hash-ok';
                const githubFileUrl = `${this.GITHUB_REPO}/blob/${this.GITHUB_BRANCH}/public/${encodeURIComponent(file)}`;

                const hashTitle = isChanged && storedHash ? `Current: ${hash}\nPrevious: ${storedHash}` : hash;

                html += `<div class="integrity-hash-row ${statusClass}">
                    <div class="integrity-hash-file">
                        <span class="integrity-hash-status">${statusIcon}</span>
                        <a href="${this.esc(githubFileUrl)}" target="_blank" rel="noopener" class="integrity-hash-name integrity-hash-link" title="View on GitHub">${this.esc(file)}</a>
                    </div>
                    <div class="integrity-hash-value" title="${this.esc(hashTitle)}">${this.esc(hash)}</div>
                </div>`;
            }
            html += '</div>';
        }

        // GitHub verification link — always shown
        html += `<a href="${this.GITHUB_REPO}/tree/${this.GITHUB_BRANCH}/public" target="_blank" rel="noopener" class="integrity-github-link">
            <span>📂</span> Verify source code on GitHub
        </a>`;

        // Timestamp
        if (stored) {
            html += `<div class="integrity-timestamp">Fingerprints recorded: ${this.esc(this.formatDateTime(new Date(stored.timestamp)))}</div>`;
        }

        // Accept button (only on warning)
        if (details.changedFiles && details.changedFiles.length > 0) {
            html += `<button class="btn secondary mini integrity-accept-btn" id="integrity-accept">Accept changes as trusted</button>`;
        }

        html += '</div>';
        this.detailsPanel.innerHTML = html;

        // Bind accept button (CSP blocks inline onclick)
        const acceptBtn = this.detailsPanel.querySelector('#integrity-accept');
        if (acceptBtn) {
            acceptBtn.addEventListener('click', () => this.acceptCurrentHashes());
        }

        // Update max-height if panel is visible
        if (this.detailsVisible) {
            setTimeout(() => {
                this.detailsPanel.style.maxHeight = this.detailsPanel.scrollHeight + 'px';
            }, 10);
        }
    },

    // Set indicator state
    setStatus(status, details) {
        if (!this.indicator) return;

        this.lastDetails = details;
        const fingerprint = this.esc(details.clientHashes && this.fingerprint ? this.fingerprint : '...');

        switch (status) {
            case 'ok':
                this.indicator.innerHTML = `<span class="integrity-icon">🛡️</span><span class="integrity-label">Intact</span><code class="integrity-fp">${fingerprint}</code>`;
                this.indicator.title = 'Integrity verified — click to view hashes';
                this.indicator.className = 'integrity-badge integrity-ok';
                break;
            case 'first':
                this.indicator.innerHTML = `<span class="integrity-icon">🛡️</span><span class="integrity-label">Recorded</span><code class="integrity-fp">${fingerprint}</code>`;
                this.indicator.title = 'First verification — fingerprints recorded';
                this.indicator.className = 'integrity-badge integrity-first';
                break;
            case 'warning':
                this.indicator.innerHTML = `<span class="integrity-icon">⚠️</span><span class="integrity-label">Changes Detected</span><code class="integrity-fp">${fingerprint}</code>`;
                this.indicator.title = 'Alert! Files have changed';
                this.indicator.className = 'integrity-badge integrity-warning';
                this.showAlert(details);
                break;
            case 'mismatch':
                this.indicator.innerHTML = `<span class="integrity-icon">🚨</span><span class="integrity-label">DANGER!</span><code class="integrity-fp">${fingerprint}</code>`;
                this.indicator.title = 'DANGER! Hashes do not match';
                this.indicator.className = 'integrity-badge integrity-danger';
                this.showAlert(details);
                break;
            case 'error':
                this.indicator.innerHTML = '<span class="integrity-icon">❓</span><span class="integrity-label">Unverified</span>';
                this.indicator.title = 'Could not verify integrity';
                this.indicator.className = 'integrity-badge integrity-unknown';
                break;
        }

        // Update details panel
        this.renderDetails(details);

        // Sync sidebar clone
        this.syncSidebar();
    },

    // Sync sidebar indicator with main
    syncSidebar() {
        const clone = document.getElementById('integrity-indicator-sidebar');
        if (clone && this.indicator) {
            clone.innerHTML = this.indicator.innerHTML;
            clone.className = this.indicator.className;
            clone.title = this.indicator.title;
        }
    },

    // Show alert banner for warnings
    showAlert(details) {
        let banner = document.getElementById('integrity-alert');
        if (banner) banner.remove();

        banner = document.createElement('div');
        banner.id = 'integrity-alert';
        banner.className = 'integrity-alert';
        const githubUrl = `${this.GITHUB_REPO}/tree/${this.GITHUB_BRANCH}/public`;
        banner.innerHTML = `
            <div class="integrity-alert-content">
                <span class="integrity-alert-icon">⚠️</span>
                <div class="integrity-alert-text">
                    <strong>Integrity Alert</strong>
                    <p>${this.esc(details.message)}</p>
                    <p class="integrity-alert-files">${details.changedFiles ? 'Affected files: ' + this.esc(details.changedFiles.join(', ')) : ''}</p>
                    <a href="${githubUrl}" target="_blank" rel="noopener" class="integrity-alert-github">📂 Verify on GitHub →</a>
                </div>
                <button class="integrity-alert-dismiss" id="integrity-alert-close">✕</button>
            </div>
        `;
        document.body.prepend(banner);

        // Bind dismiss button (CSP blocks inline onclick)
        banner.querySelector('#integrity-alert-close').addEventListener('click', () => banner.remove());

        // Auto-expand details panel to show hashes
        if (!this.detailsVisible) {
            this.toggleDetails();
        }
    },

    // Main verification routine
    async verify() {
        try {
            // 1. Fetch server-reported hashes
            const serverRes = await fetch('/api/integrity', { cache: 'no-store' });
            if (!serverRes.ok) {
                this.setStatus('error', { statusText: 'Error contacting server' });
                return;
            }
            const serverData = await serverRes.json();
            const serverHashes = serverData.files;

            // 2. Independently compute hashes of loaded files
            const clientHashes = {};
            for (const file of this.CRITICAL_FILES) {
                const hash = await this.hashFile(file);
                if (hash) clientHashes[file] = hash;
            }
            this.fingerprint = await this.fingerprintOf(clientHashes);

            // 3. Compare client-computed vs server-reported (detects MITM/proxy tampering)
            const serverMismatches = [];
            for (const file of this.CRITICAL_FILES) {
                if (clientHashes[file] && serverHashes[file] && clientHashes[file] !== serverHashes[file]) {
                    serverMismatches.push(file);
                }
            }

            if (serverMismatches.length > 0) {
                this.setStatus('mismatch', {
                    statusText: '🚨 DANGER — content does not match server hashes',
                    message: 'The files received by your browser do not match what the server claims to have sent! This could indicate someone is intercepting your connection.',
                    changedFiles: serverMismatches,
                    clientHashes
                });
                return;
            }

            // 4. Compare with previously stored hashes (detects server-side file changes)
            const stored = this.getStoredHashes();

            if (!stored) {
                // First visit — register fingerprints
                this.storeHashes(clientHashes);
                this.setStatus('first', {
                    statusText: '✓ First verification — fingerprints recorded',
                    clientHashes
                });
                return;
            }

            const changedFiles = [];
            for (const file of this.CRITICAL_FILES) {
                if (clientHashes[file] && stored.hashes[file] && clientHashes[file] !== stored.hashes[file]) {
                    changedFiles.push(file);
                }
            }

            if (changedFiles.length > 0) {
                this.setStatus('warning', {
                    statusText: '⚠️ Files modified since last visit',
                    message: 'Server files have changed since your last visit. This could be a legitimate update or a code injection attempt. If you did not expect changes, do not enter your password.',
                    changedFiles,
                    clientHashes
                });
                return;
            }

            // All OK
            this.setStatus('ok', {
                statusText: '✓ All files intact — no changes detected',
                clientHashes
            });

        } catch (e) {
            console.error('[Integrity] Verification failed:', e);
            this.setStatus('error', { statusText: 'Verification error' });
        }
    },

    // Accept current hashes as trusted (after user reviews a warning)
    acceptCurrentHashes() {
        if (this.lastDetails && this.lastDetails.clientHashes) {
            this.storeHashes(this.lastDetails.clientHashes);
            this.setStatus('ok', {
                statusText: '✓ Fingerprints updated — files accepted as trusted',
                clientHashes: this.lastDetails.clientHashes
            });
            const banner = document.getElementById('integrity-alert');
            if (banner) banner.remove();
        }
    },

    // Initialize and inject into page
    init() {
        const indicator = this.createIndicator();
        const detailsPanel = this.createDetailsPanel();

        // Place in login panel
        const panel = document.querySelector('.auth-wrapper .panel');
        if (panel) {
            const wrapper = document.createElement('div');
            wrapper.className = 'integrity-wrapper';
            wrapper.appendChild(indicator);
            panel.appendChild(wrapper);
            panel.appendChild(detailsPanel);
        }

        // Clone into sidebar footer
        const sidebarFooter = document.querySelector('.sidebar-footer');
        if (sidebarFooter) {
            const clone = indicator.cloneNode(true);
            clone.id = 'integrity-indicator-sidebar';
            clone.addEventListener('click', () => this.toggleDetails());
            const wrapper = document.createElement('div');
            wrapper.className = 'integrity-wrapper sidebar-integrity';
            wrapper.appendChild(clone);
            sidebarFooter.appendChild(wrapper);
        }

        // Run verification
        this.verify();
    }
};

// Auto-init when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => IntegrityCheck.init());
} else {
    IntegrityCheck.init();
}
