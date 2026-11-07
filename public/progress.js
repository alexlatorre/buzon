// progress.js - Progress bar for the long steps: reading, encrypting, transferring and decrypting.
// Transfers report real bytes (XMLHttpRequest for uploads, since fetch cannot report them; a streamed
// body for downloads). WebCrypto encrypts or decrypts a whole file in one call that reports nothing,
// so those steps show a moving bar with the step's name instead of a made-up percentage.

const Progress = {
    formatBytes(bytes) {
        if (bytes < 1024) return `${bytes} B`;
        if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
        if (bytes < 1073741824) return `${(bytes / 1048576).toFixed(1)} MB`;
        return `${(bytes / 1073741824).toFixed(2)} GB`;
    },

    formatTimeLeft(seconds) {
        if (seconds < 60) return `${Math.max(1, Math.round(seconds))} s left`;
        return `${Math.round(seconds / 60)} min left`;
    },

    // Drives a <div class="progress hidden"> holding a .progress-label and a .progress-track with a
    // .progress-fill inside. The parts are looked up on first use, so a page can bind it at load time.
    bar(el) {
        let parts = null;
        let step = null;      // label of the transfer being measured, to restart the speed on a new one
        let startedAt = 0;
        let startedBytes = 0;
        let paintedAt = 0;
        const get = () => (parts ||= {
            label: el.querySelector('.progress-label'),
            track: el.querySelector('.progress-track'),
            fill: el.querySelector('.progress-fill')
        });
        const show = () => el.classList.remove('hidden');

        return {
            // A step of unknown length: the step's name and a moving bar
            busy(text) {
                const { label, track, fill } = get();
                show();
                el.classList.add('progress-busy');
                fill.style.width = '';
                track.removeAttribute('aria-valuenow');
                label.textContent = text;
                step = null;
            },

            // `done` of `total` bytes, with the speed and the time left once there is a second to measure
            bytes(text, done, total) {
                if (!total) return this.busy(`${text} ${Progress.formatBytes(done)}`);
                if (done > total) total = done;
                const now = Date.now();
                if (step !== text) {
                    step = text;
                    startedAt = now;
                    startedBytes = done;
                    paintedAt = 0;
                }
                // Downloads report every few kilobytes: repaint at most ten times a second
                if (done < total && now - paintedAt < 100) return;
                paintedAt = now;

                const { label, track, fill } = get();
                show();
                el.classList.remove('progress-busy');
                const percent = Math.min(100, Math.floor((done / total) * 100));
                fill.style.width = `${percent}%`;
                track.setAttribute('aria-valuenow', String(percent));

                let rate = '';
                const seconds = (now - startedAt) / 1000;
                if (seconds >= 1 && done > startedBytes && done < total) {
                    const perSecond = (done - startedBytes) / seconds;
                    rate = ` · ${Progress.formatBytes(Math.round(perSecond))}/s · ${Progress.formatTimeLeft((total - done) / perSecond)}`;
                }
                label.textContent = `${text} ${Progress.formatBytes(done)} of ${Progress.formatBytes(total)} · ${percent}%${rate}`;
            },

            hide() {
                el.classList.add('hidden');
                el.classList.remove('progress-busy');
                if (parts) {
                    parts.fill.style.width = '0%';
                    parts.label.textContent = '';
                }
                step = null;
            }
        };
    },

    // Sends a request reporting the bytes uploaded: onProgress(done, total). Resolves to a Response,
    // as fetch does, and rejects with a TypeError when the request does not get through.
    upload(url, { method = 'POST', headers = {}, body = null } = {}, onProgress) {
        return new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            xhr.open(method, url);
            for (const [name, value] of Object.entries(headers)) xhr.setRequestHeader(name, value);
            xhr.responseType = 'blob';
            if (onProgress) {
                xhr.upload.onprogress = e => onProgress(e.loaded, e.lengthComputable ? e.total : 0);
            }
            xhr.onload = () => {
                const noBody = [101, 204, 205, 304].includes(xhr.status);
                resolve(new Response(noBody ? null : xhr.response, { status: xhr.status, statusText: xhr.statusText }));
            };
            xhr.onerror = () => reject(new TypeError('Network error: the upload did not get through.'));
            xhr.onabort = () => reject(new TypeError('The upload was cancelled.'));
            xhr.ontimeout = () => reject(new TypeError('The upload timed out.'));
            xhr.send(body);
        });
    },

    // Reads a response body reporting the bytes received: onProgress(done, total). The total is the
    // Content-Length, or `expected` when the response does not give one (0: unknown). With a
    // Content-Length the body is written into one buffer of that size, so a large file is not held twice.
    async readBody(res, onProgress, expected = 0) {
        const declared = Number(res.headers.get('Content-Length')) || 0;
        const total = declared || expected;
        if (!onProgress || !res.body || !res.body.getReader) return res.arrayBuffer();

        const reader = res.body.getReader();
        let buffer = declared ? new Uint8Array(declared) : null;
        const chunks = [];
        let done = 0;
        onProgress(0, total);
        for (;;) {
            const { done: finished, value } = await reader.read();
            if (finished) break;
            if (buffer && done + value.byteLength <= buffer.byteLength) {
                buffer.set(value, done);
            } else {
                // More than declared: keep what came so far and go on in pieces
                if (buffer) {
                    chunks.push(buffer.subarray(0, done));
                    buffer = null;
                }
                chunks.push(value);
            }
            done += value.byteLength;
            onProgress(done, total);
        }
        if (buffer) return done === buffer.byteLength ? buffer.buffer : buffer.slice(0, done).buffer;
        const out = new Uint8Array(done);
        let offset = 0;
        for (const chunk of chunks) {
            out.set(chunk, offset);
            offset += chunk.byteLength;
        }
        return out.buffer;
    }
};
