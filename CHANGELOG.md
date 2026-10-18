# Changelog

## Unreleased

- better-sqlite3 13: built on N-API, prebuilt binaries ship inside the package (Alpine included), no install script any more.
- The `uuid` dependency is gone: ids come from Node's `crypto.randomUUID()` (same v4 format).

## 2.0.0 — 2026-10-18

A full security review and its fixes. Upgrading needs a few decisions: read [Upgrading from earlier versions](README.md#-upgrading-from-earlier-versions) first.

### Breaking

- **Startup is strict.** Without certificates the server no longer falls back to plain HTTP: set `TLS=off` behind a TLS-terminating proxy. A missing database next to files of an earlier install stops the server instead of opening an empty one.
- **Legacy accounts cannot log in** unless `LEGACY_MIGRATION=open` (accounts created before the auth hash existed).
- **Pending packages expire** after 30 days (`PACKAGE_RETENTION_DAYS`, `0` keeps them).
- **Share passwords need 12 characters**, and downloads need a proof derived from the password.
- **`GET /api/share/:token/meta`** no longer returns `createdAt`, `downloadCount` or `maxDownloads` (it returns `downloadsLeft`), nor the type of new shares.
- **New stored formats** (drop format 2, share format 2): an older server must not receive drops after the upgrade, since it would store them as format 1 and they would not open.

### Cryptography

- **Drop format 2:** every ciphertext bound to its role with AES-GCM associated data; the message seals the sender name and the file list; raw binary bodies. The inbox warns when the server drops, duplicates or swaps files or renames the sender.
- **Recipient key fingerprint** in drop links (`#k=`), checked by the send page.
- **Share names sealed** until the password is entered; the owner keeps only a name key (HKDF), not the file key.
- **Login salt checked** in the browser and pinned per username; a change needs confirmation.
- **Per-account key derivation**, a minimum of PBKDF2-SHA256 with 600 000 iterations enforced by the browser.
- **Password change** without new keys, and **key rotation** (new RSA pair, only session and name keys re-wrapped).
- The legacy-migration challenge can no longer be used as an RSA decryption oracle.

### Server

- Ownership checks fixed (cross-user share deletion), upload fields and sizes validated before anything is written, quota serialised per user, one-time links and download limits atomic.
- `X-Forwarded-For` trusted only behind a declared proxy; rate limits that do not lock out logins.
- Security headers on every response, Subresource Integrity on every script and stylesheet, integrity hashes refreshed without restart.
- Housekeeping: orphan files, missing-file rows, used one-time links, expired packages and shares, WAL compaction.
- MySQL/MariaDB driver fixed and tested; backups with `npm run backup`.
- Docker: Node 24 LTS, unprivileged user, health check, graceful shutdown.

### Dashboard and pages

- List and delete your shares; destroy packages that cannot be decrypted; clearer handling of expired sessions, failed downloads and clipboard errors.
- Dates as `yyyy/mm/dd`, sender names marked as unverified, keys and decrypted content dropped on logout.

### Project

- 225 tests (plus 11 MySQL tests), run by GitHub Actions on Node 22 and 24.
- `SECURITY.md` with a private reporting channel.
- Minor dependency updates; no known vulnerabilities (`npm audit`).

## 1.0.0 — 2026-03-11

First release: zero-knowledge drop box (RSA-OAEP + AES-GCM + PBKDF2 in the browser), one-time links, password-protected shares, integrity check of the frontend files, SQLite and MySQL, Docker image.
