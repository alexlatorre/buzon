# Shadow Drop (Secure DropBox)

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

Shadow Drop is a file and message delivery platform with a **Zero-Knowledge** architecture. Anyone can send you files and messages through a link; everything is encrypted in the sender's browser and only your browser can decrypt it. The server stores encrypted blobs it cannot read.

https://gallifrey.sytes.net/

🇪🇸 [Versión en español más abajo](#-español)

---

## Contents

- [User guide](#-user-guide)
- [How the cryptography works](#-how-the-cryptography-works)
- [Security measures](#-security-measures)
- [Threat model and limitations](#-threat-model-and-limitations)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Docker](#-docker)
- [Tests](#-tests)
- [API reference](#-api-reference)
- [Upgrading from earlier versions](#-upgrading-from-earlier-versions)
- [Project structure](#-project-structure)
- [Trusted hashes](#-trusted-hashes-sha-256)

---

## 🚀 User Guide

### 1. Registration & login
- Create an account with a **username** (3–32 letters, digits or `_`) and a **master password**.
- The **strength meter** rates the password in real time.
- **Important**: the master password is the only key to your data. If you lose it, nobody (not even the server admin) can recover your files.
- **🔑 Change Password** in the sidebar changes it while you are logged in (you need the current one). Your keys, packages, shares and links stay the same.
- **🔄 Rotate Keys** replaces your key pair with a new one (you need the password). It is a separate action, never done by a password change. Packages and shares keep opening, but **your drop link changes**: the links you gave out stop working on the send page, so share the new one shown afterwards. Unused one-time links can be copied again from the sidebar, or replaced with new ones from the same screen. Use it when your password or your encrypted private key may have leaked, after changing the password. What it does not fix is listed under [Threat model](#-threat-model-and-limitations).

### 2. Receiving files (Drop)
- After login your **public link** is shown. Anyone with it can send you an encrypted package.
- Generate **one-time links** from the sidebar: each works for exactly one submission.
- You can disable the public link at any time; one-time links keep working.

### 3. Reading packages
- Packages appear in your inbox. Opening one decrypts the message, the file names and the files in your browser.
- Download files one by one or all at once; original names and types are restored.
- **Destroy Package** deletes it permanently from the server. Packages you do not destroy are deleted automatically after 30 days.

### 4. Secure file sharing
- Click **📤 Share File**, drop a file, set an **unlock password** and, optionally, an encrypted note.
- Choose an **expiry** (1 h, 24 h, 7 days, 30 days, never) and a **download limit** (1, 5, 10, 25, unlimited).
- Send the generated link and, through a different channel, the password. The recipient decrypts the file in their browser.
- Expired or exhausted shares are removed from the server automatically (hourly).

### 5. Security page
From the login screen, **"How does it work? Learn about our security →"** opens a visual explanation of the whole crypto flow.

---

## 🔐 How the cryptography works

Everything runs in the browser with the Web Crypto API (`window.crypto.subtle`).

| Step | What happens |
|---|---|
| **Register** | `PBKDF2(password, random 16-byte salt, 600 000 iterations, SHA-256)` → AES-256 master key. An RSA-4096 key pair is generated; the private key is encrypted with the master key (AES-GCM) before upload. |
| **Login** | The browser derives the master key again and sends only `serverAuthHash = SHA-256(masterKey ‖ "SERVER_AUTH")`. The server stores `SHA-256(serverAuthHash)`, compares in constant time and returns the encrypted private key, which is decrypted in memory. |
| **Send (drop)** | The sender's browser fetches your public key, creates a random AES-256-GCM session key, encrypts the message, **each file and each file name** with it, and wraps the session key with RSA-OAEP under its own label. Each ciphertext is bound to its role with associated data: the message seals the sender name and a list of random file ids, each name carries its file's id, and each file body (sent as raw bytes, IV ‖ ciphertext) can only be decrypted under that id. |
| **Receive** | Your private key unwraps the session key, which decrypts message, names and files. The inbox compares the files and sender name the server lists with the sealed ones and warns about any difference. |
| **Share** | A random AES-256-GCM key encrypts the file; a name key derived from it (HKDF) seals the file name. The file key is wrapped with `PBKDF2(share password, random salt, 600 000)`; only the name key is also wrapped with the owner's own RSA public key (its own OAEP label), so the dashboard lists shares by name while an account takeover does not expose their contents. The link page shows neither name nor type before the password, and saves the file with a neutral type. |
| **Rotate keys** | The browser generates a new RSA-4096 key pair, unwraps each pending package's session key and each format 2 share's owner name key with the current private key and wraps them again for the new public key, under the same OAEP label. File bodies, names and messages are not touched. The new private key is encrypted under the same password with a new salt. |

The server never sees passwords, master keys, private keys, session keys, messages, file contents or (for drops) file names.

---

## 🛡️ Security measures

- **End-to-end encryption**: RSA-4096 (OAEP) + AES-256-GCM + PBKDF2 (600 000 iterations).
- **Auth hash at rest**: the database keeps a hash of the login token, so a leaked database cannot be replayed to log in.
- **Legacy account migration, closed by default**: accounts created before the auth hash existed cannot log in unless `LEGACY_MIGRATION=open`; then they are upgraded only when the browser decrypts a labelled challenge encrypted with the account's public key, and answers with a hash of it.
- **Sessions**: random bearer tokens (`Authorization: Bearer`), 24 h lifetime, ownership checked on every user resource (packages, files, shares, links).
- **Strict CSP and headers**: `script-src 'self'`, `frame-ancestors 'none'`, `object-src 'none'`, HSTS, `nosniff`, `no-referrer`, `no-store`, no CORS.
- **Untrusted data rendered as text**: sender names and file names never go through `innerHTML`.
- **Rate limiting**: auth (20 / 15 min), uploads (50 / 15 min) and API (200 / 15 min) per IP. `X-Forwarded-For` is only trusted when a proxy is declared (`TRUST_PROXY`, or `TLS=off`).
- **Upload hardening**: drop links and quota are checked **before** anything is written to disk; at most 20 files × 50 MB per drop and 1 file × 100 MB per share; multer errors are returned as JSON.
- **Race-free limits**: one-time links and download limits are enforced with atomic conditional updates.
- **Quotas**: drops and shares share a 500 MB per-user quota.
- **Path traversal protection**: every ID in the API is validated as a UUID and stored files are named by the server.
- **Anti-enumeration on login**: unknown usernames get a deterministic, well-formed fake salt and the same error as a wrong password.
- **Password change without new keys**: the browser re-encrypts the same private key under the new password (new salt, current key derivation), so packages, shares and drop links keep working. The server also requires the current password's auth hash, so a stolen session token is not enough, and every other session of the account ends. The key pair itself is not replaced: someone who knew the old password and kept a copy of the encrypted key can still decrypt with it, so after a leak, rotate the keys too.
- **Key rotation**: a new key pair, generated in the browser, replaces the old one; only the small wrapped keys move (each pending package's session key, each format 2 share's owner name key), so the time it takes grows with the number of packages and shares, not with their size. The server requires the current password's auth hash and the answer to a challenge encrypted to the current public key under its own label, so neither a stolen session token nor the login auth hash alone can swap the key senders get. It applies everything in one transaction, only if the lists name every pending package and format 2 share (otherwise one would stop opening; the page reads them again and retries), and ends every other session; logins and password changes take the same per-user lock, so no session keeps the old keys. A key the current private key cannot open (junk sent through the drop link) is left as it is. The send page names the key it encrypted to, and the server refuses a drop that names a key the recipient no longer has, so a send page opened before the rotation cannot leave a package nobody can open.
- **Per-account key derivation**: stored with each account and returned with the salt; the browser refuses a derivation weaker than PBKDF2-SHA256 with 600 000 iterations, so a server cannot ask for a cheap hash, and the default can be raised without locking anyone out.
- **Login salt checked by the browser**: it must be a well-formed 16-byte value, and it is remembered per username (under a hash of it, in `localStorage`) after each successful login or registration. If the server later sends a different one, the browser asks before using the password with it. This is trust on first use: on a new browser, or after the storage is cleared (which the server itself can do with a `Clear-Site-Data` header), there is nothing to compare with, and the login screen says "first login for this account in this browser".
- **Packages sealed as a whole** (drop format 2): the server cannot swap file bodies, names or messages between slots or packages, drop or duplicate a file, or change the sender name without the inbox showing a warning; a package relabelled to the old format does not open.
- **Recipient key fingerprint in drop links**: links end in `#k=<fingerprint>`, computed by the recipient's browser from its private key. The fragment never reaches the server, and the send page refuses to encrypt to a public key that does not match it. Older links without it still work, with a warning.
- **Subresource Integrity**: every script and stylesheet tag carries the SHA-256 of its file, so the browser refuses to run a modified file served under an unmodified page (`npm run hashes` keeps the attributes current).
- **File integrity check**: the 10 frontend files are hashed by the server and by the browser, compared with the hashes seen on the previous visit, and linked to GitHub for external comparison.
- **Boss key** (double ESC): instant logout and memory wipe.

---

## ⚠️ Threat model and limitations

Be clear about what Shadow Drop protects against:

- **A malicious or compromised server can serve modified JavaScript** that steals your password. The integrity check makes this visible (it alerts when files change between visits and lets you compare with the [trusted hashes](#-trusted-hashes-sha-256)), but it cannot prevent it: whoever controls the server also controls `integrity.js`.
- **The drop link fingerprint protects against a tampered API or database, not against a server that controls its own HTTP responses**: such a server can redirect the send page to a link carrying its own `#k`, which is the same power as serving modified pages. The send page shows the fingerprint in use, so a sender can compare it with the one the recipient gave them.
- **Metadata is visible to the server**: who receives packages, when, how many files and their encrypted sizes, the sender name the sender typed, and for shares their size, limits and expiry. Share names are sealed with the file key (shares created before that change keep their name and type in clear).
- **Offline guessing**: the salt and encrypted private key of a user, and the salt and wrapped key of a share, are available to an attacker who gets the database (or, for shares, the link). PBKDF2 with 600 000 iterations slows guessing down; a strong password is still the real protection.
- **What key rotation fixes, and what it does not.** Someone with the old password and a copy of the old encrypted private key (an old backup or database dump, a past session) has the old private key; a password change alone does not stop it working. Rotation re-wraps each package's session key and each share's name key for the new key pair, but **does not change them**:

  | After a rotation, the old private key… | |
  |---|---|
  | opens packages that arrive after the rotation | **No** |
  | opens existing packages and shares whose old wrapped keys the attacker never copied | **No**: the server now holds only keys wrapped for the new key |
  | opens existing packages whose old wrapped session key the attacker copied (a stolen database, a backup, a malicious server that keeps old rows), whenever they also get the files, even later | **Yes**: the session key inside is the same, and the files never change. For shares, the old owner key reveals only the name |
  | helps someone who also knows the current password | **Yes**: rotation does not change the password, so change a leaked password first |

  The defence for content that already exists is not keeping it: destroy packages once downloaded (pending packages also expire after `PACKAGE_RETENTION_DAYS`, 30 days by default) and delete shares you no longer need. Backups made with `npm run backup`, and any other copy of the database, still hold the old encrypted private key and the old wrapped keys: delete them, or keep them as carefully as the password. With MySQL, old values can also stay in the database server's own logs for a while; with SQLite the server checkpoints its write-ahead log right after the rotation.
- **The server can move a share's sealed name to another of the same owner's shares**, so the dashboard or the link page could show one share's name for another: nothing binds the name to the token, which the server chooses. It cannot read or invent a name.
- **A stored package can be served again**: nothing ties a package to a date or a position in the inbox, so the server can show a copy of a real package twice, or with another date. It cannot change what is inside.
- **Registration reveals whether a username exists** (it must, to avoid duplicates). Login does not.
- **Sessions are kept in memory**: restarting the server logs everyone out.

Found something outside these limits? See [SECURITY.md](SECURITY.md) for how to report it privately.

---

## 📦 Installation

Requirements: **Node.js 22+** (the Docker image uses Node 24 LTS) and **HTTPS** in front of users (the Web Crypto API only works in secure contexts; `localhost` is fine for development).

```bash
npm install
npm start
```

Open `http://localhost:4000` (or `https://` if certificates are found, see below).

MySQL/MariaDB support is built in (`mysql2` is a dependency; tested against MariaDB 11.4 in strict mode): set `DB_ENGINE=mysql` and the `MYSQL_*` variables. The server creates and migrates the tables before accepting requests and stops if the database cannot be reached.

---

## ⚙️ Configuration

All settings are environment variables; nothing secret lives in the repository.

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `4000` | Listening port. |
| `DATA_DIR` | `./data` | SQLite database, uploaded files, shares and the fake-salt secret. |
| `DB_ENGINE` | `sqlite` | `sqlite` or `mysql`. |
| `MYSQL_HOST` / `MYSQL_PORT` | `localhost` / `3306` | MySQL server. |
| `MYSQL_USER` / `MYSQL_PASSWORD` | `root` / *(empty)* | MySQL credentials. Use a dedicated user. |
| `MYSQL_DATABASE` | `buzon` | MySQL database name. |
| `TLS` | *(on)* | `off` serves plain HTTP (TLS terminated by a proxy), even if certificates exist. Without it, the server needs usable certificates and refuses to start otherwise. |
| `TRUST_PROXY` | `1` with `TLS=off`, otherwise `false` | Express `trust proxy` setting: the number of proxies in front of the app, or `false`. Only set it when a proxy really sits in front, otherwise clients can forge `X-Forwarded-For` and bypass rate limits. `true` is refused at startup. |
| `LEGACY_MIGRATION` | closed | `open` lets accounts created before the login hash existed migrate on their next login. While open, anyone who knows such a username can fetch its encrypted private key and guess the password offline, so open it only as long as needed. |
| `AUTH_RATE_LIMIT` | `20` | Auth requests per IP every 15 minutes. |
| `API_RATE_LIMIT` | `200` | Other API requests per IP every 15 minutes (login has its own limit). |
| `REQUEST_TIMEOUT_MS` | `1800000` (30 min) | Time allowed for a whole request; raise it for very large uploads over slow links. |
| `PACKAGE_RETENTION_DAYS` | `30` | Pending packages older than this are deleted with their files by the hourly cleanup; `0` keeps them until the owner destroys them. |
| `ORPHAN_GRACE_MS` | `3600000` (1 h) | Age after which upload files with no database row are deleted by the hourly cleanup. |

### TLS certificates
The server looks for, in order: `certs/fullchain.pem` + `certs/privkey.pem`, `fullchain.pem` + `privkey.pem`, `cert.pem` + `key.pem`. It serves plain HTTP only with `TLS=off`, which is the right setup behind a reverse proxy that handles TLS. Without `TLS=off`, it refuses to start if it finds no certificates, or finds them but cannot use them (unreadable key, bad PEM, mismatched pair), instead of serving cleartext on the port you believe is HTTPS. Certificates and keys are git-ignored.

---

## 💾 Backups

With SQLite everything lives in `DATA_DIR`: the database, `drop/`, `shares/` and `.salt_secret`. Copying `buzon.db` alone is not enough: recent changes may still be in `buzon.db-wal`.

```bash
npm run backup -- /path/to/empty/folder
```

A missing database is created on first start (the log says so). If `buzon.db` is missing but `DATA_DIR` still holds files from an earlier install (`.salt_secret`, `buzon.db-wal`, uploads), the server refuses to start instead of opening an empty database: restore the database, or move those files away to really start from scratch. With MySQL the database itself must exist; the server creates its tables, logs it, and refuses in the same situation.

The script uses SQLite's online backup API, so it is consistent while the server runs, and copies the upload folders and `.salt_secret`. Restore by putting the folder back as `DATA_DIR`. Keep `.salt_secret` with the database: if it is lost, the server generates a new one and logs a warning, and fake salts for unknown usernames change (which lets someone comparing them over time tell real accounts apart).

## 🐳 Docker

```bash
docker build -t shadow-drop .

docker run -d -p 443:4000 \
  -v ./data:/app/data \
  -v ./fullchain.pem:/app/certs/fullchain.pem:ro \
  -v ./privkey.pem:/app/certs/privkey.pem:ro \
  --name shadow-drop shadow-drop
```

The image is built in two stages (no compilers in the final image, ~190 MB), reports its health to Docker (`HEALTHCHECK` on `/api/integrity`) and shuts down gracefully on `docker stop`.

The container runs as the unprivileged `node` user (uid 1000):

- The `data` volume must be writable by uid 1000: `sudo chown -R 1000:1000 ./data`.
- `privkey.pem` must be readable by uid 1000. Let's Encrypt keys are usually `root`-only; copy them with the right owner or terminate TLS in a reverse proxy and run with `-e TLS=off -e TRUST_PROXY=1`.

Behind a reverse proxy (Nginx, Traefik, Caddy):

```bash
docker run -d -p 127.0.0.1:4000:4000 -v ./data:/app/data \
  -e TLS=off -e TRUST_PROXY=1 --name shadow-drop shadow-drop
```

---

## 🧪 Tests

```bash
npm test
```

The suite (`test/`, Node's built-in test runner, no extra dependencies) starts real server instances on random ports with throw-away data directories and drives them with the same WebCrypto steps as the browser. It covers registration and login, legacy migration, fake salts, sessions and ownership checks, password change and key rotation (driving the real dashboard code), drops with encrypted names, one-time links and download limits under concurrency, quotas, upload limits, share expiry, security headers, the integrity endpoint and rate limiting.

The MySQL/MariaDB driver tests are skipped unless `MYSQL_TEST_URL` points at a server where the user may create databases (they create and drop a throw-away one):

```bash
MYSQL_TEST_URL=mysql://root:password@127.0.0.1:3306 npm test
```

GitHub Actions runs the whole suite, MySQL included (against MariaDB 11.4), on Node 22 and 24 for every push and pull request (`.github/workflows/test.yml`).

---

## 📡 API reference

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/api/auth/register` | – | Create an account (salt, public key, encrypted private key, auth hash). |
| `GET` | `/api/auth/salt/:username` | – | Salt and key derivation (fake but stable for unknown users). |
| `POST` | `/api/auth/login` | – | Log in with the auth hash; legacy accounts answer a challenge first. |
| `POST` | `/api/auth/password` | ✔ | Change the password: the private key re-encrypted under the new one, plus the current password's auth hash. Ends the account's other sessions. |
| `POST` | `/api/auth/rotate-keys/challenge` | ✔ | A nonce encrypted to the account's current public key (label `shadowdrop/rotation-challenge/v1`), for one rotation attempt. |
| `POST` | `/api/auth/rotate-keys` | ✔ | Rotate keys: the current password's auth hash, `challengeId` and `challengeResponse` (SHA-256 of `shadowdrop/rotation-response/v1` ‖ nonce), the new public key (2048, 3072 or 4096 bits) and vault (`salt`, which must be new, `kdf`, `encryptedPrivateKey`, `iv`, `serverAuthHash`), and `packages: [{ id, encryptedSessionKey }]` and `shares: [{ token, ownerKey }]` naming every pending package and format 2 share (`null` keeps a key as it is). 403 for a wrong password, 403 with `code: "key-proof"` for a missing or wrong answer, 409 with `code: "lists-changed"` when the lists do not match, 409 without a code when the password changed meanwhile. Ends the account's other sessions. |
| `POST` | `/api/auth/logout` | ✔ | End the session. |
| `GET` | `/api/user/:id/public-key` | – | Public key behind a drop link. |
| `GET` | `/api/user/:id/quota` | – | Quota and usage behind a drop link. |
| `POST` | `/api/user/:id/config` | ✔ | Enable or disable the public link. |
| `POST` / `GET` / `DELETE` | `/api/user/:id/one-time-link(s)` | ✔ | Manage one-time links. |
| `POST` | `/api/drop/:id` | – | Send an encrypted package (multipart). With `keyFingerprint`, refused (409) if it is not the recipient's current key. |
| `GET` | `/api/packages/:id` | ✔ | List your packages. |
| `GET` | `/api/package/:packageId/file/:fileId` | ✔ | Download an encrypted file you own. |
| `DELETE` | `/api/package/:packageId` | ✔ | Destroy a package you own. |
| `POST` | `/api/share/:userId` | ✔ | Upload an encrypted share. |
| `GET` | `/api/share/:token/meta` | – | Share metadata and wrapped key. |
| `GET` | `/api/share/:token/download` | – | Download the encrypted share (counts towards the limit). |
| `GET` | `/api/shares/:userId` | ✔ | List your shares. |
| `DELETE` | `/api/share/:token` | ✔ | Delete a share you own. |
| `GET` | `/api/integrity` | – | SHA-256 of the 10 frontend files. |

---

## ⬆️ Upgrading from earlier versions

- **Auth hashes**: existing rows are re-hashed automatically on each user's next login.
- **Legacy accounts** (`LEGACY_MIGRATION_REQUIRED`): they cannot log in by default. Start the server with `LEGACY_MIGRATION=open`, let their owners log in once (the browser answers a key-possession challenge), then remove the variable.
- **MySQL / MariaDB**: missing columns, larger message columns and indexes are added on startup; the server waits for that before accepting requests.
- **Configuration**: `config.js` no longer holds credentials; move them to the environment variables above.
- **Docker**: the image now runs as uid 1000; fix volume and key permissions as described in [Docker](#-docker).
- **Drops**: names and types are no longer stored in clear. Files stored before that change still carry them inside their JSON on disk; they disappear as those packages are destroyed or expire (30 days by default).
- **Share format 2**: new shares are stored with `format = 2` and an `owner_key` (columns added on startup); their name is sealed and no type is stored. `GET /api/share/:token/meta` no longer returns `createdAt`, `downloadCount` or `maxDownloads` (it returns `downloadsLeft`), nor `mimeType` for format 2. Shares created before keep working.
- **Shares**: new shares need a download proof derived from the password, so link holders cannot use up downloads; shares created before keep working without it. Share passwords now need 12 characters.
- **Drop format 2**: new drops are stored with `format = 2` (a column added on startup). Packages sent before still open; their names and files use the previous format. File bodies are now raw bytes, 28 bytes larger than the file. The 256 KB message limit now also covers the sealed file list and sender name. Do not roll back to a version before format 2 while it receives drops: an older server accepts them but stores them as format 1, and they will not open.
- **No certificates means no start**: without `TLS=off`, the server no longer falls back to plain HTTP when it finds no certificates. Behind a TLS-terminating proxy, set `TLS=off` (with `TRUST_PROXY`).
- **Lost database guard**: a missing database next to files of an earlier install stops the server (see [Backups](#-backups)).
- **Pending packages expire** after `PACKAGE_RETENTION_DAYS` (30 by default); set `0` before upgrading to keep the old behaviour.
- **Restart after changing `public/`** is no longer required for the integrity check, but run `npm run hashes` after any frontend change: the pages carry Subresource Integrity hashes, and a stale one makes the browser refuse the file.
- **Users will see "Changes detected"** in the integrity badge after each release that changes the frontend. Tell them to compare with the [trusted hashes](#-trusted-hashes-sha-256) before accepting.
- **Key rotation**: `POST /api/auth/rotate-keys` and **🔄 Rotate Keys** need no schema change. After a user rotates, their drop links carry a new `#k` fingerprint and the old ones fail on the send page; tell users to share the new link. The send page now sends `keyFingerprint` with each drop, and the server refuses a drop for a key the recipient no longer has (409); send pages opened before the upgrade do not send it and are not checked. A share upload whose session ended meanwhile (a rotation or password change ends the other sessions) is now refused with 401.
- **Per-account key derivation**: accounts now store their key derivation (`users.kdf`, added on startup as `pbkdf2-sha256:600000` for existing accounts). To raise it, change `KDF_DEFAULT` in `public/crypto.js` and `DEFAULT_KDF` in `server.js` together (a test checks they match): it applies to new accounts and to each account's next password change, and existing accounts keep logging in (until they change their password, they can be told apart from unknown usernames). The browser refuses anything under 600 000 iterations.

---

## 📂 Project structure

- `server.js` – Express API, security headers, rate limits, uploads, TLS discovery.
- `config.js` – Configuration read from environment variables.
- `db.js`, `db/sqlite.js`, `db/mysql.js` – Database drivers with the same interface.
- `public/` – Frontend (vanilla JS, HTML, CSS):
  - `app.js` – Login, inbox, packages, one-time links, sharing.
  - `crypto.js` – PBKDF2, RSA-OAEP, AES-GCM helpers.
  - `drop.js` / `drop.html` – Sender page.
  - `share.js` / `share.html` – Share download page.
  - `integrity.js` – Client-side integrity check.
  - `about.html` – Security explanation page.
- `test/` – Automated tests (`npm test`).
- `Dockerfile` – Node 24 Alpine image, runs as `node`.
- `LICENSE` – AGPL-3.0.

---

## 🔏 Trusted Hashes (SHA-256)

The repository forces LF line endings (`.gitattributes`), so these hashes are the same on GitHub, in any checkout (Windows included) and in the Docker image. Compare them with what your instance serves; `npm test` fails if this table or the pages' integrity attributes are out of date; regenerate both with `npm run hashes`.

<!-- hashes:start -->
| File | SHA-256 |
|---|---|
| `app.js` | `251ca0bb931e348b353252d33383391663d6a9f7c92c669955059686c6b65f3e` |
| `crypto.js` | `d1812f28a693e792d1f1d8ce1651b729a17c529cb3b8ea5555808a5b186966d9` |
| `integrity.js` | `c2c8bd10ae4691b569fe5673ce6012e8f231456bbeda5d7033b18a893dba6814` |
| `share.js` | `162c4d9fc68d15af86b8d4f6066131c2d3e83d10d96f294518b9923bbba4cf39` |
| `drop.js` | `73de54def55149b7fe57b50da92a2515000d320be5663b992706cba508180291` |
| `style.css` | `6d6547c18c864f398651e6a286405f14966633eb5526e0bbd277671b3701418c` |
| `index.html` | `38fc752a56f83597f62dffcac16083100e040a033071fc66319948384fe272a4` |
| `about.html` | `218c8d670db6d2792b84292c8d879c160d69028924d9336cb723b9f5eb538db1` |
| `drop.html` | `2c5d211ec615e62b9b8badd2ea41d6f4015f48449052728f99d0a86f3011cbb6` |
| `share.html` | `c61a586ef49918c1b8e78f3cb54535ee654c19ac0870a76ff493233fe0c7bd60` |
<!-- hashes:end -->

Manual check from the browser console (F12):

```javascript
fetch('/app.js').then(r=>r.text()).then(t=>crypto.subtle.digest('SHA-256',new TextEncoder().encode(t))).then(h=>console.log(Array.from(new Uint8Array(h)).map(b=>b.toString(16).padStart(2,'0')).join('')))
```

---
---

# 🇪🇸 Español

Shadow Drop es una plataforma para recibir ficheros y mensajes con arquitectura **Zero-Knowledge**: todo se cifra en el navegador de quien envía y solo tu navegador puede descifrarlo. El servidor guarda bloques cifrados que no puede leer.

## Guía rápida
1. **Registro**: elige usuario y contraseña maestra. **Si la pierdes, nadie puede recuperar tus datos.**
2. **Recibir**: comparte tu enlace público o genera enlaces de un solo uso (sirven para un único envío).
3. **Leer**: los paquetes, sus mensajes y los nombres de los ficheros se descifran en tu navegador. **Destroy Package** los borra del servidor; los que no borres se eliminan solos a los 30 días.
4. **Compartir ficheros**: 📤 Share File → arrastra el fichero, pon una contraseña y, si quieres, caducidad y límite de descargas. Envía el enlace y, por otro canal, la contraseña. Los enlaces caducados o agotados se borran solos cada hora.
5. **Rotar claves**: 🔄 Rotate Keys sustituye tu par de claves por uno nuevo. Paquetes y shares se siguen abriendo, pero **tu enlace de envío cambia**: los que ya diste dejan de funcionar y hay que compartir el nuevo (los de un solo uso siguen valiendo si los copias otra vez). Úsalo si tu contraseña o tu clave privada cifrada han podido filtrarse, después de cambiar la contraseña.

## Seguridad
- **Cifrado de extremo a extremo**: RSA-4096 (OAEP) + AES-256-GCM + PBKDF2 (600 000 iteraciones).
- **El servidor no ve** contraseñas, claves, mensajes, contenido de ficheros ni (en los envíos) sus nombres.
- **Paquetes sellados** (formato 2): el servidor no puede intercambiar ficheros, nombres o mensajes, quitar o duplicar un fichero ni cambiar el nombre del remitente sin que la bandeja lo avise.
- **Cambio de contraseña sin cambiar las claves**: el navegador vuelve a cifrar la misma clave privada; el servidor pide además la contraseña actual y cierra las demás sesiones.
- **Rotación de claves**: el navegador genera un par nuevo y solo mueve las claves pequeñas (la de sesión de cada paquete pendiente y la del nombre de cada share de formato 2), sin tocar ficheros, nombres ni mensajes. El servidor exige la contraseña y una prueba de que tienes la clave privada actual, lo aplica todo en una transacción, solo si la lista cubre todos los paquetes y esos shares, y rechaza los envíos de la página de envío cifrados para una clave que ya no es la tuya.
- **Derivación de clave por cuenta**: el navegador rechaza cualquiera más débil que PBKDF2 con 600 000 iteraciones.
- **Salt del login comprobado por el navegador**: debe tener 16 bytes y se recuerda por usuario; si el servidor manda otro distinto, el navegador pregunta antes de usar la contraseña.
- **Hash de autenticación protegido**: la base de datos guarda un hash del token de login; si se filtra, no sirve para entrar.
- **Migración de cuentas antiguas, cerrada por defecto**: no pueden entrar salvo con `LEGACY_MIGRATION=open`; entonces solo se actualizan si el navegador descifra un reto cifrado con la clave pública de la cuenta.
- **Sesiones** con token `Bearer` de 24 h y comprobación de propietario en paquetes, ficheros, shares y enlaces.
- **CSP estricta y cabeceras** (HSTS, `nosniff`, `no-referrer`, sin iframes, sin CORS). Los nombres de remitente y de fichero se pintan siempre como texto.
- **Límites de peticiones** por IP; `X-Forwarded-For` solo se tiene en cuenta si se configura `TRUST_PROXY`.
- **Subidas protegidas**: enlace y cuota se comprueban antes de escribir en disco; máximo 20 ficheros de 50 MB por envío y 1 de 100 MB por share.
- **Límites sin condiciones de carrera** en enlaces de un solo uso y en descargas.
- **Cuota** de 500 MB por usuario para envíos y shares juntos.
- **Verificación de integridad** de los 10 ficheros del frontend.
- **Boss key** (doble ESC): cierra la sesión y borra la memoria al instante.

## Límites conocidos
- Un servidor comprometido puede servir JavaScript modificado. La verificación de integridad lo hace visible, pero no lo puede impedir.
- El servidor ve metadatos: cuándo recibes paquetes, cuántos ficheros y su tamaño cifrado, el nombre de remitente que escribe quien envía y, en los shares, su tamaño (el nombre va sellado; solo los shares anteriores a ese cambio lo tienen en claro).
- Quien obtenga la base de datos (o el enlace de un share) puede intentar adivinar contraseñas sin conexión; PBKDF2 lo frena, pero la defensa real es una contraseña fuerte.
- Rotar las claves no cambia las claves de sesión: quien ya tenga la clave privada antigua y una copia anterior de las claves de sesión envueltas (base de datos robada, copia de seguridad o un servidor que guarde las filas viejas) puede leer esos paquetes en cuanto consiga sus ficheros, aunque sea después; destruye los paquetes al descargarlos (caducan a los 30 días), borra las copias de seguridad antiguas y, si la contraseña se ha filtrado, cámbiala antes de rotar.
- El registro revela si un usuario existe; el login no.
- Las sesiones viven en memoria: al reiniciar el servidor hay que volver a entrar.

## Instalación y configuración
```bash
npm install
npm start      # http://localhost:4000
npm test       # batería de pruebas automáticas
```

Se configura con variables de entorno (tabla completa en [Configuration](#-configuration)): `PORT`, `DATA_DIR`, `DB_ENGINE`, `MYSQL_*`, `TLS=off` para servir HTTP detrás de un proxy (sin él y sin certificados, el servidor no arranca), `TRUST_PROXY` (número de proxies delante; por defecto `false`, o `1` con `TLS=off`) y `AUTH_RATE_LIMIT`.

## Docker
```bash
docker run -d -p 443:4000 \
  -v ./data:/app/data \
  -v ./fullchain.pem:/app/certs/fullchain.pem:ro \
  -v ./privkey.pem:/app/certs/privkey.pem:ro \
  --name shadow-drop shadow-drop
```

El contenedor se ejecuta como el usuario `node` (uid 1000): el volumen `data` tiene que ser suyo (`sudo chown -R 1000:1000 ./data`) y debe poder leer `privkey.pem`. Detrás de un proxy inverso usa `-e TLS=off -e TRUST_PROXY=1`.

## Seguridad: cómo avisar
Si encuentras una vulnerabilidad, no abras una incidencia pública: sigue [SECURITY.md](SECURITY.md).

## Licencia
AGPL-3.0: código abierto; quien lo modifique y lo ofrezca como servicio debe publicar sus cambios.
