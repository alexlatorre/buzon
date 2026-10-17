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
| **Send (drop)** | The sender's browser fetches your public key, creates a random AES-256-GCM session key, encrypts the message, **each file and each file name** with it, and wraps the session key with RSA-OAEP. |
| **Receive** | Your private key unwraps the session key, which decrypts message, names and files. |
| **Share** | A random AES-256-GCM key encrypts the file; that key is wrapped with `PBKDF2(share password, random salt, 600 000)`. |

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
- **File integrity check**: the 10 frontend files are hashed by the server and by the browser, compared with the hashes seen on the previous visit, and linked to GitHub for external comparison.
- **Boss key** (double ESC): instant logout and memory wipe.

---

## ⚠️ Threat model and limitations

Be clear about what Shadow Drop protects against:

- **A malicious or compromised server can serve modified JavaScript** that steals your password. The integrity check makes this visible (it alerts when files change between visits and lets you compare with the [trusted hashes](#-trusted-hashes-sha-256)), but it cannot prevent it: whoever controls the server also controls `integrity.js`.
- **Metadata is visible to the server**: who receives packages, when, how many files and their encrypted sizes, the sender name the sender typed, and for shares the file name and type (shown to the recipient before they enter the password).
- **Offline guessing**: the salt and encrypted private key of a user, and the salt and wrapped key of a share, are available to an attacker who gets the database (or, for shares, the link). PBKDF2 with 600 000 iterations slows guessing down; a strong password is still the real protection.
- **Registration reveals whether a username exists** (it must, to avoid duplicates). Login does not.
- **Sessions are kept in memory**: restarting the server logs everyone out.

---

## 📦 Installation

Requirements: **Node.js 22+** (the Docker image uses Node 24 LTS) and **HTTPS** in front of users (the Web Crypto API only works in secure contexts; `localhost` is fine for development).

```bash
npm install
npm start
```

Open `http://localhost:4000` (or `https://` if certificates are found, see below).

For MySQL also install the driver: `npm install mysql2`.

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
| `TLS` | *(on)* | `off` forces plain HTTP even if certificates exist (TLS terminated by a proxy). |
| `TRUST_PROXY` | `1` with `TLS=off`, otherwise `false` | Express `trust proxy` setting: the number of proxies in front of the app, or `false`. Only set it when a proxy really sits in front, otherwise clients can forge `X-Forwarded-For` and bypass rate limits. `true` is refused at startup. |
| `LEGACY_MIGRATION` | closed | `open` lets accounts created before the login hash existed migrate on their next login. While open, anyone who knows such a username can fetch its encrypted private key and guess the password offline, so open it only as long as needed. |
| `AUTH_RATE_LIMIT` | `20` | Auth requests per IP every 15 minutes. |
| `API_RATE_LIMIT` | `200` | Other API requests per IP every 15 minutes (login has its own limit). |
| `REQUEST_TIMEOUT_MS` | `1800000` (30 min) | Time allowed for a whole request; raise it for very large uploads over slow links. |
| `PACKAGE_RETENTION_DAYS` | `30` | Pending packages older than this are deleted with their files by the hourly cleanup; `0` keeps them until the owner destroys them. |
| `ORPHAN_GRACE_MS` | `3600000` (1 h) | Age after which upload files with no database row are deleted by the hourly cleanup. |

### TLS certificates
The server looks for, in order: `certs/fullchain.pem` + `certs/privkey.pem`, `fullchain.pem` + `privkey.pem`, `cert.pem` + `key.pem`. If none are found (or `TLS=off`) it serves HTTP, which is the right setup behind a reverse proxy that handles TLS. If certificates are found but cannot be used (unreadable key, bad PEM, mismatched pair) the server refuses to start instead of falling back to HTTP. Certificates and keys are git-ignored.

---

## 🐳 Docker

```bash
docker build -t shadow-drop .

docker run -d -p 443:4000 \
  -v ./data:/app/data \
  -v ./fullchain.pem:/app/certs/fullchain.pem:ro \
  -v ./privkey.pem:/app/certs/privkey.pem:ro \
  --name shadow-drop shadow-drop
```

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

The suite (`test/`, Node's built-in test runner, no extra dependencies) starts real server instances on random ports with throw-away data directories and drives them with the same WebCrypto steps as the browser. It covers registration and login, legacy migration, fake salts, sessions and ownership checks, drops with encrypted names, one-time links and download limits under concurrency, quotas, upload limits, share expiry, security headers, the integrity endpoint and rate limiting.

---

## 📡 API reference

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/api/auth/register` | – | Create an account (salt, public key, encrypted private key, auth hash). |
| `GET` | `/api/auth/salt/:username` | – | PBKDF2 salt (fake but stable for unknown users). |
| `POST` | `/api/auth/login` | – | Log in with the auth hash; legacy accounts answer a challenge first. |
| `POST` | `/api/auth/logout` | ✔ | End the session. |
| `GET` | `/api/user/:id/public-key` | – | Public key behind a drop link. |
| `GET` | `/api/user/:id/quota` | – | Quota and usage behind a drop link. |
| `POST` | `/api/user/:id/config` | ✔ | Enable or disable the public link. |
| `POST` / `GET` / `DELETE` | `/api/user/:id/one-time-link(s)` | ✔ | Manage one-time links. |
| `POST` | `/api/drop/:id` | – | Send an encrypted package (multipart). |
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
- **MySQL**: missing `users` columns are added on startup.
- **Configuration**: `config.js` no longer holds credentials; move them to the environment variables above.
- **Docker**: the image now runs as uid 1000; fix volume and key permissions as described in [Docker](#-docker).
- **Drops**: file names are encrypted for packages sent with the new `drop.js`. Older packages keep their plain names and still open normally.

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

The repository forces LF line endings (`.gitattributes`), so these hashes are the same on GitHub, in any checkout (Windows included) and in the Docker image. Compare them with what your instance serves; `npm test` fails if this table is out of date; regenerate it with `npm run hashes`.

<!-- hashes:start -->
| File | SHA-256 |
|---|---|
| `app.js` | `f291df35593f3d9490824adf7b08458a62c9a2d3481c2ff4f8e3185f2e38bda9` |
| `crypto.js` | `eb21b69f540396a22e4ea4f1bd35a00490e27026dad2a33075fdaaad6487db0c` |
| `integrity.js` | `3891adc44c05e55b436347f8d5a43a82992e7c1a14585ebef060bdc1ed4041fe` |
| `share.js` | `4b6845353d71d6eef468e2922b8e2c029efd912c3572aa1d4b7344bb41e5721e` |
| `drop.js` | `cc639892f1841c211ccf971f535e8e32292a6cbb0da817ab1fd42f016b52a187` |
| `style.css` | `6d6547c18c864f398651e6a286405f14966633eb5526e0bbd277671b3701418c` |
| `index.html` | `b6d091e0ecac342cf640e89db5d57d6fe05d7e07bd6fffd0af48b1d4959aa8db` |
| `about.html` | `5eea32319dfd255efd0eab6c8816c835e577adccbc0ed14a5e50599ebfc4b1e6` |
| `drop.html` | `23e6cd33fce3d27d050f855b17880eae32f4e9dc67d32a5e951c93f800f7f7cd` |
| `share.html` | `327917ca6c4f8e137a34d95ec7f8ea65a838da3f049505aa048ced13f8636ef6` |
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

## Seguridad
- **Cifrado de extremo a extremo**: RSA-4096 (OAEP) + AES-256-GCM + PBKDF2 (600 000 iteraciones).
- **El servidor no ve** contraseñas, claves, mensajes, contenido de ficheros ni (en los envíos) sus nombres.
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
- El servidor ve metadatos: cuándo recibes paquetes, cuántos ficheros y su tamaño cifrado, el nombre de remitente que escribe quien envía y, en los shares, el nombre del fichero.
- Quien obtenga la base de datos (o el enlace de un share) puede intentar adivinar contraseñas sin conexión; PBKDF2 lo frena, pero la defensa real es una contraseña fuerte.
- El registro revela si un usuario existe; el login no.
- Las sesiones viven en memoria: al reiniciar el servidor hay que volver a entrar.

## Instalación y configuración
```bash
npm install
npm start      # http://localhost:4000
npm test       # batería de pruebas automáticas
```

Se configura con variables de entorno (tabla completa en [Configuration](#-configuration)): `PORT`, `DATA_DIR`, `DB_ENGINE`, `MYSQL_*`, `TLS=off` para servir HTTP detrás de un proxy, `TRUST_PROXY` (número de proxies delante; por defecto `false`, o `1` con `TLS=off`) y `AUTH_RATE_LIMIT`.

## Docker
```bash
docker run -d -p 443:4000 \
  -v ./data:/app/data \
  -v ./fullchain.pem:/app/certs/fullchain.pem:ro \
  -v ./privkey.pem:/app/certs/privkey.pem:ro \
  --name shadow-drop shadow-drop
```

El contenedor se ejecuta como el usuario `node` (uid 1000): el volumen `data` tiene que ser suyo (`sudo chown -R 1000:1000 ./data`) y debe poder leer `privkey.pem`. Detrás de un proxy inverso usa `-e TLS=off -e TRUST_PROXY=1`.

## Licencia
AGPL-3.0: código abierto; quien lo modifique y lo ofrezca como servicio debe publicar sus cambios.
