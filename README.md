# Shadow Drop (Secure DropBox)

Shadow Drop is a file and message delivery platform with **Zero-Knowledge** architecture. It allows anyone to send you information securely — the server is unable to read any content.

https://gallifrey.sytes.net/

---

## 🚀 User Guide

### 1. Registration & Login
- Create an account with a **Username** and **Master Password**.
- The **strength meter** shows password security in real time (red/very weak → green/very strong).
- **IMPORTANT**: Your master password is the only key to your data. If lost, nobody (not even the server admin) can recover your files.

### 2. Receiving Files (Drop)
- After login, your **Public Link** is shown. Share it to receive files.
- You can generate **One-Time Links** from the sidebar — they expire after the first successful submission.
- You can disable the public link at any time from the Dashboard settings.

### 3. Download & Read
- Packages appear in your inbox.
- Opening a package decrypts it in your browser.
- Download files individually or all at once — original names and extensions are restored automatically.

### 4. Security Page
- From the login screen, click **"How does it work? Learn about our security →"** for a visual explanation of the crypto architecture.

### 5. Secure File Sharing
- From the dashboard, click **📤 Share File** in the sidebar.
- Select a file, set an **unlock password**, and optionally add a message.
- Configure **expiration** (1h, 24h, 7 days, 30 days, or never) and **download limit**.
- The browser encrypts the file with **AES-256-GCM** and protects the key with **PBKDF2** derived from the password.
- A link is generated that you can copy and send to the recipient.
- The recipient opens the link, enters the password, and the file is decrypted and downloaded **exclusively in their browser**.
- The server never has access to the file contents or password.

---

## 🛡️ Security

### Zero-Knowledge Architecture
Unlike other services, Shadow Drop uses real **End-to-End Encryption (E2EE)**. The server acts only as "blind storage" for encrypted bits.

#### Where does the magic happen?
All cryptographic processing occurs **exclusively in the user's Browser** using the `window.crypto` (Web Crypto API).

1. **Registration/Login (Receiver)**: Master password derives a key via **PBKDF2** (600,000 iterations, SHA-256). RSA-4096 private key is encrypted with this derived key **before** leaving your machine.
2. **Sending (Sender)**: Downloads your public key → generates a random **AES-GCM-256** session key → encrypts files and message with AES → encrypts AES key with your RSA public key (**RSA-OAEP**).
3. **Receiving (Receiver)**: Browser downloads the encrypted block → private key (decrypted in RAM after login) decrypts the AES key → AES key decrypts the message and files.

**Result**: The server never holds the keys to view your files.

### Content Security Policy (CSP)
Strict HTTP security headers: `script-src 'self'` (blocks XSS), `frame-ancestors 'none'` (anti-clickjacking), `no-referrer`, `no-store`, disabled camera/microphone/geolocation.

### File Integrity Verification
1. **Server hashing**: On startup, SHA-256 hashes are computed for all critical public files and exposed at `/api/integrity`.
2. **Client verification**: The browser independently computes hashes and compares them.
3. **Change detection (localStorage)**: First-visit fingerprints are stored; any change triggers an integrity alert.
4. **GitHub verification**: Links to source code on [GitHub](https://github.com/alexlatorre/buzon/tree/master/public) for external verification.

### Other Security Features
- **Boss Key** (double ESC): Instant session logout with memory wipe.
- **One-Time Links**: Auto-invalidated after first submission.
- **Disable Public Link**: Cut external access at any time.
- **Package Destruction**: Permanent server-side file deletion after reading.
- **Password Strength Meter**: Real-time evaluation of length, character variety, and uniqueness.
- **Responsive Design**: Mobile and tablet adaptive interface with sliding sidebar.

### 🔏 Trusted Hashes (SHA-256)
Use this table as an external source of truth to verify that files served by your instance have not been tampered with.

| File | SHA-256 |
|---|---|
| `app.js` | `8d708cdca3371eacf0a5428dbae0fea2e35c21119d501fa0fc925450faab256e` |
| `crypto.js` | `27eca691dc43573d5a7eaaebcb5fed60aa40e23dc797647ef3c6df690850441c` |
| `integrity.js` | `0a897a7a4869fb40a52b996b76ae52a60c1af548913ae2bce8e2e9cdd980e053` |
| `share.js` | `cc9a1a55b27713204604ed323f18682b62a4e3b0cfcef904317e4bc1ba571a91` |
| `drop.js` | `fe68762008b9712982a0b8f0a77f5cbcc70878f611c19ea7d3e0793072ac8eb2` |
| `style.css` | `d959dbcb0061ce42eb6e1afb714d964070d76c079b80f1540d1bd067b6a58335` |
| `index.html` | `f145a0e3305e363d199f837d6d0af58c9d08d37e25a23f6b86d94ef4f473a9f6` |
| `about.html` | `5b6ff72b65c24da11173a09c5401be7e575e69741754dc0412a560421aa10af2` |
| `drop.html` | `212cfaadd493f015dff8d832cb01f30139dcecf7eff48adcd5233d4d29277888` |
| `share.html` | `7e310e38af379693f2f6dbf50c4f00c3eecf2c7dfd6b6d1c3acd317716c9c531` |

> **Manual verification** (browser console F12):
> ```javascript
> fetch('/app.js').then(r=>r.text()).then(t=>crypto.subtle.digest('SHA-256',new TextEncoder().encode(t))).then(h=>console.log(Array.from(new Uint8Array(h)).map(b=>b.toString(16).padStart(2,'0')).join('')))
> ```

---

## 🐳 Docker

### Build
```bash
docker build -t shadow-drop .
```

### Run with persistent data
```bash
docker run -d -p 443:4000 \
  -v ./data:/app/data \
  -v ./fullchain.pem:/app/certs/fullchain.pem:ro \
  -v ./privkey.pem:/app/certs/privkey.pem:ro \
  --name shadow-drop shadow-drop
```

### Export / Import
```bash
docker save -o shadow-drop.tar shadow-drop   # Export
docker load -i shadow-drop.tar               # Import
```

---

## ⚙️ Setup & Configuration

### Requirements
- **Node.js** (v18+ recommended).
- **HTTPS**: Required for browser crypto APIs. Mount your SSL certs or run behind a reverse proxy.

### Database
Supports **SQLite** (default) and **MySQL**. Configure in `config.js`:

```javascript
module.exports = {
    db: {
        engine: 'sqlite', // or 'mysql'
        mysql: { host: 'localhost', user: 'root', password: 'your_password', database: 'buzon' }
    }
};
```

*Note: For MySQL, run `npm install mysql2`.*

### Run
1. Install: `npm install`
2. Start: `npm start` or `node server.js`
3. Open `https://localhost:4000`

---

## 📂 Project Structure
- `/public`: Frontend (Vanilla JS, HTML, CSS). Apple-inspired premium design.
  - `crypto.js`: Cryptographic utilities (PBKDF2, RSA-OAEP, AES-GCM).
  - `integrity.js`: File integrity verification system.
  - `share.js`: Secure file sharing (PBKDF2 + AES-GCM decryption).
  - `about.html`: Security information page.
  - `share.html`: Password-protected file download page.
- `/db`: Database drivers (SQLite/MySQL).
- `/data`: Local storage (database + encrypted files).
- `server.js`: Backend API (Express) with CSP and security headers.
- `config.js`: Global configuration.
- `Dockerfile`: Alpine + Node 20 Docker image.

---
---

# 🇪🇸 Español

Shadow Drop es una plataforma de entrega de archivos y mensajes con arquitectura **Zero-Knowledge**. Permite que cualquier persona te envíe información de manera ultra-segura sin que el servidor pueda leer el contenido.

## Guía Rápida
1. **Registro**: Elige usuario y contraseña maestra. **Si la pierdes, nadie puede recuperar tus datos.**
2. **Recibir archivos**: Comparte tu enlace público o genera enlaces de un solo uso.
3. **Descargar**: Los paquetes se descifran en tu navegador. Descarga individual o masiva.
4. **Compartir ficheros**: Pulsa 📤 Share File → selecciona archivo + contraseña → se cifra con AES-256 + PBKDF2 → comparte el enlace. El receptor introduce la contraseña para descifrar.

## Seguridad
- **E2EE real** con RSA-4096 + AES-256-GCM + PBKDF2 (600K iteraciones).
- **CSP estricta**: Solo scripts propios, sin iframes, sin caché.
- **Verificación de integridad**: Hashes SHA-256 verificados contra GitHub.
- **Boss Key** (doble ESC), enlaces de un solo uso, destrucción de paquetes.
- **Diseño responsive**: Optimizado para móviles y tablets.

## Docker
```bash
docker run -d -p 443:4000 \
  -v ./data:/app/data \
  -v ./fullchain.pem:/app/certs/fullchain.pem:ro \
  -v ./privkey.pem:/app/certs/privkey.pem:ro \
  --name shadow-drop shadow-drop
```
