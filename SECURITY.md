# Security policy

Shadow Drop is a personal open-source project. Security reports are welcome and handled on a best-effort basis.

## Supported versions

Only the latest release on `master` (2.x) gets fixes. Upgrade before reporting if you run something older.

## Reporting a vulnerability

Please **do not open a public issue** for a vulnerability.

Use GitHub's private reporting instead: open the repository's **Security** tab and choose **Report a vulnerability**. If that option is not available, open an issue that only asks for a private contact, without any details.

A useful report says:

- what an attacker can do, and from which position (anonymous sender, link holder, logged-in user, malicious server, someone with a copy of the database);
- the steps or a proof of concept against a local install (`TLS=off npm start`);
- the version or commit you tested.

Please test only against your own installation, never against someone else's server.

## What is in scope

- Anything that lets the server, a sender or a link holder read content, file names or keys it should not, or tamper with them unnoticed.
- Weaknesses in the browser-side cryptography (`public/crypto.js`, `public/app.js`, `public/drop.js`, `public/share.js`).
- Server-side flaws: authentication, sessions, access to another user's packages or shares, quota or rate-limit bypasses, file handling.

## Known limits (not vulnerabilities)

These are documented in the README under *Threat model and limitations*:

- A server that controls its own HTTP responses can serve modified JavaScript. The integrity check makes this visible but cannot prevent it.
- Metadata visible to the server: who receives packages and when, file counts and sizes, the sender name as typed.
- What an attacker already copied (an old database, or old encrypted keys plus an old password) stays readable with what they had. Key rotation and password changes protect what comes after.
