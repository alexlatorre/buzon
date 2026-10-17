// Loads public/crypto.js the way the browser does, so tests exercise the real client crypto code
const fs = require('fs');
const path = require('path');

function loadCryptoUtils(file = path.join(__dirname, '..', 'public', 'crypto.js')) {
    const code = fs.readFileSync(file, 'utf8');
    const window = { crypto: globalThis.crypto, btoa, atob };
    return new Function('window', `${code}\nreturn CryptoUtils;`)(window);
}

module.exports = { loadCryptoUtils };
