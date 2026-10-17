// Docker HEALTHCHECK: healthy when /api/integrity answers 200 over HTTPS or, with TLS=off, HTTP.
// The certificate is not checked here: it is a liveness probe on localhost, not a client.
const http = require('http');
const https = require('https');

const port = Number(process.env.PORT) || 4000;
const useTls = process.env.TLS !== 'off';

function probe(lib, options) {
    return new Promise(resolve => {
        const req = lib.get({ host: '127.0.0.1', port, path: '/api/integrity', timeout: 4000, ...options }, res => {
            res.resume();
            resolve(res.statusCode === 200);
        });
        req.on('timeout', () => { req.destroy(); resolve(false); });
        req.on('error', () => resolve(false));
    });
}

(async () => {
    // With TLS on but no certificates mounted the server speaks HTTP, so try both
    const ok = useTls
        ? (await probe(https, { rejectUnauthorized: false })) || (await probe(http, {}))
        : await probe(http, {});
    process.exit(ok ? 0 : 1);
})();
