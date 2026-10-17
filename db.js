const config = require('./config');

let dbDriver;

if (config.db.engine === 'mysql') {
    dbDriver = require('./db/mysql');
    console.log('Using MySQL database engine');
} else {
    // Default to SQLite
    dbDriver = require('./db/sqlite');
    console.log('Using SQLite database engine');
}

// Test aid: DB_TEST_LATENCY_MS delays every call, the way a network database (MySQL) yields to the
// event loop between queries. Never set in production.
const latency = Number(process.env.DB_TEST_LATENCY_MS) || 0;
if (latency > 0) {
    console.log(`DB_TEST_LATENCY_MS=${latency}: every database call is delayed`);
    for (const [name, fn] of Object.entries(dbDriver)) {
        if (typeof fn === 'function') {
            dbDriver[name] = async (...args) => {
                await new Promise(resolve => setTimeout(resolve, latency));
                return fn(...args);
            };
        }
    }
}

module.exports = dbDriver;
