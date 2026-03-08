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

module.exports = dbDriver;
