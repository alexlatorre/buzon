// Settings come from environment variables so credentials never end up in git
module.exports = {
    db: {
        engine: process.env.DB_ENGINE || 'sqlite', // 'sqlite' or 'mysql'
        mysql: {
            host: process.env.MYSQL_HOST || 'localhost',
            port: Number(process.env.MYSQL_PORT) || 3306,
            user: process.env.MYSQL_USER || 'root',
            password: process.env.MYSQL_PASSWORD || '',
            database: process.env.MYSQL_DATABASE || 'buzon'
        }
    }
};
