// db.js
// Use the promise API from mysql2 so pool.execute() returns a Promise
const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASS || 'MySql@2025',      // <-- put your MySQL password here (or set env vars)
  database: process.env.DB_NAME || 'erp_iqac_db',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

module.exports = pool;
