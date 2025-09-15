// test-db.js
const db = require('./db');

(async () => {
  try {
    const [rows] = await db.execute('SELECT 1 + 1 AS result');
    console.log('DB connected! 1+1 =', rows[0].result);
    process.exit(0);
  } catch (err) {
    console.error('DB connection error:', err);
    process.exit(1);
  }
})();
