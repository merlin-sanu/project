// server.js
require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const session = require('express-session');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const multer = require('multer');
const mysql = require('mysql2/promise');
const cloudinary = require('cloudinary').v2;

const app = express();
const PORT = process.env.PORT || 3000;

// ---------- Cloudinary config (reads from env) ----------
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true
});

// ---------------------
// Diagnostic logging for DATABASE_URL
// ---------------------
const rawDb = process.env.DATABASE_URL || '';
if (rawDb) {
  try {
    const masked = rawDb.replace(/\/\/([^:]+):([^@]+)@/, '//$1:*****@');
    console.log('DIAG: DATABASE_URL present (masked):', masked);
  } catch (e) {
    console.log('DIAG: DATABASE_URL present (raw starts):', rawDb.slice(0, 50));
  }
} else {
  console.log('DIAG: DATABASE_URL NOT SET — falling back to DB_HOST/localhost');
}

// ---------------------
// DB pool helper (single-file, reusable pool)
// ---------------------
let pool = null;
async function getPool() {
  if (pool) return pool;

  try {
    if (process.env.DATABASE_URL) {
      pool = mysql.createPool(process.env.DATABASE_URL);
    } else {
      pool = mysql.createPool({
        host: process.env.DB_HOST || '127.0.0.1',
        user: process.env.DB_USER || 'root',
        password: process.env.DB_PASS || '',
        database: process.env.DB_NAME || 'erp_iqac_db',
        port: parseInt(process.env.DB_PORT || '3306', 10),
        waitForConnections: true,
        connectionLimit: 10,
        queueLimit: 0
      });
    }

    try {
      const [rows] = await pool.query('SELECT 1 AS ok');
      console.log('DB test OK:', rows && rows[0] ? rows[0].ok : rows);
    } catch (tErr) {
      console.error('DB test query failed:', tErr && (tErr.message || tErr));
    }

    return pool;
  } catch (err) {
    console.error('Failed to create DB pool:', err && err.message ? err.message : err);
    throw err;
  }
}

const db = {
  query: async (...args) => {
    const p = await getPool();
    return p.query(...args);
  },
  getConnection: async () => {
    const p = await getPool();
    return p.getConnection();
  }
};

// Ensure uploads folder exists locally for dev (not used for production Cloudinary)
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  try { fs.mkdirSync(uploadsDir, { recursive: true }); } catch (_) {}
}

// ---------- Multer (memory storage for cloud uploads) ----------
const MAX_FILE_BYTES = 5 * 1024 * 1024; // 5 MB
const allowedMimes = [
  'application/pdf',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
];

const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: MAX_FILE_BYTES },
  fileFilter: (req, file, cb) => {
    if (allowedMimes.includes(file.mimetype)) cb(null, true);
    else cb(new Error('Invalid file type. Only PDF/DOC/DOCX allowed.'));
  }
});

// ---------- Middleware ----------
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'replace-this-with-a-secure-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 }
}));

// ---------- Helpers ----------
function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  if (req.headers.accept && req.headers.accept.includes('application/json')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  return res.redirect('/login.html');
}

function requireRole(allowed) {
  return (req, res, next) => {
    if (!req.session || !req.session.user) return res.redirect('/login.html');
    const role = req.session.user.role || 'student';
    if (Array.isArray(allowed)) {
      if (allowed.includes(role)) return next();
    } else {
      if (role === allowed) return next();
    }
    if (req.headers.accept && req.headers.accept.includes('application/json')) {
      return res.status(403).json({ error: 'Forbidden - insufficient permissions' });
    }
    return res.status(403).send('Forbidden - insufficient permissions');
  };
}

function genToken(len = 48) {
  return crypto.randomBytes(len).toString('hex');
}

// ---------- Health (API) ----------
app.get('/api/ping', (req, res) => res.json({ ok: true, time: Date.now() }));

// ---------- Pages / API routes (API routes come BEFORE static) ----------
app.get(['/', '/dashboard', '/index.html'], (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/aqar', requireAuth, (req, res) => res.sendFile(path.join(__dirname, 'public', 'aqar.html')));
app.get('/accreditations', requireAuth, (req, res) => res.sendFile(path.join(__dirname, 'public', 'accreditations.html')));
app.get('/feedback', requireAuth, (req, res) => res.sendFile(path.join(__dirname, 'public', 'feedback.html')));
app.get('/faculty', requireAuth, (req, res) => res.sendFile(path.join(__dirname, 'public', 'faculty.html')));
app.get('/settings', requireAuth, (req, res) => res.sendFile(path.join(__dirname, 'public', 'settings.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'public', 'register.html')));
app.get('/logout.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'logout.html')));
app.get('/forgot', (req, res) => res.sendFile(path.join(__dirname, 'public', 'forgot.html')));
app.get('/reset', (req, res) => res.sendFile(path.join(__dirname, 'public', 'reset.html')));

// ---------- Auth: register/login ----------
app.post('/register', async (req, res, next) => {
  try {
    const { username, email, password, role } = req.body;
    if (!username || !email || !password) return res.status(400).send('Missing fields');
    const allowedRoles = ['student','faculty','parent','admin'];
    const userRole = allowedRoles.includes(role) ? role : 'student';
    const pwHash = await bcrypt.hash(password, 10);

    await db.query('INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)', [username, email, pwHash, userRole]);
    return res.redirect('/login.html');
  } catch (err) {
    console.error('Register error:', err);
    if (err && err.code === 'ER_DUP_ENTRY') return res.status(400).send('Username or email already exists');
    return next(err);
  }
});

app.post('/login', async (req, res, next) => {
  try {
    const { usernameOrEmail, password } = req.body;
    if (!usernameOrEmail || !password) return res.status(400).send('Missing fields');
    const [rows] = await db.query(
      'SELECT id, username, email, password_hash, role FROM users WHERE username = ? OR email = ? LIMIT 1',
      [usernameOrEmail, usernameOrEmail]
    );
    if (!rows || rows.length === 0) return res.status(401).send('Invalid credentials');
    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).send('Invalid credentials');

    req.session.user = { id: user.id, username: user.username, email: user.email, role: user.role || 'student' };

    try {
      const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress || (req.socket && req.socket.remoteAddress) || null;
      await db.query('INSERT INTO login_activity (user_id, username, ip) VALUES (?, ?, ?)', [user.id, user.username, ip]);
    } catch (logErr) {
      console.error('Failed to record login activity:', logErr);
    }

    return res.redirect('/settings');
  } catch (err) {
    console.error('Login error:', err);
    return next(err);
  }
});

// ---------- Forgot / Reset ----------
app.post('/forgot', async (req, res, next) => {
  try {
    const { email, newPassword, confirmPassword } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });

    const [rows] = await db.query('SELECT id, username FROM users WHERE email = ? LIMIT 1', [email]);
    if (!rows || rows.length === 0) {
      return res.json({ ok: true, msg: 'If this email is registered, you will receive a reset link (dev: check server console).' });
    }
    const user = rows[0];

    if (newPassword) {
      if (newPassword !== confirmPassword) return res.status(400).json({ error: 'Passwords do not match' });
      const pwHash = await bcrypt.hash(newPassword, 10);
      await db.query('UPDATE users SET password_hash = ? WHERE id = ?', [pwHash, user.id]);
      await db.query('DELETE FROM password_resets WHERE user_id = ?', [user.id]);
      return res.json({ ok: true, msg: 'Password updated. Please login.' });
    }

    const token = genToken(24);
    const expiresAt = new Date(Date.now() + 1000 * 60 * 60).toISOString().slice(0,19).replace('T',' ');
    await db.query('INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, ?)', [user.id, token, expiresAt]);
    const resetUrl = `${req.protocol}://${req.get('host')}/reset.html?token=${token}`;
    console.log(`Password reset for ${email}. Reset URL (dev): ${resetUrl}`);
    return res.json({ ok: true, msg: 'If this email is registered, you will receive a reset link (dev: check server console).' });
  } catch (err) {
    console.error('Forgot error:', err);
    return next(err);
  }
});

app.post('/reset', async (req, res, next) => {
  try {
    const { token, password } = req.body;
    if (!token || !password) return res.status(400).json({ error: 'Token and new password required' });

    const [rows] = await db.query('SELECT id, user_id, expires_at FROM password_resets WHERE token = ? LIMIT 1', [token]);
    if (!rows || rows.length === 0) return res.status(400).json({ error: 'Invalid or expired token' });

    const rec = rows[0];
    const expires = new Date(rec.expires_at);
    if (expires < new Date()) {
      await db.query('DELETE FROM password_resets WHERE id = ?', [rec.id]);
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    const pwHash = await bcrypt.hash(password, 10);
    await db.query('UPDATE users SET password_hash = ? WHERE id = ?', [pwHash, rec.user_id]);
    await db.query('DELETE FROM password_resets WHERE user_id = ?', [rec.user_id]);

    return res.json({ ok: true, msg: 'Password updated. Please login.' });
  } catch (err) {
    console.error('Reset error:', err);
    return next(err);
  }
});

// ---------- API endpoints ----------
app.get('/api/me', (req, res) => {
  if (req.session && req.session.user) return res.json({ user: req.session.user });
  return res.status(401).json({ user: null });
});

app.get('/api/stats', requireAuth, async (req, res, next) => {
  try {
    const [[facultyCount]] = await db.query('SELECT COUNT(*) AS count FROM faculty');
    const [[aqarCount]] = await db.query('SELECT COUNT(*) AS count FROM aqar_reports');
    const [[feedbackCount]] = await db.query('SELECT COUNT(*) AS count FROM feedback');
    const [[accCount]] = await db.query('SELECT COUNT(*) AS count FROM accreditations');
    res.json({
      faculty: facultyCount.count || 0,
      aqar: aqarCount.count || 0,
      feedback: feedbackCount.count || 0,
      accreditations: accCount.count || 0
    });
  } catch (err) { console.error('Stats error', err); return next(err); }
});

// Faculty APIs
app.get('/api/faculty', requireAuth, async (req, res, next) => {
  try { const [rows] = await db.query('SELECT * FROM faculty ORDER BY id DESC'); res.json(rows); } catch (err) { console.error(err); return next(err); }
});
app.post('/api/faculty', requireAuth, requireRole(['faculty','admin']), async (req, res, next) => {
  try {
    const { name, department, email } = req.body;
    if (!name || !department || !email) return res.status(400).json({ error: 'Missing fields' });
    const [result] = await db.query('INSERT INTO faculty (name, department, email) VALUES (?, ?, ?)', [name, department, email]);
    res.json({ ok: true, id: result.insertId });
  } catch (err) { console.error(err); if (err && err.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: 'Email already exists' }); return next(err); }
});
app.put('/api/faculty/:id', requireAuth, requireRole(['faculty','admin']), async (req, res, next) => {
  try { const id = parseInt(req.params.id, 10); const { name, department, email } = req.body; if (!name || !department || !email) return res.status(400).json({ error: 'Missing fields' }); await db.query('UPDATE faculty SET name=?, department=?, email=? WHERE id=?', [name, department, email, id]); res.json({ ok: true }); } catch (err) { console.error(err); return next(err); }
});
app.delete('/api/faculty/:id', requireAuth, requireRole(['faculty','admin']), async (req, res, next) => {
  try { const id = parseInt(req.params.id, 10); await db.query('DELETE FROM faculty WHERE id=?', [id]); res.json({ ok: true }); } catch (err) { console.error(err); return next(err); }
});

// AQAR endpoints (uploads)
app.get('/api/aqar', requireAuth, async (req, res, next) => {
  try { const [rows] = await db.query('SELECT id, filename, original_name, uploader_id, created_at FROM aqar_reports ORDER BY id DESC'); res.json(rows); } catch (err) { console.error(err); return next(err); }
});

app.post('/api/aqar', requireAuth, requireRole(['faculty','admin']), (req, res, next) => {
  upload.single('report')(req, res, async function (err) {
    if (err) {
      console.error('Multer error:', err);
      return res.status(400).json({ error: err.message || 'Upload failed' });
    }
    try {
      if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
      const filename = req.file.filename;
      const original = req.file.originalname;
      const uploaderId = req.session.user ? req.session.user.id : null;
      const [result] = await db.query('INSERT INTO aqar_reports (filename, original_name, uploader_id) VALUES (?, ?, ?)', [filename, original, uploaderId]);
      return res.json({ ok: true, id: result.insertId, fileUrl: `/uploads/${filename}`, originalName: original });
    } catch (e) {
      console.error('Upload error:', e);
      try { if (req.file && req.file.path) fs.unlinkSync(req.file.path); } catch (_) {}
      return next(e);
    }
  });
});

app.delete('/api/aqar/:id', requireAuth, requireRole(['faculty','admin']), async (req, res, next) => {
  try {
    const id = parseInt(req.params.id, 10);
    const [rows] = await db.query('SELECT filename FROM aqar_reports WHERE id=? LIMIT 1', [id]);
    if (!rows || rows.length === 0) return res.status(404).json({ error: 'Not found' });
    const filename = rows[0].filename;
    await db.query('DELETE FROM aqar_reports WHERE id=?', [id]);
    const filePath = path.join(uploadsDir, filename);
    fs.unlink(filePath, (err) => { if (err) console.warn('Could not delete file:', filePath, err && err.message); });
    return res.json({ ok: true });
  } catch (err) { console.error('Delete AQAR error:', err); return next(err); }
});

// Accreditations APIs
app.get('/api/accreditations', requireAuth, async (req, res, next) => {
  try { const [rows] = await db.query('SELECT id, title, year, status, created_at FROM accreditations ORDER BY id DESC'); res.json(rows); } catch (err) { console.error(err); return next(err); }
});
app.post('/api/accreditations', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const { title, year, status } = req.body;
    if (!title || !year || !status) return res.status(400).json({ error: 'Missing fields' });
    const y = parseInt(year, 10);
    if (Number.isNaN(y)) return res.status(400).json({ error: 'Year must be a number' });
    const [result] = await db.query('INSERT INTO accreditations (title, year, status) VALUES (?, ?, ?)', [title.trim(), y, status.trim()]);
    res.json({ ok: true, id: result.insertId });
  } catch (err) { console.error(err); return next(err); }
});
app.put('/api/accreditations/:id', requireAuth, requireRole('admin'), async (req, res, next) => {
  try { const id = parseInt(req.params.id, 10); const { title, year, status } = req.body; if (!title || !year || !status) return res.status(400).json({ error: 'Missing fields' }); const y = parseInt(year, 10); if (Number.isNaN(y)) return res.status(400).json({ error: 'Year must be a number' }); await db.query('UPDATE accreditations SET title=?, year=?, status=? WHERE id=?', [title.trim(), y, status.trim(), id]); res.json({ ok: true }); } catch (err) { console.error(err); return next(err); }
});
app.delete('/api/accreditations/:id', requireAuth, requireRole('admin'), async (req, res, next) => {
  try { const id = parseInt(req.params.id, 10); await db.query('DELETE FROM accreditations WHERE id=?', [id]); res.json({ ok: true }); } catch (err) { console.error(err); return next(err); }
});

// Feedback
app.get('/api/feedback', requireAuth, async (req, res, next) => {
  try { const [rows] = await db.query('SELECT id, user_id, message, created_at FROM feedback ORDER BY id DESC'); res.json(rows); } catch (err) { console.error(err); return next(err); }
});
app.post('/api/feedback', requireAuth, async (req, res, next) => {
  try {
    const { message } = req.body;
    if (!message || message.trim().length === 0) return res.status(400).json({ error: 'Message required' });
    const userId = req.session && req.session.user ? req.session.user.id : null;
    const [result] = await db.query('INSERT INTO feedback (user_id, message) VALUES (?, ?)', [userId, message.trim()]);
    res.json({ ok: true, id: result.insertId });
  } catch (err) { console.error(err); return next(err); }
});

// Login activity
app.get('/api/logins', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const [rows] = await db.query('SELECT id, user_id, username, ip, created_at FROM login_activity ORDER BY id DESC LIMIT 200');
    res.json(rows);
  } catch (err) { console.error(err); return next(err); }
});

// Misc
app.get('/protected-settings', requireAuth, (req, res) => res.json({ ok: true, user: req.session.user, msg: `Hello ${req.session.user.username}` }));

// Logout
We must return full corrected code truncated previously. Provide updated /api/aqar and delete behavior. Let's craft full final server.js continuing from where truncated. Ensure all routes included. At end start listening. Provide final code.
::contentReference[oaicite:0]{index=0}
