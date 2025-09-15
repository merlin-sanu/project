// server.js (full - replace your existing file with this)
const express = require('express');
const path = require('path');
const fs = require('fs');
const session = require('express-session');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const db = require('./db'); // mysql2/promise pool
const multer = require('multer');

const app = express();
const PORT = process.env.PORT || 3000;

// ---------- Multer (same as before) ----------
const MAX_FILE_BYTES = 5 * 1024 * 1024; // 5 MB
const allowedMimes = [
  'application/pdf',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
];

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, 'uploads')),
  filename: (req, file, cb) => {
    const safe = file.originalname.replace(/\s+/g, '_').replace(/[^a-zA-Z0-9_.-]/g, '');
    const fname = `${Date.now()}-${safe}`;
    cb(null, fname);
  }
});
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

// Serve static public files and uploads
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ---------- Helpers ----------
function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.redirect('/login.html');
}

// Role-based middleware: pass one or array of allowed roles
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

// small helper: generate token
function genToken(len = 48) {
  return crypto.randomBytes(len).toString('hex');
}

// ---------- Pages ----------
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
app.post('/register', async (req, res) => {
  try {
    const { username, email, password, role } = req.body;
    if (!username || !email || !password) return res.status(400).send('Missing fields');
    const allowedRoles = ['student','faculty','parent','admin'];
    const userRole = allowedRoles.includes(role) ? role : 'student';
    const pwHash = await bcrypt.hash(password, 10);
    await db.execute('INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)', [username, email, pwHash, userRole]);
    return res.redirect('/login.html');
  } catch (err) {
    console.error('Register error:', err);
    if (err && err.code === 'ER_DUP_ENTRY') return res.status(400).send('Username or email already exists');
    return res.status(500).send('Server error');
  }
});

app.post('/login', async (req, res) => {
  try {
    const { usernameOrEmail, password } = req.body;
    if (!usernameOrEmail || !password) return res.status(400).send('Missing fields');
    const [rows] = await db.execute(
      'SELECT id, username, email, password_hash, role FROM users WHERE username = ? OR email = ? LIMIT 1',
      [usernameOrEmail, usernameOrEmail]
    );
    if (!rows || rows.length === 0) return res.status(401).send('Invalid credentials');
    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).send('Invalid credentials');

    // set session with role
    req.session.user = { id: user.id, username: user.username, email: user.email, role: user.role || 'student' };

    // record login activity (best-effort) WITHOUT user_agent as requested earlier
    try {
      const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress || (req.socket && req.socket.remoteAddress) || null;
      await db.execute('INSERT INTO login_activity (user_id, username, ip) VALUES (?, ?, ?)', [user.id, user.username, ip]);
    } catch (logErr) {
      console.error('Failed to record login activity:', logErr);
    }

    return res.redirect('/settings');
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).send('Server error');
  }
});

// ---------- Forgot/Reset (unchanged) ----------
app.post('/forgot', async (req, res) => {
  try {
    const { email, newPassword, confirmPassword } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });

    // find user
    const [rows] = await db.execute('SELECT id, username FROM users WHERE email = ? LIMIT 1', [email]);
    if (!rows || rows.length === 0) {
      // respond success to avoid enumeration
      return res.json({ ok: true, msg: 'If this email is registered, you will receive a reset link (dev: check server console).' });
    }
    const user = rows[0];

    // If newPassword provided, do quick-reset (dev-only). In production remove quick-reset.
    if (newPassword) {
      if (newPassword !== confirmPassword) return res.status(400).json({ error: 'Passwords do not match' });
      const pwHash = await bcrypt.hash(newPassword, 10);
      await db.execute('UPDATE users SET password_hash = ? WHERE id = ?', [pwHash, user.id]);
      // Optionally remove existing tokens
      await db.execute('DELETE FROM password_resets WHERE user_id = ?', [user.id]);
      return res.json({ ok: true, msg: 'Password updated. Please login.' });
    }

    // token flow: create token and log link (dev)
    const token = genToken(24);
    const expiresAt = new Date(Date.now() + 1000 * 60 * 60).toISOString().slice(0,19).replace('T',' ');
    await db.execute('INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, ?)', [user.id, token, expiresAt]);
    const resetUrl = `${req.protocol}://${req.get('host')}/reset.html?token=${token}`;
    console.log(`Password reset for ${email}. Reset URL (dev): ${resetUrl}`);
    return res.json({ ok: true, msg: 'If this email is registered, you will receive a reset link (dev: check server console).' });
  } catch (err) {
    console.error('Forgot error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

app.post('/reset', async (req, res) => {
  try {
    const { token, password } = req.body;
    if (!token || !password) return res.status(400).json({ error: 'Token and new password required' });

    const [rows] = await db.execute('SELECT id, user_id, expires_at FROM password_resets WHERE token = ? LIMIT 1', [token]);
    if (!rows || rows.length === 0) return res.status(400).json({ error: 'Invalid or expired token' });

    const rec = rows[0];
    const expires = new Date(rec.expires_at);
    if (expires < new Date()) {
      await db.execute('DELETE FROM password_resets WHERE id = ?', [rec.id]);
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    const pwHash = await bcrypt.hash(password, 10);
    await db.execute('UPDATE users SET password_hash = ? WHERE id = ?', [pwHash, rec.user_id]);
    await db.execute('DELETE FROM password_resets WHERE user_id = ?', [rec.user_id]);

    return res.json({ ok: true, msg: 'Password updated. Please login.' });
  } catch (err) {
    console.error('Reset error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// ---------- API: me (includes role now) ----------
app.get('/api/me', (req, res) => {
  if (req.session && req.session.user) return res.json({ user: req.session.user });
  return res.status(401).json({ user: null });
});

// ---------- API: stats for dashboard ----------
app.get('/api/stats', requireAuth, async (req, res) => {
  try {
    const [[facultyCount]] = await db.execute('SELECT COUNT(*) AS count FROM faculty');
    const [[aqarCount]] = await db.execute('SELECT COUNT(*) AS count FROM aqar_reports');
    const [[feedbackCount]] = await db.execute('SELECT COUNT(*) AS count FROM feedback');
    const [[accCount]] = await db.execute('SELECT COUNT(*) AS count FROM accreditations');
    res.json({
      faculty: facultyCount.count || 0,
      aqar: aqarCount.count || 0,
      feedback: feedbackCount.count || 0,
      accreditations: accCount.count || 0
    });
  } catch (err) {
    console.error('Stats error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- Faculty APIs ----------
// GET: any authenticated user can view
app.get('/api/faculty', requireAuth, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM faculty ORDER BY id DESC');
    res.json(rows);
  } catch (err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});

// POST / PUT / DELETE: only faculty or admin can modify
app.post('/api/faculty', requireAuth, requireRole(['faculty','admin']), async (req, res) => {
  try {
    const { name, department, email } = req.body;
    if (!name || !department || !email) return res.status(400).json({ error: 'Missing fields' });
    const [result] = await db.execute('INSERT INTO faculty (name, department, email) VALUES (?, ?, ?)', [name, department, email]);
    res.json({ ok: true, id: result.insertId });
  } catch (err) { console.error(err); if (err && err.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: 'Email already exists' }); res.status(500).json({ error: 'Server error' }); }
});

app.put('/api/faculty/:id', requireAuth, requireRole(['faculty','admin']), async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const { name, department, email } = req.body;
    if (!name || !department || !email) return res.status(400).json({ error: 'Missing fields' });
    await db.execute('UPDATE faculty SET name=?, department=?, email=? WHERE id=?', [name, department, email, id]);
    res.json({ ok: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/faculty/:id', requireAuth, requireRole(['faculty','admin']), async (req, res) => {
  try { const id = parseInt(req.params.id, 10); await db.execute('DELETE FROM faculty WHERE id=?', [id]); res.json({ ok: true }); }
  catch (err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});

// ---------- AQAR endpoints ----------
// GET: authenticated users can list/download
app.get('/api/aqar', requireAuth, async (req, res) => {
  try { const [rows] = await db.execute('SELECT id, filename, original_name, uploader_id, created_at FROM aqar_reports ORDER BY id DESC'); res.json(rows); }
  catch (err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});

// POST (upload) and DELETE: only faculty or admin
app.post('/api/aqar', requireAuth, requireRole(['faculty','admin']), (req, res) => {
  upload.single('report')(req, res, async function (err) {
    try {
      if (err) { console.error('Multer error:', err); return res.status(400).json({ error: err.message || 'Upload failed' }); }
      if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
      const filename = req.file.filename;
      const original = req.file.originalname;
      const uploaderId = req.session.user ? req.session.user.id : null;
      const [result] = await db.execute('INSERT INTO aqar_reports (filename, original_name, uploader_id) VALUES (?, ?, ?)', [filename, original, uploaderId]);
      return res.json({ ok: true, id: result.insertId, fileUrl: `/uploads/${filename}`, originalName: original });
    } catch (e) {
      console.error('Upload error:', e);
      try { if (req.file && req.file.path) fs.unlinkSync(req.file.path); } catch (_) {}
      return res.status(500).json({ error: 'Server error' });
    }
  });
});

app.delete('/api/aqar/:id', requireAuth, requireRole(['faculty','admin']), async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const [rows] = await db.execute('SELECT filename FROM aqar_reports WHERE id=? LIMIT 1', [id]);
    if (!rows || rows.length === 0) return res.status(404).json({ error: 'Not found' });
    const filename = rows[0].filename;
    await db.execute('DELETE FROM aqar_reports WHERE id=?', [id]);
    const filePath = path.join(__dirname, 'uploads', filename);
    fs.unlink(filePath, (err) => { if (err) console.warn('Could not delete file:', filePath, err.message); });
    return res.json({ ok: true });
  } catch (err) { console.error('Delete AQAR error:', err); res.status(500).json({ error: 'Server error' }); }
});

// ---------- Accreditations APIs ----------
// GET: any authenticated user
app.get('/api/accreditations', requireAuth, async (req, res) => {
  try { const [rows] = await db.execute('SELECT id, title, year, status, created_at FROM accreditations ORDER BY id DESC'); res.json(rows); }
  catch (err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});

// POST/PUT/DELETE: admin only (already restricted)
app.post('/api/accreditations', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const { title, year, status } = req.body;
    if (!title || !year || !status) return res.status(400).json({ error: 'Missing fields' });
    const y = parseInt(year, 10);
    if (Number.isNaN(y)) return res.status(400).json({ error: 'Year must be a number' });
    const [result] = await db.execute('INSERT INTO accreditations (title, year, status) VALUES (?, ?, ?)', [title.trim(), y, status.trim()]);
    res.json({ ok: true, id: result.insertId });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});
app.put('/api/accreditations/:id', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const { title, year, status } = req.body;
    if (!title || !year || !status) return res.status(400).json({ error: 'Missing fields' });
    const y = parseInt(year, 10);
    if (Number.isNaN(y)) return res.status(400).json({ error: 'Year must be a number' });
    await db.execute('UPDATE accreditations SET title=?, year=?, status=? WHERE id=?', [title.trim(), y, status.trim(), id]);
    res.json({ ok: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});
app.delete('/api/accreditations/:id', requireAuth, requireRole('admin'), async (req, res) => {
  try { const id = parseInt(req.params.id, 10); await db.execute('DELETE FROM accreditations WHERE id=?', [id]); res.json({ ok: true }); }
  catch (err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});

// ---------- Feedback ----------
app.get('/api/feedback', requireAuth, async (req, res) => {
  try { const [rows] = await db.execute('SELECT id, user_id, message, created_at FROM feedback ORDER BY id DESC'); res.json(rows); }
  catch (err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});
app.post('/api/feedback', requireAuth, async (req, res) => {
  try {
    const { message } = req.body;
    if (!message || message.trim().length === 0) return res.status(400).json({ error: 'Message required' });
    const userId = req.session && req.session.user ? req.session.user.id : null;
    const [result] = await db.execute('INSERT INTO feedback (user_id, message) VALUES (?, ?)', [userId, message.trim()]);
    res.json({ ok: true, id: result.insertId });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});

// ---------- Login activity (no user_agent column) ----------
app.get('/api/logins', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT id, user_id, username, ip, created_at FROM login_activity ORDER BY id DESC LIMIT 200');
    res.json(rows);
  } catch (err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});

// ---------- Misc ----------
app.get('/protected-settings', requireAuth, (req, res) => res.json({ ok: true, user: req.session.user, msg: `Hello ${req.session.user.username}` }));

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) { console.error('Error destroying session:', err); res.clearCookie('connect.sid'); return res.redirect('/'); }
    return res.redirect('/logout.html');
  });
});

// 404
app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, 'public', '404.html'), err => { if (err) res.status(404).send('404 - Page not found'); });
});

// Start
app.listen(PORT, () => console.log(`Server started: http://localhost:${PORT}`));
