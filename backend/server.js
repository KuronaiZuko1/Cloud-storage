// server.js

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { neon } = require('@neondatabase/serverless');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 8301;

// =============================
// DATABASE CONNECTION
// =============================

if (!process.env.DATABASE_URL) {
  console.error('❌ DATABASE_URL not found in environment variables');
  process.exit(1);
}

const sql = neon(process.env.DATABASE_URL);

// =============================
// MIDDLEWARE
// =============================

const allowedOrigins = [
  'https://cloud-storage-ui.netlify.app'
];

app.use(cors({
  origin: function(origin, callback) {
    if (!origin) return callback(null, true);

    if (!allowedOrigins.includes(origin)) {
      return callback(new Error('CORS not allowed'), false);
    }

    return callback(null, true);
  },
  credentials: true
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// =============================
// FILE UPLOAD CONFIG
// =============================

const storage = multer.memoryStorage();

const upload = multer({
  storage,
  limits: {
    fileSize: 50 * 1024 * 1024
  }
});

// =============================
// JWT
// =============================

const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret';

// =============================
// AUTH MIDDLEWARE
// =============================

function authenticateToken(req, res, next) {

  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Authentication required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {

    if (err) {
      return res.status(403).json({ message: 'Invalid token' });
    }

    req.user = user;
    next();

  });
}

// =============================
// DATABASE INIT
// =============================

async function initializeDatabase() {

  await sql`
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )
  `;

  await sql`
  CREATE TABLE IF NOT EXISTS files (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(500) NOT NULL,
    original_name VARCHAR(500) NOT NULL,
    mime_type VARCHAR(100),
    size BIGINT NOT NULL,
    file_data BYTEA NOT NULL,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )
  `;

  const admin = await sql`
  SELECT * FROM users WHERE username='admin'
  `;

  if (admin.length === 0) {

    const hash = await bcrypt.hash('admin123', 10);

    await sql`
    INSERT INTO users (username,password,email)
    VALUES ('admin',${hash},'admin@cloudstorage.com')
    `;

    console.log('✅ Default admin created');
  }

}

// =============================
// AUTH ROUTES
// =============================

app.post('/api/auth/login', async (req, res) => {

  try {

    const { username, password } = req.body;

    const users = await sql`
    SELECT * FROM users WHERE username=${username}
    `;

    if (users.length === 0) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const user = users[0];

    const valid = await bcrypt.compare(password, user.password);

    if (!valid) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email
      }
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }

});

// FIX 3: Added try/catch to prevent unhandled crash on DB error
app.get('/api/auth/verify', authenticateToken, async (req, res) => {

  try {

    const user = await sql`
    SELECT id,username,email FROM users WHERE id=${req.user.id}
    `;

    if (user.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ user: user[0] });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }

});

app.post('/api/auth/logout', authenticateToken, (req, res) => {
  res.json({ message: 'Logged out' });
});

// =============================
// FILE ROUTES
// =============================

// Upload file
app.post('/api/files/upload', authenticateToken, upload.single('file'), async (req, res) => {

  try {

    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }

    const { originalname, mimetype, size, buffer } = req.file;

    const fileBuffer = Buffer.isBuffer(buffer)
      ? buffer
      : Buffer.from(buffer);

    const result = await sql`
    INSERT INTO files
    (user_id,name,original_name,mime_type,size,file_data)
    VALUES
    (
      ${req.user.id},
      ${originalname},
      ${originalname},
      ${mimetype},
      ${size},
      ${fileBuffer}
    )
    RETURNING id,name,mime_type,size,uploaded_at
    `;

    res.json(result[0]);

  } catch (err) {

    console.error(err);
    res.status(500).json({ message: 'Upload failed' });

  }

});

// Get files
// FIX 4: Added try/catch to prevent unhandled crash on DB error
app.get('/api/files', authenticateToken, async (req, res) => {

  try {

    const files = await sql`
    SELECT id,name,original_name,mime_type,size,uploaded_at
    FROM files
    WHERE user_id=${req.user.id}
    ORDER BY uploaded_at DESC
    `;

    res.json(files);

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }

});

// FIX 1 (CRITICAL): Moved /api/files/stats BEFORE /api/files/:id routes.
// Express matches routes in order — if :id routes come first, "stats" is
// treated as a file ID and this endpoint is never reached.

// Stats
app.get('/api/files/stats', authenticateToken, async (req, res) => {

  try {

    const stats = await sql`
    SELECT
    COUNT(*) as total_files,
    COALESCE(SUM(size),0) as total_size
    FROM files
    WHERE user_id=${req.user.id}
    `;

    res.json(stats[0]);

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }

});

// Download file
app.get('/api/files/:id/download', authenticateToken, async (req, res) => {

  try {

    const files = await sql`
    SELECT
      original_name,
      mime_type,
      file_data
    FROM files
    WHERE id=${req.params.id}
    AND user_id=${req.user.id}
    `;

    if (files.length === 0) {
      return res.status(404).json({ message: 'File not found' });
    }

    const file = files[0];

    let buffer = file.file_data;

    // Neon serverless returns BYTEA as { type: 'Buffer', data: [...] }
    // Buffer.isBuffer() returns false for this plain object, so we must
    // explicitly handle all three possible shapes:
    if (Buffer.isBuffer(buffer)) {
      // already a real Buffer — nothing to do
    } else if (typeof buffer === 'string') {
      // hex-encoded string (e.g. "\\x414243...")
      buffer = buffer.startsWith('\\x')
        ? Buffer.from(buffer.slice(2), 'hex')
        : Buffer.from(buffer, 'base64');
    } else if (buffer && buffer.type === 'Buffer' && Array.isArray(buffer.data)) {
      // plain object from Neon: { type: 'Buffer', data: [47, 47, ...] }
      buffer = Buffer.from(buffer.data);
    } else {
      // fallback: try to wrap whatever it is
      buffer = Buffer.from(buffer);
    }

    res.setHeader('Content-Type', file.mime_type || 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(file.original_name)}"`);
    res.setHeader('Content-Length', buffer.length);

    res.send(buffer);

  } catch (err) {

    console.error(err);
    res.status(500).json({ message: 'Download failed' });

  }

});

// Delete file
// FIX 5: Added try/catch to prevent unhandled crash on DB error
app.delete('/api/files/:id', authenticateToken, async (req, res) => {

  try {

    const result = await sql`
    DELETE FROM files
    WHERE id=${req.params.id}
    AND user_id=${req.user.id}
    RETURNING id
    `;

    if (result.length === 0) {
      return res.status(404).json({ message: 'File not found' });
    }

    res.json({ message: 'File deleted' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }

});

// Health
app.get('/health', (req, res) => {
  res.json({ status: 'OK', time: new Date() });
});

// =============================
// START SERVER
// =============================

async function start() {

  await initializeDatabase();

  app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
  });

}

start();
