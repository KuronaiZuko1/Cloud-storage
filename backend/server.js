// server.js
// Files are stored in Cloudflare R2.
// Neon only stores metadata (no file_data BYTEA column).

const express  = require('express');
const cors     = require('cors');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const multer   = require('multer');
const { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const { neon }  = require('@neondatabase/serverless');
require('dotenv').config();

const app  = express();
const PORT = process.env.PORT || 8301;

// =============================
// ENV VALIDATION
// FIX #1: Added JWT_SECRET to required vars — previously it had an insecure
//         hardcoded fallback ('change-this-secret') that would silently be
//         used in production if the env var was absent.
// FIX #2: Added CORS_ORIGIN so the allowed origin is configurable per
//         environment without code changes.
// =============================

const required = [
  'DATABASE_URL',
  'JWT_SECRET',          // FIX #1 — was missing; fallback was a security hole
  'R2_ACCOUNT_ID',
  'R2_ACCESS_KEY_ID',
  'R2_SECRET_ACCESS_KEY',
  'R2_BUCKET_NAME',
  'CORS_ORIGIN',         // FIX #2 — was hardcoded; now env-configurable
];

for (const key of required) {
  if (!process.env[key]) {
    console.error(`❌ Missing required environment variable: ${key}`);
    process.exit(1);
  }
}

// =============================
// DATABASE
// =============================

const sql = neon(process.env.DATABASE_URL);

// =============================
// CLOUDFLARE R2 CLIENT
// R2 is S3-compatible — we use the AWS SDK pointed at the R2 endpoint.
// =============================

const r2 = new S3Client({
  region: 'auto',
  endpoint: `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: {
    accessKeyId:     process.env.R2_ACCESS_KEY_ID,
    secretAccessKey: process.env.R2_SECRET_ACCESS_KEY,
  },
});

const BUCKET = process.env.R2_BUCKET_NAME;

// =============================
// MIDDLEWARE
// FIX #2: CORS origin now read from env var instead of a hardcoded array.
// =============================

// FIX #2 — was: const allowedOrigins = ['https://cloud-storage-ui.netlify.app'];
const allowedOrigins = process.env.CORS_ORIGIN.split(',').map(o => o.trim());

app.use(cors({
  origin: function (origin, callback) {
    // Allow server-to-server / curl requests (no Origin header)
    if (!origin) return callback(null, true);
    if (!allowedOrigins.includes(origin)) {
      return callback(new Error('CORS not allowed'), false);
    }
    return callback(null, true);
  },
  credentials: true,
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// =============================
// MULTER — memory storage (50 MB cap)
// =============================

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 },
});

// =============================
// JWT
// FIX #1: Removed insecure hardcoded fallback. JWT_SECRET is now required
//         above; if missing the process exits before reaching this line.
// =============================

const JWT_SECRET = process.env.JWT_SECRET; // FIX #1 — was: || 'change-this-secret'

// =============================
// HELPERS
// =============================

/**
 * FIX #3 & #4 — Validate and parse a route :id parameter.
 * Previously req.params.id (a string) was passed raw to SQL against a
 * SERIAL/INTEGER column.  A non-numeric value caused a Postgres cast error
 * instead of a clean 400 response, and even a valid numeric string could
 * behave unexpectedly depending on the driver version.
 * Returns the integer, or null if invalid.
 */
function parseId(param) {
  const n = parseInt(param, 10);
  return Number.isFinite(n) && n > 0 ? n : null;
}

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
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
}

// =============================
// MULTER ERROR HANDLER
// FIX #5 — Multer throws a MulterError for oversized files and other upload
//           problems. Without this middleware those errors bubble up as
//           unformatted 500s (or crash the request entirely in some Express
//           versions). We catch them here and return proper JSON responses.
// =============================

// eslint-disable-next-line no-unused-vars
function handleMulterError(err, req, res, next) {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({ message: 'File exceeds the 50 MB size limit' });
    }
    return res.status(400).json({ message: `Upload error: ${err.message}` });
  }
  next(err); // Pass non-Multer errors to the default Express error handler
}

// =============================
// DATABASE INIT
// No file_data column — files live in R2, DB stores r2_key only.
// =============================

async function initializeDatabase() {

  await sql`
    CREATE TABLE IF NOT EXISTS users (
      id         SERIAL PRIMARY KEY,
      username   VARCHAR(255) UNIQUE NOT NULL,
      password   VARCHAR(255) NOT NULL,
      email      VARCHAR(255),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `;

  await sql`
    CREATE TABLE IF NOT EXISTS files (
      id            SERIAL PRIMARY KEY,
      user_id       INTEGER REFERENCES users(id) ON DELETE CASCADE,
      original_name VARCHAR(500) NOT NULL,
      mime_type     VARCHAR(100),
      size          BIGINT NOT NULL,
      r2_key        VARCHAR(1000) NOT NULL,
      uploaded_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `;

  const admin = await sql`SELECT id FROM users WHERE username = 'admin'`;

  if (admin.length === 0) {
    const hash = await bcrypt.hash('admin123', 10);
    await sql`
      INSERT INTO users (username, password, email)
      VALUES ('admin', ${hash}, 'admin@cloudstorage.com')
    `;
    console.log('✅ Default admin created (username: admin, password: admin123)');
  }
}

// =============================
// AUTH ROUTES
// =============================

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    const users = await sql`SELECT * FROM users WHERE username = ${username}`;

    if (users.length === 0) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const user  = users[0];
    const valid = await bcrypt.compare(password, user.password);

    if (!valid) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({ token, user: { id: user.id, username: user.username, email: user.email } });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/auth/verify', authenticateToken, async (req, res) => {
  try {
    const user = await sql`
      SELECT id, username, email FROM users WHERE id = ${req.user.id}
    `;
    if (user.length === 0) return res.status(404).json({ message: 'User not found' });
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

// --- Upload ---
// Multer buffers the file in memory, then we stream it straight to R2.
// Only metadata is written to Postgres.
app.post(
  '/api/files/upload',
  authenticateToken,
  // FIX #5: wrap upload.single so Multer errors reach handleMulterError below
  (req, res, next) => upload.single('file')(req, res, next),
  handleMulterError, // FIX #5 — catch MulterError (e.g. LIMIT_FILE_SIZE) here
  async (req, res) => {
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }

    const { originalname, mimetype, size, buffer } = req.file;
    const r2Key = `${req.user.id}/${Date.now()}-${originalname}`;

    // FIX #6 — Upload to R2 first, then write DB metadata.
    // If the DB insert fails we delete the orphaned R2 object so storage
    // and the database never drift out of sync.
    // Previously a DB failure left an unreachable object in R2 permanently.
    try {
      await r2.send(new PutObjectCommand({
        Bucket:      BUCKET,
        Key:         r2Key,
        Body:        buffer,
        ContentType: mimetype,
      }));
    } catch (err) {
      console.error('R2 upload error:', err);
      return res.status(500).json({ message: 'Upload to storage failed' });
    }

    try {
      const result = await sql`
        INSERT INTO files (user_id, original_name, mime_type, size, r2_key)
        VALUES (${req.user.id}, ${originalname}, ${mimetype}, ${size}, ${r2Key})
        RETURNING id, original_name, mime_type, size, uploaded_at
      `;
      return res.json(result[0]);
    } catch (dbErr) {
      // FIX #6 — Compensating delete: roll back the R2 object on DB failure
      console.error('DB insert error (rolling back R2 object):', dbErr);
      try {
        await r2.send(new DeleteObjectCommand({ Bucket: BUCKET, Key: r2Key }));
      } catch (cleanupErr) {
        console.error('R2 cleanup after DB failure also failed:', cleanupErr);
      }
      return res.status(500).json({ message: 'Upload failed' });
    }
  }
);

// --- List files ---
app.get('/api/files', authenticateToken, async (req, res) => {
  try {
    const files = await sql`
      SELECT id, original_name, mime_type, size, uploaded_at
      FROM files
      WHERE user_id = ${req.user.id}
      ORDER BY uploaded_at DESC
    `;
    res.json(files);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// --- Stats ---
// Must stay BEFORE /:id routes so Express doesn't match "stats" as an id.
app.get('/api/files/stats', authenticateToken, async (req, res) => {
  try {
    const stats = await sql`
      SELECT COUNT(*) as total_files, COALESCE(SUM(size), 0) as total_size
      FROM files
      WHERE user_id = ${req.user.id}
    `;
    res.json(stats[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// --- Download ---
// Generates a short-lived pre-signed R2 URL (15 min) and redirects the
// client to it. No binary data passes through the server at all.
app.get('/api/files/:id/download', authenticateToken, async (req, res) => {
  // FIX #3 & #4 — Validate :id before hitting the DB. Previously a
  // non-numeric id (e.g. "abc") caused a Postgres cast error (500) instead
  // of a clean 400.
  const fileId = parseId(req.params.id);
  if (!fileId) return res.status(400).json({ message: 'Invalid file ID' });

  try {
    const files = await sql`
      SELECT original_name, mime_type, r2_key
      FROM files
      WHERE id = ${fileId} AND user_id = ${req.user.id}
    `;

    if (files.length === 0) {
      return res.status(404).json({ message: 'File not found' });
    }

    const { r2_key, original_name, mime_type } = files[0];

    // FIX #7 — Use RFC 5987 encoding for the Content-Disposition filename.
    // Previously encodeURIComponent() was applied inside double-quotes, which
    // double-encodes the value and produces a garbled filename in most
    // browsers. RFC 5987 (filename*=UTF-8''...) handles non-ASCII names
    // correctly; we keep a plain ASCII fallback for older clients.
    const asciiName    = original_name.replace(/[^\x20-\x7E]/g, '_');
    const encodedName  = encodeURIComponent(original_name);
    const disposition  =
      `attachment; filename="${asciiName}"; filename*=UTF-8''${encodedName}`;

    const signedUrl = await getSignedUrl(
      r2,
      new GetObjectCommand({
        Bucket:                     BUCKET,
        Key:                        r2_key,
        ResponseContentDisposition: disposition,      // FIX #7
        ResponseContentType:        mime_type || 'application/octet-stream',
      }),
      { expiresIn: 900 } // 15 minutes
    );

    // Redirect the browser directly to R2 — no binary proxying needed.
    res.redirect(signedUrl);

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Download failed' });
  }
});

// --- Delete ---
// Removes the object from R2 first, then removes the metadata row.
app.delete('/api/files/:id', authenticateToken, async (req, res) => {
  // FIX #3 & #4 — Validate :id before hitting the DB.
  const fileId = parseId(req.params.id);
  if (!fileId) return res.status(400).json({ message: 'Invalid file ID' });

  try {
    const files = await sql`
      SELECT r2_key FROM files
      WHERE id = ${fileId} AND user_id = ${req.user.id}
    `;

    if (files.length === 0) {
      return res.status(404).json({ message: 'File not found' });
    }

    // Delete from R2
    await r2.send(new DeleteObjectCommand({
      Bucket: BUCKET,
      Key:    files[0].r2_key,
    }));

    // Delete metadata row
    await sql`DELETE FROM files WHERE id = ${fileId}`;

    res.json({ message: 'File deleted' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// --- Health ---
app.get('/health', (req, res) => {
  res.json({ status: 'OK', time: new Date() });
});

// =============================
// GLOBAL ERROR HANDLER
// FIX #5 (continued) — catches any unhandled errors that reach here,
// including Multer errors that weren't consumed by handleMulterError.
// =============================

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ message: 'Internal server error' });
});

// =============================
// START
// =============================

async function start() {
  await initializeDatabase();
  app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
  });
}

start();
