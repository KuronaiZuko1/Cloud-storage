const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { neon } = require('@neondatabase/serverless');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 8301;

// Database connection with better error handling
if (!process.env.DATABASE_URL) {
  console.error('❌ DATABASE_URL is not set!');
  console.error('Available env vars:', Object.keys(process.env).join(', '));
  process.exit(1);
}

console.log('✅ DATABASE_URL is set, length:', process.env.DATABASE_URL.length);
const sql = neon(process.env.DATABASE_URL);

// Middleware
// CORS Configuration
const allowedOrigins = [
  'https://cloud-storage-ui.netlify.app',// Your Netlify URL
];

app.use(cors({
  origin: function(origin, callback) {
    // Allow requests with no origin (mobile apps, Postman, curl, etc.)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Multer configuration for file uploads
const storage = multer.memoryStorage();
const upload = multer({ 
  storage: storage,
  limits: { fileSize: 50 * 1024 * 1024 } // 50MB limit
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Authentication required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Initialize database tables
async function initializeDatabase() {
  try {
    // Create users table
    await sql`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        email VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `;

    // Create files table
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

    // Create default admin user if not exists
    const existingUser = await sql`
      SELECT * FROM users WHERE username = 'admin'
    `;

    if (existingUser.length === 0) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      await sql`
        INSERT INTO users (username, password, email)
        VALUES ('admin', ${hashedPassword}, 'admin@cloudstorage.com')
      `;
      console.log('✅ Default admin user created');
    }

    console.log('✅ Database initialized successfully');
  } catch (error) {
    console.error('❌ Database initialization error:', error);
  }
}

// AUTH ROUTES

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    const users = await sql`
      SELECT * FROM users WHERE username = ${username}
    `;

    if (users.length === 0) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    const user = users[0];
    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      return res.status(401).json({ message: 'Invalid username or password' });
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
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Change password (add this after login route)
app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    // Get user
    const users = await sql`
      SELECT * FROM users WHERE id = ${req.user.id}
    `;

    if (users.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const user = users[0];

    // Verify current password
    const isValid = await bcrypt.compare(currentPassword, user.password);
    if (!isValid) {
      return res.status(401).json({ message: 'Current password is incorrect' });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update password
    await sql`
      UPDATE users 
      SET password = ${hashedPassword}
      WHERE id = ${req.user.id}
    `;

    res.json({ message: 'Password changed successfully' });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Verify token
app.get('/api/auth/verify', authenticateToken, async (req, res) => {
  try {
    const users = await sql`
      SELECT id, username, email FROM users WHERE id = ${req.user.id}
    `;

    if (users.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ user: users[0] });
  } catch (error) {
    console.error('Verify token error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Logout
app.post('/api/auth/logout', authenticateToken, (req, res) => {
  res.json({ message: 'Logged out successfully' });
});

// FILE ROUTES

// Upload file
app.post('/api/files/upload', authenticateToken, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }

    const { originalname, mimetype, size, buffer } = req.file;

    const result = await sql`
      INSERT INTO files (user_id, name, original_name, mime_type, size, file_data)
      VALUES (
        ${req.user.id},
        ${originalname},
        ${originalname},
        ${mimetype},
        ${size},
        ${buffer}
      )
      RETURNING id, name, mime_type, size, uploaded_at
    `;

    res.json(result[0]);
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ message: 'Failed to upload file' });
  }
});

// Get all files for user
app.get('/api/files', authenticateToken, async (req, res) => {
  try {
    const files = await sql`
      SELECT id, name, original_name, mime_type, size, uploaded_at
      FROM files
      WHERE user_id = ${req.user.id}
      ORDER BY uploaded_at DESC
    `;

    res.json(files);
  } catch (error) {
    console.error('Get files error:', error);
    res.status(500).json({ message: 'Failed to retrieve files' });
  }
});

// Download file - FIXED VERSION
app.get('/api/files/:id/download', authenticateToken, async (req, res) => {
  try {
    const files = await sql`
      SELECT 
        id, 
        name, 
        original_name, 
        mime_type, 
        size,
        encode(file_data, 'base64') as file_data_base64
      FROM files
      WHERE id = ${req.params.id} AND user_id = ${req.user.id}
    `;

    if (files.length === 0) {
      return res.status(404).json({ message: 'File not found' });
    }

    const file = files[0];
    
    // Convert base64 back to buffer
    const fileBuffer = Buffer.from(file.file_data_base64, 'base64');

    // Set headers
    res.setHeader('Content-Type', file.mime_type || 'application/octet-stream');
    res.setHeader('Content-Length', fileBuffer.length);
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(file.original_name)}"`);
    res.setHeader('Cache-Control', 'no-cache');
    
    // Send buffer
    res.end(fileBuffer, 'binary');
  } catch (error) {
    console.error('Download error:', error);
    res.status(500).json({ message: 'Failed to download file' });
  }
});

// Delete file
app.delete('/api/files/:id', authenticateToken, async (req, res) => {
  try {
    const result = await sql`
      DELETE FROM files
      WHERE id = ${req.params.id} AND user_id = ${req.user.id}
      RETURNING id
    `;

    if (result.length === 0) {
      return res.status(404).json({ message: 'File not found' });
    }

    res.json({ message: 'File deleted successfully' });
  } catch (error) {
    console.error('Delete error:', error);
    res.status(500).json({ message: 'Failed to delete file' });
  }
});

// Get storage statistics
app.get('/api/files/stats', authenticateToken, async (req, res) => {
  try {
    const stats = await sql`
      SELECT 
        COUNT(*) as total_files,
        COALESCE(SUM(size), 0) as total_size
      FROM files
      WHERE user_id = ${req.user.id}
    `;

    res.json(stats[0]);
  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({ message: 'Failed to retrieve statistics' });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Start server
async function startServer() {
  await initializeDatabase();
  
  app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📊 Database: Connected to NeonDB`);
    console.log(`🔐 JWT Secret: ${JWT_SECRET === 'your-secret-key-change-in-production' ? '⚠️  Using default (change in production!)' : '✅ Custom secret configured'}`);
  });
}

startServer().catch(console.error);