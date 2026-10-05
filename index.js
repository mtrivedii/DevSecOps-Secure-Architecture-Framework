// index.js

const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');

// Import handlers & routers
const checkAdminHandler = require('./checkAdmin');
const getSasTokenHandler = require('./getSasToken');
const verifyUploadHandler = require('./verifyUpload');
const usersRouter = require('./users');
const twoFARouter = require('./2fa');
const registerRouter = require('./register'); 
const loginRouter = require('./login');
const requireAdminDb = require('./requireAdminDB');

const app = express();

app.disable('x-powered-by');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser()); // Enable cookie parsing

// Updated CORS configuration for credentials
app.use((req, res, next) => {
  // For security with cookies, you can't use '*' with credentials
  const allowedOrigins = ['https://maanitwebapp.com', 'http://localhost:3000'];
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-CSRF-Token');
  res.setHeader('Access-Control-Allow-Credentials', 'true'); // Enable credentials for CORS
  
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  next();
});

// Security headers
app.use((req, res, next) => {
 res.setHeader(
   'Content-Security-Policy',
   "default-src 'self'; " +
     "script-src 'self'; " +
     "style-src 'self' 'unsafe-inline'; " +
     "img-src 'self' data: https://api.qrserver.com; " +
     "connect-src 'self' https://*.blob.core.windows.net " +
     "https://*.microsoftonline.com https://login.microsoft.com " +
     "https://maanit-func.azurewebsites.net; " +
     "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
 );
 res.setHeader('X-Frame-Options', 'DENY');
 res.setHeader('X-Content-Type-Options', 'nosniff');
 res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
 res.setHeader('Permissions-Policy', 'camera=(), geolocation=(), microphone=()');
 res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
 next();
});

// Debug logger
app.use((req, res, next) => {
 // Do not log headers: they carry the session cookie and the Authorization header.
 console.log(`[DEBUG] ${req.method} ${req.url} - IP: ${req.ip}`);
 next();
});

// Easy Auth guard
function requireAuth(req, res, next) {
 const principal = req.headers['x-ms-client-principal'];
 if (!principal) {
   return res.redirect(
     '/.auth/login/aad?post_login_redirect_uri=' +
       encodeURIComponent(req.originalUrl)
   );
 }
 next();
}

// === API Routes ===
app.get('/api/checkAdmin', checkAdminHandler.handler);
app.post('/api/checkAdmin', checkAdminHandler.handler);

app.get('/api/getSasToken', getSasTokenHandler.handler);
app.post('/api/verifyUpload', verifyUploadHandler.handler);
app.options('/api/getSasToken', (req, res) => {
  // Updated CORS for specific routes too
  const allowedOrigins = ['https://maanitwebapp.com', 'http://localhost:3000'];
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-CSRF-Token');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Max-Age', '86400');
  res.status(200).end();
});

// Mount routes - login route is NOT behind requireAuth
app.use('/api/register', registerRouter);
app.use('/api/2fa', twoFARouter);
app.use('/api', loginRouter);
app.use('/api', usersRouter);

// === Protected Admin Pages ===
app.get('/admin.html', requireAdminDb, (req, res) => {
 res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});
app.get('/security.html', requireAdminDb, (req, res) => {
 res.sendFile(path.join(__dirname, 'public', 'security.html'));
});
app.get('/users.html', requireAdminDb, (req, res) => {
 res.sendFile(path.join(__dirname, 'public', 'users.html'));
});

// === Static File Serving ===
app.use(express.static(path.join(__dirname, 'public'), {
 setHeaders: (res, filePath) => {
   // Apply CSP to non-static assets
   if (!filePath.match(/\.(css|js)$/)) {
     res.setHeader(
       'Content-Security-Policy',
       "default-src 'self'; " +
         "script-src 'self'; " +
         "style-src 'self' 'unsafe-inline'; " +
         "img-src 'self' data: https://api.qrserver.com; " +
         "connect-src 'self' https://*.blob.core.windows.net " +
         "https://*.microsoftonline.com https://login.microsoft.com " +
         "https://maanit-func.azurewebsites.net; " +
     "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
     );
   }
   res.setHeader('X-Frame-Options', 'DENY');
   res.setHeader('X-Content-Type-Options', 'nosniff');
   res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
   res.setHeader('Permissions-Policy', 'camera=(), geolocation=(), microphone=()');
   res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
 }
}));

// 401 page
app.get('/401.html', (req, res) => {
 res.sendFile(path.join(__dirname, 'public', '401.html'));
});

// Error handler
app.use((err, req, res, next) => {
 console.error('Unhandled error:', err);
 console.error('Stack trace:', err.stack);
 res.status(500).json({ error: 'Internal Server Error' });
});

// SPA fallback
app.get('*', (req, res) => {
 res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
const port = process.env.PORT || 3000;
app.listen(port, () => {
 console.log(`Server running on port ${port}`);
});