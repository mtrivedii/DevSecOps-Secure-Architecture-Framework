// 2fa.js - API endpoint for two-factor authentication
const express = require('express');
const router = express.Router();
const sql = require('mssql');
const crypto = require('crypto');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const jwt = require('jsonwebtoken');
const { getTwoFactorSession, getAuthSession, clearTwoFactorSession } = require('./session');
const securityLog = require('./securityLog');

// Singleton SQL connection pool
let sqlPool = null;
async function getSqlPool() {
  // Using the connection string format you had in this file.
  // Ensure 'SQLAZURECONNSTR_SqlConnectionString' is correctly set in your Azure App Service environment.
  if (!sqlPool) {
    if (!process.env.SQLAZURECONNSTR_SqlConnectionString) {
      console.error('FATAL ERROR: SQLAZURECONNSTR_SqlConnectionString is not defined.');
      // In a real app, you might throw an error or have a fallback,
      // but for now, it will fail when sql.connect is called.
    }
    sqlPool = await sql.connect(process.env.SQLAZURECONNSTR_SqlConnectionString);
  }
  return sqlPool;
}

// The user ID always comes from a signed cookie, never from the request body.
// Setup: a signed-in user, or a browser that just registered.
function setupUserId(req) {
  const auth = getAuthSession(req);
  if (auth && Number.isInteger(auth.userId)) return auth.userId;
  return getTwoFactorSession(req, ['setup']);
}

// Limit wrong 2FA codes per account: 5 failures in 15 minutes, then wait.
const failedCodes = new Map(); // userId -> number[] of failure times
const CODE_WINDOW_MS = 15 * 60 * 1000;
const CODE_MAX_FAILURES = 5;
function codeLocked(userId) {
  const now = Date.now();
  const list = (failedCodes.get(userId) || []).filter(t => now - t < CODE_WINDOW_MS);
  failedCodes.set(userId, list);
  return list.length >= CODE_MAX_FAILURES;
}
function noteCodeFailure(userId) {
  const list = failedCodes.get(userId) || [];
  list.push(Date.now());
  failedCodes.set(userId, list);
}

// Setup 2FA - Step 1: Generate secret and QR code
router.post('/setup', async (req, res) => {
  const userId = setupUserId(req);
  if (!userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  try {
    const pool = await getSqlPool();
    const userResult = await pool.request()
      .input('userId', sql.Int, userId)
      .query('SELECT id, email, twoFactorEnabled FROM dbo.users WHERE id = @userId');
    
    if (userResult.recordset.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const user = userResult.recordset[0];
    const email = user.email;
    
    if (user.twoFactorEnabled) {
      return res.status(400).json({ error: '2FA is already enabled for this user' });
    }
    
    const secret = speakeasy.generateSecret({
      length: 20,
      name: `SecureApp:${email}`
    });
    
    await pool.request()
      .input('userId', sql.Int, userId)
      .input('secret', sql.NVarChar, secret.base32)
      .query(`
        UPDATE dbo.users
        SET twoFactorTempSecret = @secret
        WHERE id = @userId
      `);
    
    const otpauth_url = secret.otpauth_url;
    const qrCodeImage = await QRCode.toDataURL(otpauth_url);
    
    securityLog.record('twofa.setup_started', { req, email, userId });
    
    return res.status(200).json({
      secret: secret.base32,
      qrCodeUrl: qrCodeImage,
      message: 'Scan this QR code with your authenticator app'
    });
    
  } catch (error) {
    console.error('2FA setup error:', error.message, error.stack);
    return res.status(500).json({ error: 'Failed to set up 2FA' });
  }
});

// Setup 2FA - Step 2: Verify and activate
router.post('/verify', async (req, res) => {
  const userId = setupUserId(req);
  const { token: verificationTokenFromUser } = req.body;
  
  if (!userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  if (!verificationTokenFromUser) {
    return res.status(400).json({ error: 'Verification token is required' });
  }
  if (codeLocked(userId)) {
    securityLog.record('rate_limit.exceeded', { req, userId, detail: '2FA activation codes', severity: 'medium' });
    return res.status(429).json({ error: 'Too many wrong codes. Try again later.' });
  }
  
  try {
    const pool = await getSqlPool();
    const secretResult = await pool.request()
      .input('userId', sql.Int, userId)
      .query(`
        SELECT id, email, twoFactorTempSecret 
        FROM dbo.users 
        WHERE id = @userId
      `);
    
    if (secretResult.recordset.length === 0 || !secretResult.recordset[0].twoFactorTempSecret) {
      return res.status(404).json({ error: 'No 2FA setup found for this user or temporary secret missing.' });
    }
    
    const user = secretResult.recordset[0];
    
    const verified = speakeasy.totp.verify({
      secret: user.twoFactorTempSecret,
      encoding: 'base32',
      token: verificationTokenFromUser,
      window: 1 
    });
    
    if (!verified) {
      noteCodeFailure(userId);
      securityLog.record('twofa.failure', { req, email: user.email, userId, detail: 'activation code' });
      return res.status(401).json({ error: 'Invalid verification code' });
    }
    
    const recoveryCodes = Array(3).fill(0).map(() => {
      const code = crypto.randomBytes(12).toString('hex');
      return `${code.slice(0,4)}-${code.slice(4,8)}-${code.slice(8,12)}`.toUpperCase();
    });
    
    const hashedCodes = recoveryCodes.map(code => 
      crypto.createHash('sha256').update(code).digest('hex')
    );
    
    await pool.request()
      .input('userId', sql.Int, userId)
      .input('secretToStore', sql.NVarChar, user.twoFactorTempSecret) // Store the confirmed temp secret as the main secret
      .input('recoveryCodesJson', sql.NVarChar, JSON.stringify(hashedCodes))
      .query(`
        UPDATE dbo.users
        SET 
          twoFactorEnabled = 1,
          twoFactorSecret = @secretToStore,
          twoFactorTempSecret = NULL,
          twoFactorRecoveryCodes = @recoveryCodesJson
        WHERE id = @userId
      `);
    
    securityLog.record('twofa.enabled', { req, email: user.email, userId });
    
    return res.status(200).json({
      message: '2FA successfully activated',
      twoFactorEnabled: true,
      recoveryCodes: recoveryCodes // Send plain recovery codes to user once
    });
    
  } catch (error) {
    console.error('2FA verification (activation) error:', error.message, error.stack);
    return res.status(500).json({ error: 'Failed to verify 2FA token during activation' });
  }
});

// Login with 2FA (Validate 2FA code during login attempt)
router.post('/validate', async (req, res) => {
  // Only a browser that just passed the password step has this cookie.
  const userId = getTwoFactorSession(req, ['login']);
  const { token: twoFactorTokenFromUser } = req.body;
  
  if (!userId) {
    return res.status(401).json({ error: 'Sign in with your password first.' });
  }
  if (!twoFactorTokenFromUser) {
    return res.status(400).json({ error: '2FA token is required' });
  }
  if (codeLocked(userId)) {
    securityLog.record('rate_limit.exceeded', { req, userId, detail: '2FA login codes', severity: 'medium' });
    return res.status(429).json({ error: 'Too many wrong codes. Try again later.' });
  }
  
  try {
    const pool = await getSqlPool();
    const secretResult = await pool.request()
      .input('userId', sql.Int, userId)
      .query(`
        SELECT id, email, twoFactorSecret, twoFactorRecoveryCodes, Role
        FROM dbo.users 
        WHERE id = @userId AND twoFactorEnabled = 1
      `);
    
    if (secretResult.recordset.length === 0 || !secretResult.recordset[0].twoFactorSecret) {
      return res.status(404).json({ error: 'No active 2FA found for this user or 2FA not enabled.' });
    }
    
    const user = secretResult.recordset[0];
    let validated = false;

    // Check if the token is a recovery code
    if (user.twoFactorRecoveryCodes) {
        try {
            const recoveryCodesList = JSON.parse(user.twoFactorRecoveryCodes); // Ensure this is an array
            const hashedTokenFromUser = crypto.createHash('sha256').update(twoFactorTokenFromUser).digest('hex');
            const recoveryCodeIndex = recoveryCodesList.indexOf(hashedTokenFromUser);

            if (recoveryCodeIndex !== -1) {
                recoveryCodesList.splice(recoveryCodeIndex, 1); // Use and invalidate
                await pool.request()
                .input('userId', sql.Int, userId)
                .input('updatedRecoveryCodes', sql.NVarChar, JSON.stringify(recoveryCodesList))
                .query(`
                    UPDATE dbo.users
                    SET twoFactorRecoveryCodes = @updatedRecoveryCodes
                    WHERE id = @userId
                `);
                validated = true;
                securityLog.record('twofa.recovery_used', { req, email: user.email, userId, severity: 'medium', detail: `${recoveryCodesList.length} recovery codes left` });
            }
        } catch (e) {
            console.error('Error parsing or using recovery codes during validation:', e.message, e.stack);
        }
    }
    
    if (!validated) { // If not validated by recovery code, try TOTP
      validated = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: 'base32',
        token: twoFactorTokenFromUser,
        window: 1
      });
    }
    
    if (!validated) {
      noteCodeFailure(userId);
      securityLog.record('twofa.failure', { req, email: user.email, userId, detail: 'login code' });
      return res.status(401).json({ error: 'Invalid verification code' });
    }
    
    failedCodes.delete(userId);
    clearTwoFactorSession(res); // the step-one cookie is single use
    securityLog.record('login.success', { req, email: user.email, userId, detail: 'password and 2FA' });
    
    const finalAuthToken = jwt.sign(
      { 
        userId: user.id,
        email: user.email,
        role: user.Role 
      },
      process.env.JWT_SECRET, // Ensure JWT_SECRET is set in your environment
      { expiresIn: '1h' }
    );
    
    // <<< SET THE AUTH_TOKEN COOKIE (PRODUCTION-READY) >>>
    res.cookie('auth_token', finalAuthToken, {
      httpOnly: true,
      secure: true, // Assuming your site is HTTPS, which it is
      maxAge: 3600000, // 1 hour
      sameSite: 'lax',
      path: '/'
    });
    
    return res.status(200).json({
      message: '2FA authentication successful',
      userId: user.id, // Or convert to string if client expects string userId
      email: user.email,
      user: {
        id: user.id.toString(),
        email: user.email,
        role: user.Role
      }
    });
    
  } catch (error) {
    console.error('2FA validation (login) error:', error.message, error.stack);
    return res.status(500).json({ error: 'Failed to validate 2FA token during login' });
  }
});

// Disable 2FA
router.post('/disable', async (req, res) => {
  // Only a signed-in user can turn off their own 2FA, and they must give a valid code.
  const auth = getAuthSession(req);
  if (!auth || !Number.isInteger(auth.userId)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const userId = auth.userId;
  const { token: verificationTokenFromUser } = req.body;
  
  if (!verificationTokenFromUser) {
    return res.status(400).json({ error: 'A current 2FA code is required to disable 2FA' });
  }
  if (codeLocked(userId)) {
    return res.status(429).json({ error: 'Too many wrong codes. Try again later.' });
  }
  
  try {
    const pool = await getSqlPool();
    const secretResult = await pool.request()
      .input('userId', sql.Int, userId)
      .query(`
        SELECT id, email, twoFactorSecret
        FROM dbo.users 
        WHERE id = @userId AND twoFactorEnabled = 1
      `);
    
    if (secretResult.recordset.length === 0) {
      return res.status(404).json({ error: 'No active 2FA found for this user.' });
    }
    
    const user = secretResult.recordset[0];
    
    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token: verificationTokenFromUser,
      window: 1
    });
    if (!verified) {
      noteCodeFailure(userId);
      securityLog.record('twofa.failure', { req, email: user.email, userId, detail: 'disable code' });
      return res.status(401).json({ error: 'Invalid verification code for disabling 2FA' });
    }
    
    await pool.request()
      .input('userId', sql.Int, userId)
      .query(`
        UPDATE dbo.users
        SET 
          twoFactorEnabled = 0,
          twoFactorSecret = NULL,
          twoFactorTempSecret = NULL,
          twoFactorRecoveryCodes = NULL
        WHERE id = @userId
      `);
    
    securityLog.record('twofa.disabled', { req, email: user.email, userId, severity: 'medium' });
    
    // Clear the auth_token cookie if the user is disabling their own 2FA and should be logged out
    // or forced to re-authenticate under new (non-2FA) terms.
    // This depends on your desired UX. For now, just confirming disable.
    // res.clearCookie('auth_token', { httpOnly: true, secure: true, sameSite: 'lax', path: '/' });

    return res.status(200).json({
      message: '2FA successfully disabled',
      twoFactorEnabled: false
    });
    
  } catch (error) {
    console.error('2FA disable error:', error.message, error.stack);
    return res.status(500).json({ error: 'Failed to disable 2FA' });
  }
});

// Check 2FA status
router.get('/status', async (req, res) => {
  const auth = getAuthSession(req);
  if (!auth || !Number.isInteger(auth.userId)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const userIdParam = auth.userId;
  
  try {
    const pool = await getSqlPool();
    const result = await pool.request()
      .input('userIdInput', sql.Int, userIdParam) // Use a different name for input param
      .query(`
        SELECT twoFactorEnabled
        FROM dbo.users 
        WHERE id = @userIdInput
      `);
    
    if (result.recordset.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    return res.status(200).json({
      twoFactorEnabled: !!result.recordset[0].twoFactorEnabled
    });
    
  } catch (error) {
    console.error('2FA status check error:', error.message, error.stack);
    return res.status(500).json({ error: 'Failed to check 2FA status' });
  }
});

module.exports = router;