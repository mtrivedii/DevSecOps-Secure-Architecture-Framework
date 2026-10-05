// auth-utilities.js

const crypto = require('crypto');

/**
 * Extracts userz info from Azure App Service Easy Auth header.
 * Returns an object with userId, username, roles, etc.
 */
function extractUserInfo(req) {
  try {
    // Get client principal header
    const clientPrincipal = req.headers['x-ms-client-principal'];
    if (!clientPrincipal) {
      return { isAuthenticated: false, error: 'Not authenticated' };
    }

    // Base64 decode and parse
    let principal;
    try {
      const decoded = Buffer.from(clientPrincipal, 'base64').toString('utf8');
      principal = JSON.parse(decoded);
      // Uncomment for debugging:
      // console.log('Decoded principal:', principal);
    } catch (err) {
      console.error('Auth decode error:', err.message);
      return { isAuthenticated: false, error: 'Authentication decode error' };
    }

    // Claims array
    if (!principal?.claims || !Array.isArray(principal.claims)) {
      return { isAuthenticated: false, error: 'Invalid authentication data' };
    }

    // Extract roles/app-roles
    let roles = principal.claims
      .filter(c =>
        c.typ === 'roles' ||
        c.typ === 'role' ||
        c.typ === 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role'
      )
      .map(c => c.val);

    // Extract groups if present
    const groups = principal.claims
      .filter(c =>
        c.typ === 'groups' ||
        c.typ === 'http://schemas.microsoft.com/claims/groups'
      )
      .map(c => c.val);
    roles = roles.concat(groups);

    // Always mark as authenticated if present
    if (!roles.includes('authenticated')) roles.push('authenticated');

    // Build boolean shortcuts
    const userRoles = {
      isAdmin: roles.some(r => r && r.toLowerCase() === 'admin'),
      canReadScoreboard: roles.some(r =>
        r && (r.toLowerCase() === 'scoreboard.read' || r.toLowerCase() === 'admin')
      ),
      canWriteScoreboard: roles.some(r =>
        r && (r.toLowerCase() === 'scoreboard.write' || r.toLowerCase() === 'admin')
      )
    };

    // Find userId & username
    const userIdClaim = principal.claims.find(c =>
      c.typ === 'http://schemas.microsoft.com/identity/claims/objectidentifier' ||
      c.typ === 'oid' ||
      c.typ === 'sub' ||
      c.typ === 'userId'
    );
    const usernameClaim = principal.claims.find(c =>
      c.typ === 'preferred_username' ||
      c.typ === 'name' ||
      c.typ === 'upn' ||
      c.typ === 'email' ||
      c.typ === 'userDetails'
    );

    if (!userIdClaim?.val) {
      return { isAuthenticated: false, error: 'Incomplete authentication data' };
    }

    // Client IP and agent for logging/auditing
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0]
                   || req.headers['x-real-ip']
                   || req.ip
                   || 'unknown';
    const userAgent = req.headers['user-agent'] || 'unknown';

    const userInfo = {
      isAuthenticated: true,
      userId: userIdClaim.val,
      username: usernameClaim?.val || 'User',
      roles: userRoles,
      allRoles: roles,
      identityProvider: principal.identityProvider || 'unknown',
      clientIp,
      userAgent: userAgent.substring(0, 500),
      requestNonce: crypto.randomBytes(16).toString('hex'),
      authTimestamp: Date.now()
    };

    // Uncomment for debugging:
    // console.log('Final user info:', userInfo);

    return userInfo;
  } catch (error) {
    console.error('Critical error in auth processing:', error);
    return { isAuthenticated: false, error: 'Authentication processing error' };
  }
}

/**
 * Checks if the user has the required role.
 * @param {*} userInfo - result of extractUserInfo
 * @param {*} role - role name (case-insensitive)
 * @returns {boolean}
 */
function requireRole(userInfo, role) {
  if (!userInfo?.isAuthenticated) return false;
  if (Date.now() - userInfo.authTimestamp > 30 * 60 * 1000) return false;
  const want = role.toLowerCase();
  switch (want) {
    case 'admin':
      return userInfo.roles.isAdmin === true;
    case 'authenticated':
      return true; // any signed-in user
    case 'scoreboard.read':
      return userInfo.roles.canReadScoreboard === true;
    case 'scoreboard.write':
      return userInfo.roles.canWriteScoreboard === true;
    default:
      return userInfo.allRoles.some(r => r && r.toLowerCase() === want);
  }
}

module.exports = {
  extractUserInfo,
  requireRole,
};
