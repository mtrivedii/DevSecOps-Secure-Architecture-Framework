// session.js - helpers for the signed cookies used during login and 2FA.
//
// auth_token     : the full session, set only after every login step has passed.
// twofa_session  : a short-lived cookie that says "this browser just passed step one".
//                  purpose 'login' = password was correct, 2FA code still needed.
//                  purpose 'setup' = account was just created, 2FA setup is allowed.
//
// The 2FA cookie is signed with a different key from auth_token. Without that,
// someone who only knows the password could copy the 2FA cookie into auth_token
// and skip the second factor.

const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const TWOFA_COOKIE = 'twofa_session';

function secret() {
  if (!process.env.JWT_SECRET) throw new Error('JWT_SECRET is not set');
  return process.env.JWT_SECRET;
}

function twoFactorKey() {
  return crypto.createHmac('sha256', secret()).update('twofa-session-v1').digest('hex');
}

function cookieOptions(maxAgeMs) {
  return { httpOnly: true, secure: true, sameSite: 'strict', path: '/', maxAge: maxAgeMs };
}

// Purposes and lifetimes
const LIFETIMES = { login: 5 * 60 * 1000, setup: 15 * 60 * 1000 };

function setTwoFactorSession(res, userId, purpose) {
  const ttl = LIFETIMES[purpose];
  if (!ttl) throw new Error('Unknown 2FA session purpose');
  const token = jwt.sign({ userId: Number(userId), purpose }, twoFactorKey(), {
    algorithm: 'HS256',
    expiresIn: Math.floor(ttl / 1000)
  });
  res.cookie(TWOFA_COOKIE, token, cookieOptions(ttl));
}

function clearTwoFactorSession(res) {
  res.clearCookie(TWOFA_COOKIE, cookieOptions(0));
}

// Returns the user ID from a valid 2FA cookie with one of the allowed purposes, or null.
function getTwoFactorSession(req, purposes) {
  const token = req.cookies && req.cookies[TWOFA_COOKIE];
  if (!token) return null;
  try {
    const p = jwt.verify(token, twoFactorKey(), { algorithms: ['HS256'] });
    if (!purposes.includes(p.purpose) || !Number.isInteger(p.userId)) return null;
    return p.userId;
  } catch (err) {
    return null;
  }
}

// Returns the payload of a valid full session (auth_token), or null.
function getAuthSession(req) {
  const token = req.cookies && req.cookies.auth_token;
  if (!token) return null;
  try {
    return jwt.verify(token, secret(), { algorithms: ['HS256'] });
  } catch (err) {
    return null;
  }
}

module.exports = {
  setTwoFactorSession,
  clearTwoFactorSession,
  getTwoFactorSession,
  getAuthSession
};
