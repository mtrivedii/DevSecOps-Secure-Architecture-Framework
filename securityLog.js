// securityLog.js - structured security events with a simple alert rule.
//
// Every event is written to the console as one JSON line (App Service sends
// console output to Log Analytics, so it can be queried there) and kept in a
// small in-memory list for the admin page. The in-memory list is per process
// and is lost on restart, so it is a convenience view, not the record of truth.

const MAX_EVENTS = 500;
const events = [];
let nextEventId = 1;

// Alert rule: this many failures from one source inside the window raises an alert.
const ALERT_THRESHOLD = 5;
const ALERT_WINDOW_MS = 10 * 60 * 1000;
const FAILURE_TYPES = new Set(['login.failure', 'twofa.failure']);
const failuresBySource = new Map(); // source -> { times: number[], alertedAt: number }

function clientIp(req) {
  if (!req) return 'unknown';
  const forwarded = req.headers && req.headers['x-forwarded-for'];
  return (forwarded ? String(forwarded).split(',')[0].trim() : req.ip) || 'unknown';
}

// "alice@example.com" -> "al***@example.com"
function maskEmail(email) {
  if (!email || typeof email !== 'string' || !email.includes('@')) return undefined;
  const [name, domain] = email.split('@');
  return `${name.slice(0, 2)}***@${domain}`;
}

function push(event) {
  event.id = nextEventId++;
  events.push(event);
  if (events.length > MAX_EVENTS) events.shift();
  console.log(JSON.stringify({ securityEvent: event }));
}

function checkAlert(event) {
  if (!FAILURE_TYPES.has(event.type)) return;
  const now = Date.now();
  const entry = failuresBySource.get(event.ip) || { times: [], alertedAt: 0 };
  entry.times = entry.times.filter(t => now - t < ALERT_WINDOW_MS);
  entry.times.push(now);
  failuresBySource.set(event.ip, entry);
  if (entry.times.length >= ALERT_THRESHOLD && now - entry.alertedAt > ALERT_WINDOW_MS) {
    entry.alertedAt = now;
    push({
      time: new Date(now).toISOString(),
      type: 'alert.brute_force',
      severity: 'high',
      ip: event.ip,
      detail: `${entry.times.length} failed sign-in or 2FA attempts from one address in ${ALERT_WINDOW_MS / 60000} minutes`
    });
  }
}

// record('login.failure', { req, email, userId, detail, severity })
function record(type, { req, email, userId, detail, severity = 'info' } = {}) {
  const event = {
    time: new Date().toISOString(),
    type,
    severity,
    ip: clientIp(req),
    email: maskEmail(email),
    userId: userId === undefined ? undefined : Number(userId),
    detail
  };
  push(event);
  checkAlert(event);
}

function getEvents({ limit = 100 } = {}) {
  return events.slice(-limit).reverse();
}

module.exports = { record, getEvents, maskEmail, clientIp, ALERT_THRESHOLD, ALERT_WINDOW_MS };
