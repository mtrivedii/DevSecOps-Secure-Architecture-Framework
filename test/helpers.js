// Test helpers: start the demo server on a free port and talk to it with a cookie jar.
const { spawn } = require('node:child_process');
const net = require('node:net');
const path = require('node:path');

function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.listen(0, () => { const { port } = s.address(); s.close(() => resolve(port)); });
    s.on('error', reject);
  });
}

async function startServer() {
  const port = await freePort();
  const child = spawn(process.execPath, [path.join(__dirname, '..', 'dev', 'demo-server.js')], {
    env: { ...process.env, PORT: String(port), REGISTRATION_LIMIT: '1000' },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('server did not start')), 15000);
    child.stdout.on('data', d => { if (String(d).includes('Server running')) { clearTimeout(timer); resolve(); } });
    child.on('exit', code => { clearTimeout(timer); reject(new Error('server exited ' + code)); });
  });
  return {
    base: `http://localhost:${port}`,
    stop: () => new Promise(r => { child.once('exit', r); child.kill(); })
  };
}

// A tiny browser: keeps cookies between requests, drops them when the server expires them.
function client(base) {
  const jar = new Map();
  function store(res) {
    for (const line of res.headers.getSetCookie()) {
      const [pair, ...attrs] = line.split(';');
      const eq = pair.indexOf('=');
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      const lower = attrs.map(a => a.trim().toLowerCase());
      const expired = lower.includes('max-age=0') || lower.some(a => a.startsWith('expires=thu, 01 jan 1970'));
      if (expired || value === '') jar.delete(name); else jar.set(name, { value, attrs: lower });
    }
  }
  async function request(method, url, body, extraHeaders = {}) {
    const cookie = [...jar.entries()].map(([k, v]) => `${k}=${v.value}`).join('; ');
    const res = await fetch(base + url, {
      method,
      redirect: 'manual',
      headers: { 'Content-Type': 'application/json', ...(cookie ? { Cookie: cookie } : {}), ...extraHeaders },
      body: body === undefined ? undefined : (typeof body === 'string' ? body : JSON.stringify(body))
    });
    store(res);
    const text = await res.text();
    let json; try { json = JSON.parse(text); } catch { /* not JSON */ }
    return { status: res.status, json, text, headers: res.headers };
  }
  return {
    jar,
    get: (u, h) => request('GET', u, undefined, h),
    post: (u, b, h) => request('POST', u, b, h),
    put: (u, b, h) => request('PUT', u, b, h),
    cookie: name => jar.get(name),
    setCookie: (name, value) => jar.set(name, { value, attrs: [] }),
    clearCookies: () => jar.clear()
  };
}

let counter = 0;
const uniqueEmail = () => `user${Date.now()}${counter++}@example.com`;
const PASSWORD = 'Str0ng!Passw0rd';
const ADMIN = { email: 'admin@example.com', password: 'Admin#Demo2026' };

module.exports = { startServer, client, uniqueEmail, PASSWORD, ADMIN };
