const test = require('node:test');
const assert = require('node:assert/strict');
const { startServer, client, uniqueEmail, PASSWORD, ADMIN } = require('./helpers');

let server;
test.before(async () => { server = await startServer(); });
test.after(async () => { await server.stop(); });

async function loginAs(email, password) {
  const c = client(server.base);
  const r = await c.post('/api/login', { email, password });
  assert.equal(r.status, 200);
  return c;
}

async function newUser() {
  const email = uniqueEmail();
  const anon = client(server.base);
  assert.equal((await anon.post('/api/register', { email, password: PASSWORD })).status, 201);
  return { email, c: await loginAs(email, PASSWORD) };
}

test('the user list needs an admin session', async () => {
  assert.equal((await client(server.base).get('/api/users')).status, 401);
  const { c: user } = await newUser();
  assert.equal((await user.get('/api/users')).status, 403);
  const admin = await loginAs(ADMIN.email, ADMIN.password);
  const r = await admin.get('/api/users');
  assert.equal(r.status, 200);
  assert.ok(Array.isArray(r.json));
});

test('a forged cookie is not accepted', async () => {
  const c = client(server.base);
  c.setCookie('auth_token', 'eyJhbGciOiJub25lIn0.eyJyb2xlIjoiQWRtaW4ifQ.');
  assert.equal((await c.get('/api/users')).status, 401);
});

test('admin pages are blocked for anonymous users and normal users', async () => {
  assert.equal((await client(server.base).get('/admin.html')).status, 401);
  const { c: user } = await newUser();
  assert.equal((await user.get('/admin.html')).status, 401);
  const admin = await loginAs(ADMIN.email, ADMIN.password);
  assert.equal((await admin.get('/admin.html')).status, 200);
});

test('upload links need a login and refuse script files', async () => {
  assert.equal((await client(server.base).get('/api/getSasToken?blobName=a.png')).status, 401);
  const { c } = await newUser();
  const ok = await c.get('/api/getSasToken?blobName=photo.png');
  assert.equal(ok.status, 200);
  assert.match(ok.json.sasUrl, /sig=/);
  assert.equal((await c.get('/api/getSasToken?blobName=evil.php')).status, 403);
  assert.equal((await c.get('/api/getSasToken?blobName=page.html')).status, 403);
});

test('responses carry the security headers', async () => {
  const r = await client(server.base).get('/login.html');
  assert.equal(r.headers.get('x-frame-options'), 'DENY');
  assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
  assert.ok(r.headers.get('content-security-policy'));
});
