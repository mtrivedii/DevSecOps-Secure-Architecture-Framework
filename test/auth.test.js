const test = require('node:test');
const assert = require('node:assert/strict');
const { startServer, client, uniqueEmail, PASSWORD, ADMIN } = require('./helpers');

let server;
test.before(async () => { server = await startServer(); });
test.after(async () => { await server.stop(); });

test('wrong password is rejected with a generic message', async () => {
  const c = client(server.base);
  const r = await c.post('/api/login', { email: ADMIN.email, password: 'nope' });
  assert.equal(r.status, 401);
  assert.equal(r.json.error, 'Invalid email or password.');
});

test('unknown account gets the same generic message', async () => {
  const c = client(server.base);
  const r = await c.post('/api/login', { email: 'nobody@example.com', password: PASSWORD });
  assert.equal(r.status, 401);
  assert.equal(r.json.error, 'Invalid email or password.');
});

test('login sets an httpOnly secure cookie and never returns the token in the body', async () => {
  const c = client(server.base);
  const r = await c.post('/api/login', ADMIN);
  assert.equal(r.status, 200);
  assert.equal('token' in r.json, false);
  assert.equal(r.json.user.email, ADMIN.email);
  const cookie = c.cookie('auth_token');
  assert.ok(cookie, 'auth_token cookie set');
  assert.ok(cookie.attrs.includes('httponly'));
  assert.ok(cookie.attrs.includes('secure'));
  assert.ok(cookie.attrs.some(a => a.startsWith('samesite=')));
});

test('registration rejects weak passwords and duplicate emails', async () => {
  const c = client(server.base);
  const email = uniqueEmail();
  assert.equal((await c.post('/api/register', { email, password: 'short' })).status, 400);
  assert.equal((await c.post('/api/register', { email, password: 'alllowercase1!' })).status, 400);
  assert.equal((await c.post('/api/register', { email, password: PASSWORD })).status, 201);
  assert.equal((await c.post('/api/register', { email, password: PASSWORD })).status, 409);
});

test('logout clears the session cookie', async () => {
  const c = client(server.base);
  await c.post('/api/login', ADMIN);
  assert.ok(c.cookie('auth_token'));
  const r = await c.post('/api/logout');
  assert.equal(r.status, 200);
  assert.equal(c.cookie('auth_token'), undefined);
});

test('login is rate limited per IP', async () => {
  const c = client(server.base);
  // 10 attempts are allowed in 15 minutes. Use a distinct forwarded IP so other tests are not affected.
  const headers = { 'X-Forwarded-For': '203.0.113.7' };
  let last;
  for (let i = 0; i < 12; i++) last = await c.post('/api/login', { email: 'x@example.com', password: 'bad' }, headers);
  assert.equal(last.status, 429);
});
