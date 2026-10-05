const test = require('node:test');
const assert = require('node:assert/strict');
const { startServer, client, uniqueEmail, PASSWORD, ADMIN } = require('./helpers');

let server;
test.before(async () => { server = await startServer(); });
test.after(async () => { await server.stop(); });

async function admin() {
  const c = client(server.base);
  assert.equal((await c.post('/api/login', ADMIN)).status, 200);
  return c;
}

test('the event list is admin only', async () => {
  assert.equal((await client(server.base).get('/api/security-events')).status, 401);
  const email = uniqueEmail();
  const u = client(server.base);
  await u.post('/api/register', { email, password: PASSWORD });
  await u.post('/api/login', { email, password: PASSWORD });
  assert.equal((await u.get('/api/security-events')).status, 403);
  assert.equal((await u.get('/security.html')).status === 200, false);
  assert.equal((await (await admin()).get('/api/security-events')).status, 200);
});

test('failed sign-ins are recorded with a masked email, never a password', async () => {
  const email = uniqueEmail();
  await client(server.base).post('/api/login', { email, password: 'WrongPassword!1' });
  const r = await (await admin()).get('/api/security-events?limit=50');
  const hit = r.json.events.find(e => e.type === 'login.failure');
  assert.ok(hit);
  assert.ok(!JSON.stringify(r.json).includes('WrongPassword'));
  assert.ok(!JSON.stringify(r.json).includes(email));
});

test('repeated failures from one address raise a brute-force alert', async () => {
  const email = uniqueEmail();
  for (let i = 0; i < 6; i++) await client(server.base).post('/api/login', { email, password: 'WrongPassword!1' });
  const r = await (await admin()).get('/api/security-events?limit=200');
  assert.ok(r.json.events.some(e => e.type === 'alert.brute_force'));
});
