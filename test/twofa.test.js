const test = require('node:test');
const assert = require('node:assert/strict');
const speakeasy = require('speakeasy');
const { startServer, client, uniqueEmail, PASSWORD, ADMIN } = require('./helpers');

let server;
test.before(async () => { server = await startServer(); });
test.after(async () => { await server.stop(); });

const totp = secret => speakeasy.totp({ secret, encoding: 'base32' });

// Registers a user and turns 2FA on. Returns what a test needs.
async function userWithTwoFactor() {
  const email = uniqueEmail();
  const c = client(server.base);
  const reg = await c.post('/api/register', { email, password: PASSWORD });
  assert.equal(reg.status, 201);
  const setup = await c.post('/api/2fa/setup', {});
  assert.equal(setup.status, 200);
  const verify = await c.post('/api/2fa/verify', { token: totp(setup.json.secret) });
  assert.equal(verify.status, 200);
  return { email, userId: reg.json.userId, secret: setup.json.secret, codes: verify.json.recoveryCodes };
}

test('setup and activation work for a freshly registered browser', async () => {
  const u = await userWithTwoFactor();
  assert.equal(u.codes.length, 3);
});

test('setup is refused without a cookie, even if a user ID is supplied', async () => {
  const c = client(server.base);
  assert.equal((await c.post('/api/2fa/setup', { userId: 1, email: ADMIN.email })).status, 401);
  assert.equal((await c.post('/api/2fa/verify', { userId: 1, token: '123456' })).status, 401);
  assert.equal((await c.post('/api/2fa/validate', { userId: 1, token: '123456' })).status, 401);
});

test('a user ID in the request body is ignored', async () => {
  const victim = await userWithTwoFactor();
  const attacker = client(server.base);
  await attacker.post('/api/register', { email: uniqueEmail(), password: PASSWORD });
  // The attacker only has a setup cookie for their own account. Targeting the victim must not work.
  const r = await attacker.post('/api/2fa/verify', { userId: victim.userId, token: totp(victim.secret) });
  assert.notEqual(r.status, 200); // the attacker's own account has no pending setup, so nothing is activated
  assert.ok(r.status >= 400 && r.status < 500);
  const status = await attacker.get('/api/2fa/status');
  assert.equal(status.status, 401); // no full session yet
});

test('password step then 2FA code gives a session; the step-one cookie is single use', async () => {
  const u = await userWithTwoFactor();
  const c = client(server.base);
  const step1 = await c.post('/api/login', { email: u.email, password: PASSWORD });
  assert.equal(step1.json.requireTwoFactor, true);
  assert.equal(c.cookie('auth_token'), undefined);
  assert.ok(c.cookie('twofa_session'));
  const step2 = await c.post('/api/2fa/validate', { token: totp(u.secret) });
  assert.equal(step2.status, 200);
  assert.equal('token' in step2.json, false);
  assert.ok(c.cookie('auth_token'));
  assert.equal(c.cookie('twofa_session'), undefined);
  assert.equal((await c.post('/api/2fa/validate', { token: totp(u.secret) })).status, 401);
});

test('the 2FA step-one cookie cannot be used as a session', async () => {
  const u = await userWithTwoFactor();
  const c = client(server.base);
  await c.post('/api/login', { email: u.email, password: PASSWORD });
  const stepOne = c.cookie('twofa_session').value;
  const attacker = client(server.base);
  attacker.setCookie('auth_token', stepOne);
  assert.equal((await attacker.get('/api/getSasToken?blobName=a.png')).status, 401);
  assert.equal((await attacker.get('/api/2fa/status')).status, 401);
});

test('wrong codes are limited to 5 and then locked', async () => {
  const u = await userWithTwoFactor();
  const c = client(server.base);
  await c.post('/api/login', { email: u.email, password: PASSWORD });
  for (let i = 0; i < 5; i++) assert.equal((await c.post('/api/2fa/validate', { token: '000000' })).status, 401);
  assert.equal((await c.post('/api/2fa/validate', { token: totp(u.secret) })).status, 429);
});

test('a recovery code works once', async () => {
  const u = await userWithTwoFactor();
  async function tryCode(code) {
    const c = client(server.base);
    await c.post('/api/login', { email: u.email, password: PASSWORD });
    return (await c.post('/api/2fa/validate', { token: code })).status;
  }
  assert.equal(await tryCode(u.codes[0]), 200);
  assert.equal(await tryCode(u.codes[0]), 401);
});

test('disabling 2FA needs a session and a valid current code', async () => {
  const u = await userWithTwoFactor();
  assert.equal((await client(server.base).post('/api/2fa/disable', { userId: u.userId })).status, 401);
  const c = client(server.base);
  await c.post('/api/login', { email: u.email, password: PASSWORD });
  await c.post('/api/2fa/validate', { token: totp(u.secret) });
  assert.equal((await c.post('/api/2fa/disable', {})).status, 400);
  assert.equal((await c.post('/api/2fa/disable', { token: '000000' })).status, 401);
  const ok = await c.post('/api/2fa/disable', { token: totp(u.secret) });
  assert.equal(ok.status, 200);
  assert.equal((await c.get('/api/2fa/status')).json.twoFactorEnabled, false);
});
