const test = require('node:test');
const assert = require('node:assert/strict');
const { startServer, client, uniqueEmail, PASSWORD, ADMIN } = require('./helpers');

let server;
test.before(async () => { server = await startServer(); });
test.after(async () => { await server.stop(); });

async function signedIn() {
  const c = client(server.base);
  await c.post('/api/register', { email: uniqueEmail(), password: PASSWORD });
  const email = uniqueEmail();
  const c2 = client(server.base);
  await c2.post('/api/register', { email, password: PASSWORD });
  assert.equal((await c2.post('/api/login', { email, password: PASSWORD })).status, 200);
  return c2;
}

// Asks for an upload URL, uploads the bytes, then asks the server to check them.
async function upload(c, name, bytes, type) {
  const sas = await c.get(`/api/getSasToken?blobName=${encodeURIComponent(name)}&contentType=${encodeURIComponent(type)}`);
  if (sas.status !== 200) return { sas };
  const put = await fetch(sas.json.sasUrl, { method: 'PUT', headers: { 'x-ms-blob-type': 'BlockBlob', 'Content-Type': type }, body: bytes });
  assert.equal(put.status, 201);
  const verify = await c.post('/api/verifyUpload', { blobName: sas.json.storedName });
  return { sas, verify, stored: sas.json.storedName };
}

test('upload URLs need a signed-in user', async () => {
  assert.equal((await client(server.base).get('/api/getSasToken?blobName=a.pdf')).status, 401);
  assert.equal((await client(server.base).post('/api/verifyUpload', { blobName: 'a.pdf' })).status, 401);
});

test('file types outside the allowlist are refused', async () => {
  const c = await signedIn();
  for (const name of ['a.html', 'a.js', 'a.exe', 'a.svg', 'a.php', 'noextension']) {
    assert.equal((await c.get(`/api/getSasToken?blobName=${name}`)).status, 403, name);
  }
});

test('a content type that does not match the extension is refused', async () => {
  const c = await signedIn();
  const r = await c.get('/api/getSasToken?blobName=a.pdf&contentType=text/html');
  assert.equal(r.status, 403);
});

test('a real PDF passes the content check', async () => {
  const c = await signedIn();
  const r = await upload(c, 'good.pdf', Buffer.from('%PDF-1.4\n%fake but valid start'), 'application/pdf');
  assert.equal(r.verify.status, 200);
});

test('a script renamed to .png is deleted after upload', async () => {
  const c = await signedIn();
  const r = await upload(c, 'evil.png', Buffer.from('<script>alert(1)</script>'), 'image/png');
  assert.equal(r.verify.status, 422);
  assert.equal(r.verify.json.deleted, true);
  const again = await c.post('/api/verifyUpload', { blobName: r.stored });
  assert.notEqual(again.status, 200); // the file is gone
});

test('HTML renamed to .txt is rejected', async () => {
  const c = await signedIn();
  const r = await upload(c, 'page.txt', Buffer.from('<!DOCTYPE html><html></html>'), 'text/plain');
  assert.equal(r.verify.status, 422);
});
