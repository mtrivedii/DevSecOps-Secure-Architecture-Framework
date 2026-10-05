// POST /api/verifyUpload { blobName }
// After the browser uploads straight to Blob Storage, this reads the start of the file and
// deletes it if the content does not match its extension.
// Limit: the browser triggers this call, so a client that skips it is not checked here.
// A storage-side check (Event Grid + function, or Defender for Storage) is needed to cover that.
const { BlobServiceClient, StorageSharedKeyCredential } = require('@azure/storage-blob');
const jwt = require('jsonwebtoken');
const securityLog = require('./securityLog');
const uploadRules = require('./uploadRules');

const HEAD_BYTES = 512;

async function readHead(blobClient) {
  const res = await blobClient.download(0, HEAD_BYTES);
  const chunks = [];
  for await (const chunk of res.readableStreamBody) chunks.push(chunk);
  return Buffer.concat(chunks);
}

async function handler(req, res) {
  let session;
  try {
    session = jwt.verify(req.cookies?.auth_token || '', process.env.JWT_SECRET, { algorithms: ['HS256'] });
  } catch (err) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const blobName = req.body && req.body.blobName;
  if (!blobName || typeof blobName !== 'string' || blobName.length > 256) {
    return res.status(400).json({ error: 'Missing or invalid blobName' });
  }
  const accountName = process.env.AZURE_STORAGE_ACCOUNT_NAME;
  const accountKey = process.env.AZURE_STORAGE_ACCOUNT_KEY;
  if (!accountName || !accountKey) return res.status(500).json({ error: 'Storage credentials not configured' });

  try {
    const service = new BlobServiceClient(
      `https://${accountName}.blob.core.windows.net`,
      new StorageSharedKeyCredential(accountName, accountKey)
    );
    const blobClient = service.getContainerClient('secure-uploads').getBlobClient(blobName);
    const head = await readHead(blobClient);
    const result = uploadRules.checkContent(blobName, head);
    if (!result.ok) {
      await blobClient.deleteIfExists();
      securityLog.record('upload.rejected_after_upload', { req, userId: session.userId, detail: `${result.reason}: ${blobName.slice(0, 80)}`, severity: 'warning' });
      return res.status(422).json({ error: result.reason, deleted: true });
    }
    securityLog.record('upload.verified', { req, userId: session.userId, detail: blobName.slice(0, 80) });
    return res.json({ ok: true });
  } catch (err) {
    if (err.statusCode === 404) return res.status(404).json({ error: 'File not found' });
    console.error('verifyUpload failed:', err.statusCode || err.message);
    return res.status(500).json({ error: 'Could not verify upload' });
  }
}

module.exports = { handler };
