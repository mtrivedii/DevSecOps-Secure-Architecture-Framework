// Rules for what may be uploaded. The browser page shows the same list.
const path = require('path');

const ALLOWED = {
  '.pdf':  { types: ['application/pdf'] },
  '.doc':  { types: ['application/msword'] },
  '.docx': { types: ['application/vnd.openxmlformats-officedocument.wordprocessingml.document'] },
  '.txt':  { types: ['text/plain'] },
  '.jpg':  { types: ['image/jpeg'] },
  '.jpeg': { types: ['image/jpeg'] },
  '.png':  { types: ['image/png'] },
  '.gif':  { types: ['image/gif'] },
  '.csv':  { types: ['text/csv', 'application/vnd.ms-excel', 'text/plain'] },
  '.json': { types: ['application/json'] },
  '.xml':  { types: ['application/xml', 'text/xml'] }
};

const SIGNATURES = {
  '.pdf':  [Buffer.from('%PDF')],
  '.doc':  [Buffer.from([0xD0, 0xCF, 0x11, 0xE0])],
  '.docx': [Buffer.from([0x50, 0x4B, 0x03, 0x04])],
  '.jpg':  [Buffer.from([0xFF, 0xD8, 0xFF])],
  '.jpeg': [Buffer.from([0xFF, 0xD8, 0xFF])],
  '.png':  [Buffer.from([0x89, 0x50, 0x4E, 0x47])],
  '.gif':  [Buffer.from('GIF87a'), Buffer.from('GIF89a')]
};
const TEXT_TYPES = new Set(['.txt', '.csv', '.json', '.xml']);

function extensionOf(name) {
  return path.extname(String(name)).toLowerCase();
}

// Checks the name and declared content type before a upload URL is issued.
function checkRequest(blobName, contentType) {
  const ext = extensionOf(blobName);
  if (!ALLOWED[ext]) return { ok: false, reason: 'File type not allowed' };
  if (contentType && !ALLOWED[ext].types.includes(String(contentType).split(';')[0].trim().toLowerCase())) {
    return { ok: false, reason: 'Content type does not match the file type' };
  }
  return { ok: true };
}

// Checks the first bytes of an uploaded file against what its extension claims.
function checkContent(blobName, head) {
  const ext = extensionOf(blobName);
  if (!ALLOWED[ext]) return { ok: false, reason: 'File type not allowed' };
  if (SIGNATURES[ext]) {
    const match = SIGNATURES[ext].some(sig => head.length >= sig.length && head.subarray(0, sig.length).equals(sig));
    return match ? { ok: true } : { ok: false, reason: 'File content does not match its extension' };
  }
  if (TEXT_TYPES.has(ext)) {
    if (head.includes(0)) return { ok: false, reason: 'File is not plain text' };
    const start = head.toString('utf8').trimStart().slice(0, 20).toLowerCase();
    if (start.startsWith('<script') || start.startsWith('<html') || start.startsWith('<!doctype html')) {
      return { ok: false, reason: 'File looks like a web page' };
    }
    return { ok: true };
  }
  return { ok: true };
}

module.exports = { ALLOWED, extensionOf, checkRequest, checkContent };
