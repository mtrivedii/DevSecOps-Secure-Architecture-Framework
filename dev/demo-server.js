// Local demo server. Runs the real application code with an in-memory
// database and fake Azure credentials, so it works without an Azure account.
//
//   npm install
//   npm run demo
//
// Then open http://localhost:3000. A demo admin is created on start:
//   admin@example.com / Admin#Demo2026
//
// What this shows: registration, login, TOTP 2FA, recovery codes, role-based admin
// pages, the user directory and the SAS-token upload endpoint.
// What it does not show: Front Door, the WAF, TDE, Managed Identity or Log Analytics.
// Those only exist in Azure. See /infra and /Documentation.

const Module = require('module');
const path = require('path');
const bcrypt = require('bcrypt');

process.env.JWT_SECRET = process.env.JWT_SECRET || 'demo-only-secret-change-me';
process.env.DB_SERVER = 'demo.local';
process.env.DB_NAME = 'demo';
process.env.SqlConnectionString = 'demo';
process.env.SQLAZURECONNSTR_SqlConnectionString = 'demo';
process.env.AZURE_STORAGE_ACCOUNT_NAME = 'demostorage';
process.env.AZURE_STORAGE_ACCOUNT_KEY = Buffer.from('demo-storage-key-not-real').toString('base64');
process.env.PORT = process.env.PORT || '3000';

// ------------------------------------------------------------ in-memory database
const users = [];
let nextId = 1;

function seedAdmin() {
  users.push({
    id: nextId++,
    email: 'admin@example.com',
    password: bcrypt.hashSync('Admin#Demo2026', 10),
    Role: 'Admin',
    status: 'Active',
    AzureID: null,
    twoFactorEnabled: 0,
    twoFactorSecret: null,
    twoFactorTempSecret: null,
    twoFactorRecoveryCodes: null,
    last_login: null,
    registration_complete: 1
  });
}

function runQuery(text, p) {
  const q = text.replace(/\s+/g, ' ').trim().toLowerCase();
  const byId = id => users.find(u => String(u.id) === String(id));
  const byEmail = e => users.find(u => u.email === e);
  const rows = list => ({ recordset: list, rowsAffected: [list.length] });

  if (q.startsWith('select id, email, password, role, status, twofactorenabled from dbo.users where email')) {
    const u = byEmail(p.emailparam);
    return rows(u ? [u] : []);
  }
  if (q.startsWith('update dbo.users set last_login')) {
    const u = byId(p.userIdParam); if (u) u.last_login = new Date();
    return rows([]);
  }
  if (q.startsWith('select 1 from dbo.users where email')) {
    return rows(byEmail(p.email) ? [{ '': 1 }] : []);
  }
  if (q.startsWith('insert into dbo.users')) {
    const u = {
      id: nextId++, email: p.email, password: p.passwordHash, Role: 'user', status: 'Active',
      AzureID: null, twoFactorEnabled: 0, twoFactorSecret: null, twoFactorTempSecret: null,
      twoFactorRecoveryCodes: null, last_login: null, registration_complete: 1
    };
    users.push(u);
    return rows([{ newId: u.id }]);
  }
  if (q.startsWith('select id, email, twofactorenabled from dbo.users where id')) {
    const u = byId(p.userId); return rows(u ? [u] : []);
  }
  if (q.includes('set twofactortempsecret = @secret')) {
    const u = byId(p.userId); if (u) u.twoFactorTempSecret = p.secret; return rows([]);
  }
  if (q.startsWith('select id, email, twofactortempsecret')) {
    const u = byId(p.userId); return rows(u ? [u] : []);
  }
  if (q.includes('twofactorenabled = 1') && q.startsWith('update')) {
    const u = byId(p.userId);
    if (u) {
      u.twoFactorEnabled = 1; u.twoFactorSecret = p.secretToStore;
      u.twoFactorTempSecret = null; u.twoFactorRecoveryCodes = p.recoveryCodesJson;
    }
    return rows([]);
  }
  if (q.startsWith('select id, email, twofactorsecret, twofactorrecoverycodes, role')) {
    const u = byId(p.userId); return rows(u && u.twoFactorEnabled ? [u] : []);
  }
  if (q.includes('set twofactorrecoverycodes = @updatedrecoverycodes')) {
    const u = byId(p.userId); if (u) u.twoFactorRecoveryCodes = p.updatedRecoveryCodes; return rows([]);
  }
  if (q.startsWith('select id, email, twofactorsecret from dbo.users')) {
    const u = byId(p.userId); return rows(u && u.twoFactorEnabled ? [u] : []);
  }
  if (q.includes('twofactorenabled = 0') && q.startsWith('update')) {
    const u = byId(p.userId);
    if (u) {
      u.twoFactorEnabled = 0; u.twoFactorSecret = null;
      u.twoFactorTempSecret = null; u.twoFactorRecoveryCodes = null;
    }
    return rows([]);
  }
  if (q.startsWith('select twofactorenabled from dbo.users')) {
    const u = byId(p.userIdInput); return rows(u ? [{ twoFactorEnabled: u.twoFactorEnabled }] : []);
  }
  if (q.startsWith('select id, email, azureid, role from dbo.users')) {
    return rows(users.map(u => ({ id: u.id, email: u.email, AzureID: u.AzureID, Role: u.Role })));
  }
  if (q.startsWith('select role from users where email')) {
    const u = byEmail(p.email); return rows(u ? [{ Role: u.Role }] : []);
  }
  if (q.startsWith('select role from users where azureid')) {
    const u = users.find(x => x.AzureID && x.AzureID === p.userId); return rows(u ? [{ Role: u.Role }] : []);
  }
  console.warn('[demo db] Unhandled query:', q.slice(0, 120));
  return rows([]);
}

function makeRequest() {
  const params = {};
  const req = {
    input(name, _type, value) { params[name] = value; return req; },
    async query(text) { return runQuery(text, params); }
  };
  return req;
}

const fakeSql = {
  NVarChar: 'NVarChar', Int: 'Int', VarChar: 'VarChar',
  connect: async () => {
    const pool = { request: makeRequest, on() {}, close: async () => {} };
    return pool;
  }
};

// -------------------------------------------------------- module substitutions
const realLoad = Module._load;
Module._load = function (request, parent, isMain) {
  if (request === 'mssql') return fakeSql;
  if (request === '@azure/identity') {
    return { DefaultAzureCredential: class { async getToken() { return { token: 'demo-token' }; } } };
  }
  if (request === '@azure/storage-blob') {
    // Use the real SAS generator, but never contact Azure.
    const real = realLoad.apply(this, arguments);
    class DemoBlobServiceClient {
      getContainerClient() {
        return {
          exists: async () => true, create: async () => {}, setAccessPolicy: async () => {},
          getBlobClient: rawName => { const name = `secure-uploads/${rawName}`; return {
            download: async (offset, count) => {
              const b = blobs.get(name);
              if (!b) { const e = new Error('not found'); e.statusCode = 404; throw e; }
              return { readableStreamBody: require('stream').Readable.from([b.data.subarray(offset, offset + count)]) };
            },
            deleteIfExists: async () => blobs.delete(name)
          }; }
        };
      }
    }
    return { ...real, BlobServiceClient: DemoBlobServiceClient };
  }
  return realLoad.apply(this, arguments);
};

// ------------------------------------------------------------ fake blob storage
// The browser uploads straight to the SAS URL. In the demo that URL points back at
// this server, which keeps the uploaded files in memory.
const blobs = new Map();
const MAX_DEMO_UPLOAD = 10 * 1024 * 1024;

function demoBlobMiddleware(req, res, next) {
  // Point SAS URLs at this server instead of Azure.
  if (req.method === 'GET' && req.path === '/api/getSasToken') {
    const realJson = res.json.bind(res);
    res.json = body => {
      if (body && typeof body.sasUrl === 'string') {
        body.sasUrl = body.sasUrl.replace(
          /^https:\/\/[^/]+\.blob\.core\.windows\.net\//,
          `${req.protocol}://${req.headers.host}/demo-blob/`
        );
      }
      return realJson(body);
    };
    return next();
  }
  if (!req.path.startsWith('/demo-blob/')) return next();

  const key = decodeURIComponent(req.path.replace('/demo-blob/', ''));
  if (req.method === 'PUT') {
    const chunks = [];
    let size = 0;
    req.on('data', c => {
      size += c.length;
      if (size > MAX_DEMO_UPLOAD) { res.status(413).end(); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      blobs.set(key, { data: Buffer.concat(chunks), type: req.headers['content-type'] || 'application/octet-stream' });
      console.log(`[demo blob] stored ${key} (${size} bytes)`);
      res.status(201).end();
    });
    return;
  }
  if (req.method === 'GET' && req.path === '/demo-blob/') {
    return res.json([...blobs.entries()].map(([name, b]) => ({ name, bytes: b.data.length, type: b.type, download: `/demo-blob/${encodeURI(name)}` })));
  }
  if (req.method === 'GET' && blobs.has(key)) {
    // Always download, never render, so an uploaded file cannot run in the browser.
    const b = blobs.get(key);
    res.setHeader('Content-Type', b.type);
    res.setHeader('Content-Disposition', `attachment; filename="${key.split('/').pop().replace(/"/g, '')}"`);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    return res.end(b.data);
  }
  if (req.method === 'GET') return res.status(404).end();
  return res.status(405).end();
}

const realExpress = require('express');
function demoExpress() {
  const app = realExpress();
  app.use(demoBlobMiddleware);
  return app;
}
Object.assign(demoExpress, realExpress);
const baseLoad = Module._load;
Module._load = function (request) {
  if (request === 'express') return demoExpress;
  return baseLoad.apply(this, arguments);
};

seedAdmin();
console.log('[demo] In-memory database ready. Demo admin: admin@example.com / Admin#Demo2026');
require(path.join(__dirname, '..', 'index.js'));
