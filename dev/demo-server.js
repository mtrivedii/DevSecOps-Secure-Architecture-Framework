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
        return { exists: async () => true, create: async () => {}, setAccessPolicy: async () => {} };
      }
    }
    return { ...real, BlobServiceClient: DemoBlobServiceClient };
  }
  return realLoad.apply(this, arguments);
};

seedAdmin();
console.log('[demo] In-memory database ready. Demo admin: admin@example.com / Admin#Demo2026');
require(path.join(__dirname, '..', 'index.js'));
