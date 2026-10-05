# Secure Azure Web Application

**Status: Archived - Azure resources have been decommissioned.**

A secure, full-stack web application deployed on Microsoft Azure, built as part of the *Advanced Cyber Security* course at Fontys University of Applied Sciences. The project covers architecture design, threat modelling, implementation, and post-deployment security testing.

---

## Overview

- **Stack:** Azure App Service (Linux) + Azure SQL + Node.js + GitHub Actions CI/CD
- **Domain:** maanitwebapp.com (no longer live)
- **Security frameworks:** CIS Controls, NIST SP 800-53, OWASP Top 10

---

## Security Features

### Authentication & Access Control
- TOTP-based two-factor authentication (Google/Microsoft Authenticator)
- JWT session management via secure `httpOnly` cookies
- Role-based access control (admin/user)
- NIST SP 800-63B compliant password policy with server-side validation
- IP-based rate limiting on login and registration endpoints

### Application Security
- Azure Front Door with custom WAF rules (SQLi, XSS, SSRF, Command Injection, CSRF, Path Traversal)
- HTTPS enforced end-to-end with HSTS
- Security headers: CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
- CSRF token protection on all forms
- Parameterised SQL queries throughout

### File Upload
- SAS token-based uploads directly to Azure Blob Storage (storage keys never exposed to client)
- Server-side allowlist of file extensions with a matching content type check, plus a content check after upload (see findings table for its limits)
- Filename sanitisation to prevent path traversal
- Time-limited, write-only SAS tokens (1-hour expiry)

### Security event log
- Sign-in, 2FA, registration, upload and admin-access events are recorded with the source address and a masked email (never passwords or codes)
- Admins see the latest events at `/security.html`; every event is also written to the application log as a JSON line for Log Analytics
- Alert rule: 5 failed sign-in or 2FA attempts from one address in 10 minutes raises an `alert.brute_force` event
- The page reads an in-memory list, so it is per server instance and resets on restart. The log lines are the durable record

### Cloud & Infrastructure
- Azure SQL with Transparent Data Encryption (TDE) and Managed Identity access
- Secrets injected via Azure App Service environment variables (no hardcoding)
- Defender for Cloud with vulnerability scanning and compliance monitoring
- Azure Monitor, Log Analytics, and Application Insights with a live security dashboard

### DevSecOps
- GitHub Actions CI/CD pipeline with CodeQL static analysis on every push
- OWASP ZAP dynamic analysis (DAST) performed post-deployment
- Compliance mapping against CIS Controls and NIST SP 800-53

---

## Architecture

The final architecture differs from the original design in a few key areas:

| Component | Original Plan | Final Implementation |
|---|---|---|
| Frontend hosting | Azure Static Web Apps | Azure App Service (Linux) |
| Authentication | Azure AD B2C | Custom TOTP + bcrypt + JWT |
| Secrets management | Azure Key Vault | App Service environment variables |
| Network segmentation | NSGs | Azure Front Door + WAF (perimeter) |
| Encryption at rest | Azure Disk Encryption | SQL Transparent Data Encryption |

Full justification for each change is documented in the Body of Knowledge (`/Documentation`).

---

## Security Testing

The application was subject to two rounds of independent testing:

**OWASP ZAP (DAST)** - Post-deployment dynamic scan. Zero high-severity findings. Four medium-severity findings identified and reviewed (CSP configuration, cookie flags, cache headers).

**Hacking Week (Red Team)** - The application was targeted by red teamers during a dedicated adversarial testing week. Findings and remediation status:

| Finding | Status |
|---|---|
| JWT stored in localStorage; role validation done client-side | Fixed - the session token lives only in an `httpOnly` cookie with `Secure` and `SameSite` flags. It is no longer returned in response bodies or kept in localStorage. Role checks on the server; the browser keeps only the email and role for display |
| 2FA endpoint lacked rate limiting; user IDs enumerable via API | Fixed in code - the 2FA endpoints no longer take a user ID from the request. The password step issues a short-lived signed cookie (`twofa_session`, 5 min, separate signing key, useless as a login session) that says which account the code is for. Failed codes are limited per account (5 per 15 minutes). Covered by automated tests |
| File upload bypass via `.php.jpg` extension and modified `Content-Type` headers | Mostly addressed - allowlist of file types (replacing the blocklist), declared content type must match the extension, and after upload the server reads the start of the file and deletes it if it does not match (magic bytes for PDF, Office, JPG, PNG, GIF; text check for TXT, CSV, JSON, XML). Limit: uploads go straight to Blob Storage and the browser triggers the check, so a client that skips it is not checked. Closing that needs a storage-side scan (Event Grid + function, or Defender for Storage) |
| WAF operating in detection mode rather than prevention mode | Fixed - WAF switched to prevention mode with 20+ custom rules |
| IP-based rate limiting bypassed via VPN/Tor | Not fully addressed - requires IP intelligence services beyond project scope |
| CSP uses `unsafe-inline` for `script-src` and `style-src` | Partially addressed - all inline scripts moved to files and `script-src` is now `'self'` only. `style-src` still allows `unsafe-inline` |
| Slow-rate directory enumeration not detected | Not addressed - requires behavioural anomaly detection. The new event log and brute-force alert cover sign-in and 2FA failures only |

The full red team report is in the `/Documentation` folder.

---

## Tests

```
npm install
npm test
```

The tests start the demo server and use real HTTP requests. They cover registration and login, the 2FA flow (including attempts to target another user), recovery codes, admin-only routes and forged cookies, upload rules, and the security event log.

CI runs them with `npm run test --if-present` before deploy.

---

## Run locally (demo)

The application needs Azure SQL, Blob Storage and Managed Identity, so it cannot start on a laptop as it is. `dev/demo-server.js` runs the real application code against an in-memory database and fake Azure credentials:

```
npm install
npm run demo
```

Open http://localhost:3000. A demo admin is created on start: `admin@example.com` / `Admin#Demo2026`. You can register users, set up TOTP 2FA and recovery codes, see the admin pages and the user directory, and upload files. Uploads go to a fake blob store held in memory, so they disappear when the server stops. See what was uploaded at http://localhost:3000/demo-blob/ and open the `download` link for a file. This listing exists only in the demo and has no login check.

This demonstrates the application logic only. Front Door, the WAF, TDE, Managed Identity and Log Analytics exist only in Azure. See `infra/` and `/Documentation` for those.

---

## Infrastructure as code

`infra/main.bicep` describes the Azure environment in Bicep: Front Door with a WAF policy, App Service (Linux, Node 20), Azure SQL with TDE and Entra-only auth, Blob Storage with a private container, Log Analytics and Application Insights. It uses the resource names from the Body of Knowledge.

It was reconstructed from the architecture documentation after the Azure resources were decommissioned, because the original environment was built in the portal. It compiles with `az bicep build --file infra/main.bicep`, but it has not been deployed. The WAF policy shows the structure with four representative custom rules. The deployed policy had 20+.

---

## Documentation

All technical documentation - Body of Knowledge, architecture diagrams, threat model, data flow, compliance mapping, and OWASP ZAP report, is in the `/Documentation` folder.

---

## Contact

**Maanit Trivedi**
maanit49@gmail.com
