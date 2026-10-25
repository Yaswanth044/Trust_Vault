# TrustVault — Secure Document Sharing with a Real Audit Trail

TrustVault is an enterprise document security platform engineered around one core principle:
**The wrong person can never read the file, and you can mathematically prove who read it.**

---

## 🔑 Pre-Seeded Accounts & Test Credentials

The system comes pre-seeded with 5 accounts across all 3 roles, including an unauthorized external identity for security testing. Switch between them instantly via the **Identity Switcher** at the top right of the application:

| Role | Name & Department | Email | Password | Access Capabilities |
| :--- | :--- | :--- | :--- | :--- |
| **Administrator** | Eleanor Vance (*Security Audit*) | `admin@trustvault.internal` | `AdminPass123!` | System oversight, full audit ledger, cryptographic hash verification, security incident monitor. **No automatic backdoor read on confidential files without audited Break-Glass.** |
| **Document Owner** | Sarah Jenkins (*People Ops & Finance*) | `sarah.owner@trustvault.internal` | `OwnerPass123!` | Uploads confidential files, grants/revokes permissions to named people immediately, views document audit history, deletes owned docs. |
| **Document Owner** | Marcus Sterling (*Legal & M&A*) | `marcus.owner@trustvault.internal` | `OwnerPass123!` | Manages M&A contracts and secret term sheets. Revokes access immediately. |
| **Viewer** | Elena Rostova (*Senior Analytics*) | `elena.viewer@trustvault.internal` | `ViewerPass123!` | Can only access documents explicitly granted to her. Cannot widen access, cannot delete, cannot view admin logs. |
| **Untrusted / Attacker** | Alex Mercer (*External Contractor*) | `alex.untrusted@external.com` | `ExternalPass123!` | Holds zero grants. Used for testing IDOR, path traversal, and search leakage defense. |

---

## 🌐 Live Application Deployment

| Environment | Live URL | Description |
| :--- | :--- | :--- |
| **Development Instance** | [https://ais-dev-obkecyuwoto44d4pp4l2yk-727509656447.asia-east1.run.app](https://ais-dev-obkecyuwoto44d4pp4l2yk-727509656447.asia-east1.run.app) | Active instance running server & tests live on Cloud Run |
| **Shared Preview** | [https://ais-pre-obkecyuwoto44d4pp4l2yk-727509656447.asia-east1.run.app](https://ais-pre-obkecyuwoto44d4pp4l2yk-727509656447.asia-east1.run.app) | Public shared preview endpoint |

---

## 🏛️ The Three Non-Negotiable Standards

### 1. Server Decides, Every Time
- Access is never determined by client UI state or hidden buttons.
- Every API endpoint (`/api/documents/:id`, `/api/documents/:id/content`, `/api/documents/:id/download`) evaluates `canUserReadDocument(req.user, doc)`.
- If no active, unexpired grant exists in the document's ACL, access is rejected with `403 Forbidden` and audited as an unauthorized attempt.

### 2. Tamper-Evident Cryptographic Audit Trail
- Every upload, download, view, edit, deletion, grant, revocation, and **refused attempt** is recorded in a cryptographically chained ledger.
- Each event includes:
  $$\text{hash}_n = \text{HMAC-SHA256}(\text{seq}_n \parallel \text{timestamp}_n \parallel \text{actor} \parallel \text{action} \parallel \text{resource} \parallel \text{status} \parallel \text{details} \parallel \text{hash}_{n-1})$$
- An audit log cannot be quietly modified or deleted: altering any past entry invalidates the chain.
- The built-in **Audit Integrity Inspector** and CLI runner verify every block from Genesis to Head.

### 3. Immediate Access Revocation (0ms Latency)
- When an owner revokes a user's permission:
  1. The user's grant is removed from the document ACL immediately.
  2. All active ephemeral download tokens for that user and document are purged instantly.
  3. The file streaming endpoint performs a **live ACL re-check** at byte-delivery time.
  4. Any subsequent read or download attempt fails instantly with `403 Forbidden` and logs a `REVOKED_ACCESS_ATTEMPT`.

---

## 🚀 Setup Instructions (Clean Clone)

### Prerequisites
- Node.js 20+ installed
- npm 9+

### 1. Clone & Install
```bash
git clone <repository_url>
cd trustvault
npm install
```

### 2. Run Automated Security Penetration Tests
```bash
npm test
```
*Expected Output*: 10/10 security tests pass, covering IDOR, Immediate Revocation, Path Traversal, Magic Byte Sniffing, Cryptographic Chain Verification, Ephemeral Tokens, Privilege Escalation, Deletion Defense, Search Leakage, and Admin Backdoor Separation.

### 3. Run Development Server
```bash
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## 🛡️ API Documentation & Authorization Matrix

| Method | Endpoint | Allowed Callers | Authorization Logic & Constraints |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/users` | All Authenticated | Returns directory of system identities for permission sharing. |
| `GET` | `/api/me` | All Authenticated | Returns current authenticated user context. |
| `GET` | `/api/documents` | All Authenticated | **Strict isolation**: Returns only documents the user owns or is explicitly granted in ACL. Unauthorized docs are excluded. |
| `GET` | `/api/documents/:id` | Document Owner OR Granted User | Returns document metadata. Refused attempts logged as `UNAUTHORIZED_ACCESS_ATTEMPT`. |
| `GET` | `/api/documents/:id/content`| Document Owner OR Granted User | Streams document content with dynamic confidential watermark header (`X-TrustVault-Watermark`). |
| `POST`| `/api/documents/:id/token` | Document Owner OR Granted User | Issues a single-use 60-second download token (`dtk_...`). |
| `GET` | `/api/documents/:id/download`| Document Owner OR Granted User | Validates direct session or consumes single-use ephemeral token. Re-checks live ACL at byte stream time. |
| `POST`| `/api/documents` | Owner or Administrator | Uploads document. Enforces magic byte sniffing, filename sanitization, and 20MB limit. |
| `PUT` | `/api/documents/:id` | Document Owner OR Granted Editor | Updates document metadata or text content. Increments version and recomputes SHA-256 checksum. |
| `DELETE`| `/api/documents/:id` | Document Owner ONLY | Deletes metadata, invalidates all tokens, and unlinks file from storage. |
| `POST`| `/api/documents/:id/permissions`| Document Owner ONLY | Adds or updates named user grant (`read` or `edit`, optional expiration). Logged in audit trail. |
| `POST`| `/api/documents/:id/permissions/revoke`| Document Owner ONLY | **Immediate Revocation**: Removes ACL grant, invalidates active download tokens. Zero zombie session latency. |
| `POST`| `/api/documents/:id/ai-suggest-permissions`| Document Owner ONLY | Evaluates document sensitivity using Gemini AI and recommends least-privilege recipients. Audited as `AI_PERMISSION_SUGGESTION`. |
| `GET` | `/api/audit` | Administrator (Global) OR Owner (Own Docs) | Retrieves audit events. Non-admins cannot view global logs. |
| `GET` | `/api/audit/verify` | Administrator OR Test Runner | Cryptographically walks hash chain and verifies SHA-256 HMAC integrity from sequence 0 to head. |
| `POST`| `/api/audit/simulate-tamper`| Security Judges & Auditors | Mutates an event in memory to demonstrate cryptographic tamper detection. |
| `POST`| `/api/audit/restore` | Security Judges & Auditors | Restores pristine audit chain state. |
| `POST`| `/api/admin/break-glass/:id` | Administrator ONLY | Emergency procedure to access a document with mandatory written justification. Logs high-severity `ALERT` event. |
| `GET` | `/api/security/run-tests` | Security Judges / All Users | Runs the live 10-test automated penetration suite against the server and returns forensic evidence. |

---

## 🧪 Security Test Suite

The automated test suite in `test-security.ts` asserts:
1. **SEC-01**: IDOR prevention on confidential documents.
2. **SEC-02**: Immediate revocation enforcement (0ms latency, zero zombie session persistence).
3. **SEC-03**: Directory traversal sanitization (`../../../../etc/passwd`).
4. **SEC-04**: Executable masquerade & magic byte sniffing (MZ / PE binaries rejected).
5. **SEC-05**: Cryptographic audit hash chaining and tamper detection.
6. **SEC-06**: Ephemeral download token single-use & replay attack defense.
7. **SEC-07**: Privilege escalation prevention (Viewer cannot grant permissions).
8. **SEC-08**: Unauthorized deletion block.
9. **SEC-09**: Search query information leakage prevention.
10. **SEC-10**: Admin backdoor separation (routine access barred without break-glass).

Run via:
```bash
npm test
```

---

## 🤖 Where AI Fits & Where It Must Not Decide

TrustVault integrates Gemini 2.5 Flash as an **Access Advisor** under the strict **Human-in-the-Loop** principle:
- When a document owner clicks **AI Access Advisor**, the model analyzes the document title, category, description, and classification against the organizational directory.
- It suggests the least-privilege access tier with clear security rationale (e.g. recommending read-only for Elena and warning that external contractors represent high data exfiltration risk).
- **The machine cannot write to the ACL autonomously.**
- The human owner must manually review the recommendations, select checkboxes, and click **Approve & Grant**.
- Both the AI recommendation and the owner's manual confirmation are recorded as distinct events in the cryptographic audit ledger.

---

## 📁 Repository Structure
```
├── THREATS.md                 # Threat modeling, STRIDE/OWASP mapping, mitigations, accepted risks
├── PROMPTS.md                 # 5 dated entries documenting AI interactions, catches, and security fixes
├── README.md                  # System overview, credentials, setup, API documentation
├── test-security.ts           # Standalone automated penetration test suite (npm test)
├── server.ts                  # Hardened Express server: authorization, audit chain, magic bytes
├── storage/vault_files/       # Opaque encrypted document storage outside web root
├── src/
│   ├── types.ts               # Core TypeScript definitions (Document, Grant, AuditEvent, etc.)
│   ├── App.tsx                # TrustVault React SPA with role-based UI and live security tester
│   ├── main.tsx               # Client entry point
│   └── index.css              # Tailwind styling
```
