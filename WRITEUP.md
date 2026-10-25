# TrustVault — Engineering Write-Up & Architecture Defense (WRITEUP.md)

---

## 1. Executive Summary & What Was Built

TrustVault was engineered to solve the two catastrophic failure modes of confidential document sharing:
1. **Permission Creep & Stale Access**: Unauthorized individuals gaining or retaining access to sensitive corporate records.
2. **Post-Incident Repudiation**: Inability to mathematically prove who accessed or attempted to access a leaked document.

We built a hardened, server-authoritative document security platform with:
- **Server-Decides-Every-Time Architecture**: Zero client-side trust. Every API route (`/api/documents/:id`, `/api/documents/:id/content`, `/api/documents/:id/download`) evaluates the requesting identity against the document's Access Control List (ACL). Unauthorized documents are pruned at the database query boundary, eliminating metadata and title leakage.
- **Immediate Revocation (0ms Latency)**: When an owner revokes access, active ACL grants are removed instantly, active ephemeral download tokens are purged from memory, and file streaming routes perform live re-checks at byte-delivery time.
- **HMAC-SHA256 Cryptographically Chained Audit Ledger**: Every action and refused attempt (`status: 'DENIED'`) is chained to its predecessor's cryptographic hash. Altering historical logs breaks chain integrity, flagged down to the exact sequence index.
- **Multi-Layer File Validation**: Sniffs raw buffer headers for genuine magic bytes (`%PDF-`, `\x89PNG`, `FF D8 FF`), rejects executable binaries (`MZ`, `ELF`), strips path traversal payloads (`../../../../etc/passwd`), and scans text for script injection tags.
- **Human-in-the-Loop AI Access Advisor**: Uses Gemini 2.5 Flash to recommend least-privilege recipients based on content sensitivity. Crucially, the machine *cannot* widen access autonomously; human owner confirmation is mandatory, and both recommendation and approval are logged.
- **Security Debug Mode**: A live query inspector revealing the exact parameterized SQL/Row-Level Security predicates and per-document evaluation traces.

---

## 2. What Was Deliberately Left Out (And Why)

A smaller system with an unbroken permission model beats a larger application with a security hole. We intentionally chose not to build:

1. **Folder-Level Inheritance & Nested Groups**:
   - *Why Left Out*: Folder inheritance is the single most common cause of corporate permission leaks (e.g. adding an auditor to a "Finance" folder so they can see one invoice, inadvertently giving them access to executive compensation). TrustVault enforces **explicit, per-document named grants**.
2. **Stateless JWT-Based Download URLs**:
   - *Why Left Out*: Pre-signed URLs using stateless JWTs with 15-minute expirations create an unavoidable window of vulnerability where a revoked employee can continue downloading files until the token expires. We replaced this with **single-use ephemeral tokens (`dtk_...`) combined with live ACL checks at byte-delivery time**.
3. **Automatic Superuser Backdoor for Administrators**:
   - *Why Left Out*: Standard IT administrator "read-all" privileges create insider threat risk. TrustVault isolates administrative health/audit oversight from document content. Administrators cannot read confidential documents without an **Emergency Break-Glass procedure**, which requires written justification and triggers a permanent high-severity `ALERT` log.
4. **Client-Side Zero-Knowledge Encryption**:
   - *Why Left Out*: Complete client-side client encryption prevents server-side malware scanning, magic byte verification, DLP text indexing, and server-rendered dynamic confidential watermarking. Server-side envelope encryption was preferred.

---

## 3. The Permission Model in Our Own Words

TrustVault enforces a strict **Default-Deny Access Matrix**:

```
[ Requesting Identity ]
         │
         ├── Is user the Document Owner? ─────────────► ALLOW (Full Control)
         │
         ├── Is user explicitly named in ACL?
         │         │
         │         ├── Has the grant expired? ────────► DENY (HTTP 403, Log UNAUTHORIZED_ACCESS)
         │         │
         │         └── Permission Level:
         │                   ├── 'edit' ──────────────► ALLOW (Read, Stream, Download, Update)
         │                   └── 'read' ──────────────► ALLOW (Read, Stream, Download)
         │
         ├── Is user an Administrator?
         │         │
         │         ├── Invoking Emergency Break-Glass?► ALLOW (Log High-Severity ALERT)
         │         └── Routine Read Request? ─────────► DENY (HTTP 403, Admin backdoor barred)
         │
         └── Fallthrough ─────────────────────────────► DENY (HTTP 403, Log UNAUTHORIZED_ACCESS)
```

- **Document Owner**: Has full sovereignty over the document. Can grant read or edit rights to named colleagues, set time limits, revoke access instantly, view per-document audit trails, and delete the file.
- **Authorized Viewer**: Can only interact with documents explicitly granted to them. Cannot widen access, cannot grant permissions to others, and cannot delete records.
- **Administrator**: Exercises compliance and audit oversight. Can review system-wide audit ledgers, verify cryptographic chain integrity, and monitor security incidents, but cannot quietly read confidential documents without break-glass auditing.

---

## 4. How We Used AI & Where It Was Wrong

AI was utilized as an engineering pair-programmer and integrated as an advisory feature within the platform. Critical areas where AI suggested flawed patterns that had to be caught and corrected:

1. **Stateless JWT File Links (Caught & Corrected)**:
   - *AI Proposal*: Pre-signed download links using 15-minute JWTs.
   - *The Flaw*: Violated the immediate revocation requirement by creating a 15-minute zombie access window.
   - *Correction*: Replaced with single-use ephemeral tokens verified against the live ACL at the exact moment of streaming.
2. **Un-Chained Database Logging (Caught & Corrected)**:
   - *AI Proposal*: Standard linear logging into an array/database table without integrity hashing.
   - *The Flaw*: Logs could be quietly altered or erased by an insider without detection, and refused attempts were omitted.
   - *Correction*: Implemented HMAC-SHA256 cryptographically chained ledgers with sequence validation and mandatory logging of denied attempts.
3. **MIME-Type Upload Checking (Caught & Corrected)**:
   - *AI Proposal*: Checking `file.mimetype === 'application/pdf'` and file extension.
   - *The Flaw*: Vulnerable to executable masquerading (renaming `.exe` to `.pdf` with an arbitrary MIME header).
   - *Correction*: Implemented raw buffer magic byte sniffing for `%PDF-`, `\x89PNG`, and explicit rejection of `MZ` / `ELF` headers.
4. **Autonomous AI Permission Granting (Caught & Corrected)**:
   - *AI Proposal*: AI background task automatically granting access to relevant departments.
   - *The Flaw*: Violated the rule that AI must never widen access autonomously.
   - *Correction*: Built a strictly advisory AI Access Advisor requiring manual human owner confirmation, logging both recommendation and approval.

---

## 5. What Is Unfinished & Next Enterprise Steps

In a production banking or defense deployment, the following enhancements would be added:
1. **External RFC 3161 Timestamp Anchoring**: Periodically publish head hashes to an external immutable ledger or hardware security module (HSM) to prevent whole-chain regeneration attacks.
2. **Database Clustering**: Transition in-memory document state to PostgreSQL with native Row-Level Security (RLS) and Redis clusters for distributed ephemeral token invalidation.
3. **Antivirus Engine Integration**: Pair magic byte sniffing with a clustered ClamAV daemon for deep malware scanning.
