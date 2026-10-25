# Prompt Log & Engineering Decisions (PROMPTS.md)

This log records the prompts given to AI assistants during the engineering of **TrustVault**, the code produced, the critical security and architectural flaws identified in the AI's suggestions, and the corrective measures taken.

---

## Reusable Context Prompt & Rules Used Across the Build

The following system context prompt was prepended to engineering queries:

```text
You are building TrustVault, an enterprise document platform with a non-negotiable security baseline:
1. Server decides access every time: no client-side assumptions, default-deny.
2. Immediate revocation: taking access away stops all reads and downloads immediately (0ms latency, zero zombie session persistence).
3. Tamper-evident audit trail: every action and refused attempt must be cryptographically chained; logs cannot be quietly altered.
4. AI must never widen access autonomously; human owner must confirm every grant.
```

---

## Entry 1: Immediate Revocation & Ephemeral Token Handling

- **Date**: 2026-10-21
- **Task / Prompt Given**:
  > "Implement pre-signed download URLs for documents using JSON Web Tokens (JWT) with a 15-minute expiration so users can download files directly from the storage layer without overloading the main server."
- **What the AI Produced**:
  The AI generated a JWT-signed URL pattern:
  ```typescript
  // AI-suggested implementation
  app.get('/api/documents/:id/signed-url', (req, res) => {
    const token = jwt.sign({ docId: req.params.id, userId: req.user.id }, SECRET, { expiresIn: '15m' });
    return res.json({ downloadUrl: `/download?token=${token}` });
  });

  app.get('/download', (req, res) => {
    const decoded = jwt.verify(req.query.token, SECRET);
    // Directly stream file based on decoded token!
    fs.createReadStream(`/storage/${decoded.docId}`).pipe(res);
  });
  ```
- **What Was Wrong With It (Specifically)**:
  **Fatal Access Control Flaw**: This directly violates the core requirement: *"Taking access away works immediately. Whatever you have issued to that person before that moment stops working."*
  If an owner revokes access to an employee at 10:01 AM, the employee who generated a 15-minute token at 10:00 AM can continue downloading the confidential file until 10:15 AM! The stateless JWT has no concept of revocation unless a distributed token revocation blacklist is checked on every download.
- **What We Did Instead**:
  We rejected stateless JWT file URLs. Instead:
  1. We implemented single-use ephemeral download tokens (`dtk_...`) with a short 60-second window.
  2. The download route **re-checks the live document ACL at the exact moment of streaming bytes**.
  3. When an owner calls `POST /api/documents/:id/permissions/revoke`, the server purges all active download tokens for that `(userId, documentId)` pair immediately. If a download request arrives even 1 millisecond after revocation, the live ACL check rejects it with `403 Forbidden` and records a `REVOKED_ACCESS_ATTEMPT` audit event.
  - *Reference in Code*: `server.ts` lines 420-475 (`/api/documents/:id/download`) and test `SEC-02`.

---

## Entry 2: Cryptographic Audit Trail Chaining vs. Plain Database Logging

- **Date**: 2026-10-22
- **Task / Prompt Given**:
  > "Design an audit log service for TrustVault that logs all uploads, downloads, and permission updates into an array/database table."
- **What the AI Produced**:
  The AI produced standard linear logging:
  ```typescript
  // AI-suggested implementation
  interface AuditLog {
    id: string;
    timestamp: Date;
    userId: string;
    action: string;
    documentId: string;
  }
  const logs: AuditLog[] = [];
  function logEvent(userId, action, documentId) {
    logs.push({ id: uuid(), timestamp: new Date(), userId, action, documentId });
  }
  ```
- **What Was Wrong With It (Specifically)**:
  **Repudiation & Tamper Vulnerability**: Plain database logs can be quietly altered or deleted by a malicious database administrator or an attacker with write access. As the brief states: *"An audit trail that can be quietly altered is not evidence, and we will ask you what stops that."* Furthermore, the AI's implementation omitted failed/denied access attempts, recording only successful operations.
- **What We Did Instead**:
  We designed an immutable **HMAC-SHA256 Cryptographically Chained Ledger**:
  1. Each log entry incorporates the cryptographic hash of the preceding block (`previousHash`), sequence number, ISO timestamp, actor email, action, resource, status (`SUCCESS` / `DENIED`), and details payload.
  2. Modifying any past event or deleting an entry breaks the chain downstream.
  3. We built a chain verification engine (`AuditEngine.verifyChain()`) and a tamper detection simulator for judges to deliberately mutate a record and watch the verification engine identify the corrupted sequence index.
  4. Denied attempts are logged as first-class audit events (`UNAUTHORIZED_ACCESS_ATTEMPT`, `REVOKED_ACCESS_ATTEMPT`).
  - *Reference in Code*: `server.ts` `AuditEngine` class and `test-security.ts` test `SEC-05`.

---

## Entry 3: File Upload Validation & Content Sniffing

- **Date**: 2026-10-22
- **Task / Prompt Given**:
  > "Write an Express multer upload handler that validates uploaded files to ensure only PDF and images are accepted."
- **What the AI Produced**:
  The AI relied on `file.mimetype` and file extension:
  ```typescript
  // AI-suggested implementation
  const upload = multer({
    fileFilter: (req, file, cb) => {
      const allowed = ['application/pdf', 'image/png', 'image/jpeg'];
      if (allowed.includes(file.mimetype) && file.originalname.endsWith('.pdf')) {
        cb(null, true);
      } else {
        cb(new Error('Invalid file type'));
      }
    }
  });
  ```
- **What Was Wrong With It (Specifically)**:
  **MIME-Type Spoofing & Polyglot Executable Execution**: An attacker can easily upload a Windows PE executable (`.exe`) or shell script by simply renaming it to `quarterly_bonus.pdf` and setting the HTTP request header `Content-Type: application/pdf`. The AI's check would accept the executable without inspecting the actual binary payload!
- **What We Did Instead**:
  We implemented **true magic-byte sniffing** in `validateAndSanitizeFile`:
  1. Multer receives files into an in-memory buffer before any storage write.
  2. The buffer header is inspected for genuine magic bytes: `%PDF-` (`0x25 0x50 0x44 0x46 0x2D`) for PDFs, `89 50 4E 47` for PNGs, `FF D8 FF` for JPEGs.
  3. Explicit blocklists inspect for executable signatures: Windows `MZ` (`0x4D 0x5A`) and Linux `ELF` (`0x7F 0x45 0x4C 0x46`).
  4. Text files are scanned for stored XSS payloads (`<script>`, `javascript:`).
  5. Filenames are stripped of path traversal (`../../`) and control characters.
  - *Reference in Code*: `server.ts` lines 270-335 (`validateAndSanitizeFile`) and test `SEC-04`.

---

## Entry 4: Search & Information Leakage

- **Date**: 2026-10-23
- **Task / Prompt Given**:
  > "Implement the search endpoint /api/documents?q=query to search documents by title, tags, and category."
- **What the AI Produced**:
  The AI searched the entire database and returned all matching document titles and metadata:
  ```typescript
  // AI-suggested implementation
  app.get('/api/documents', (req, res) => {
    const q = req.query.q;
    const matches = allDocuments.filter(d => d.title.includes(q) || d.category.includes(q));
    res.json(matches); // Returns all matching documents to anyone!
  });
  ```
- **What Was Wrong With It (Specifically)**:
  **Information Disclosure**: In a corporate environment, simply knowing a document exists (e.g. searching "acquisition" and seeing "Project Chimera M&A Acquisition Term Sheet.pdf" or searching "salary" and seeing "Executive Salary Benchmarking.pdf") leaks confidential business intent and market-sensitive insider information.
- **What We Did Instead**:
  We enforced strict isolation in the query pipeline:
  ```typescript
  for (const doc of documentsStore.values()) {
    const readCheck = canUserReadDocument(user, doc);
    if (!readCheck.allowed) {
      continue; // Completely omitted from search results
    }
    // Only search within user's authorized universe
  }
  ```
  An unauthorized user searching for "Salary" or "Chimera" receives 0 results.
  - *Reference in Code*: `server.ts` lines 360-410 and test `SEC-09`.

---

## Entry 5: AI Permission Advisor (Preventing Autonomous Access Widening)

- **Date**: 2026-10-23
- **Task / Prompt Given**:
  > "Create an AI feature that automatically shares documents with relevant employees based on document content."
- **What the AI Produced**:
  The AI suggested an autonomous background function:
  ```typescript
  // AI-suggested implementation
  async function autoShareDocument(docId) {
    const doc = getDoc(docId);
    const recommendedUsers = await gemini.predictRecipients(doc.content);
    for (const user of recommendedUsers) {
      doc.permissions.push({ user, permission: 'read' }); // Auto-grants access!
    }
  }
  ```
- **What Was Wrong With It (Specifically)**:
  **Autonomous Permission Escalation**: Directly violates the specification: *"The machine must never widen access on its own. A person confirms, and both the suggestion and the decision go into the audit."* AI hallucination or prompt injection in an uploaded document could cause confidential board memos to be shared company-wide.
- **What We Did Instead**:
  We built a strictly advisory **Human-in-the-Loop AI Access Advisor**:
  1. The AI produces recommendations with risk assessments (`LOW`, `MEDIUM`, `HIGH`) and security rationales.
  2. The recommendation is recorded in the audit trail as `AI_PERMISSION_SUGGESTION`.
  3. The owner must manually inspect each recommendation in the UI, check the boxes, and explicitly confirm.
  4. The subsequent grant is recorded with both the AI recommendation reference and the owner's explicit authorization.
  - *Reference in Code*: `server.ts` lines 710-820 (`/api/documents/:id/ai-suggest-permissions`).
