export type UserRole = 'admin' | 'owner' | 'viewer';

export interface User {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  department: string;
  avatarColor: string;
}

export type DocumentClassification = 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED' | 'SECRET';

export type PermissionLevel = 'read' | 'edit';

export interface DocumentGrant {
  id: string;
  userId: string;
  userEmail: string;
  userName: string;
  permission: PermissionLevel;
  grantedBy: string; // user email
  grantedAt: string; // ISO string
  expiresAt?: string | null; // ISO string or null for indefinite
}

export interface VaultDocument {
  id: string;
  title: string;
  filename: string;
  originalName: string;
  mimeType: string;
  sizeBytes: number;
  checksumSha256: string;
  category: string;
  classification: DocumentClassification;
  description: string;
  ownerId: string;
  ownerEmail: string;
  ownerName: string;
  createdAt: string;
  updatedAt: string;
  version: number;
  tags: string[];
  permissions: DocumentGrant[];
  storagePath: string; // Server internal opaque path
  textContentPreview?: string; // For safe sanitized preview
}

export type AuditAction =
  | 'DOCUMENT_UPLOAD'
  | 'DOCUMENT_READ'
  | 'DOCUMENT_DOWNLOAD'
  | 'DOCUMENT_EDIT'
  | 'DOCUMENT_DELETE'
  | 'PERMISSION_GRANT'
  | 'PERMISSION_REVOKE'
  | 'UNAUTHORIZED_ACCESS_ATTEMPT'
  | 'REVOKED_ACCESS_ATTEMPT'
  | 'PATH_TRAVERSAL_ATTEMPT'
  | 'TAMPER_DETECTION_CHECK'
  | 'CHAIN_VERIFICATION'
  | 'BREAK_GLASS_ACCESS'
  | 'AI_PERMISSION_SUGGESTION'
  | 'AI_PERMISSION_APPROVED';

export type AuditStatus = 'SUCCESS' | 'DENIED' | 'ALERT';

export interface AuditEvent {
  id: string;
  sequenceNumber: number;
  timestamp: string;
  actorId: string;
  actorEmail: string;
  actorRole: UserRole | 'anonymous';
  action: AuditAction;
  resourceId?: string;
  resourceName?: string;
  status: AuditStatus;
  ipAddress: string;
  userAgent: string;
  details: Record<string, any>;
  previousHash: string;
  hash: string;
}

export interface AuditVerificationResult {
  isValid: boolean;
  totalEntries: number;
  verifiedEntries: number;
  brokenSequenceIndex?: number;
  brokenEventId?: string;
  failureReason?: string;
  headHash: string;
}

export interface SecurityTestCaseResult {
  id: string;
  title: string;
  category: 'Access Control' | 'Immediate Revocation' | 'Audit Integrity' | 'Input Validation' | 'Information Leakage';
  threatRef: string;
  description: string;
  status: 'PASSED' | 'FAILED';
  httpStatusExpected: number;
  httpStatusReceived: number;
  auditTrailVerified: boolean;
  evidence: string;
  durationMs: number;
}
