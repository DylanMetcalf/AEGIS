import type {
  EvidenceKind,
  FindingStatus,
  RelationshipKind,
  Severity,
  TelemetryEventType,
  VerificationStatus,
} from './enums.js';
import type {
  AssetStatus,
  AssetType,
  AuditActorType,
  AuditOutcome,
  ComponentState,
  CoverageState,
  Criticality,
  Environment,
  HealthCheckResult,
  IntegrationStatus,
  JobStatus,
  MembershipStatus,
  PlatformRole,
  PrincipalKind,
  TenantRole,
} from './enums.js';
import type { AuthorizationScope } from './schemas.js';

/** Response DTOs. The server is the source of truth; these types describe its JSON. */

export interface ApiErrorBody {
  error: {
    code: string;
    message: string;
    requestId: string;
    details?: { path: string; message: string }[];
  };
}

export interface Page<T> {
  items: T[];
  nextCursor: string | null;
}

export interface SessionInfo {
  principal: {
    id: string;
    kind: PrincipalKind;
    displayName: string;
    email: string | null;
    platformRole: PlatformRole | null;
  };
  activeTenant: { id: string; slug: string; displayName: string; role: TenantRole } | null;
  memberships: { tenantId: string; slug: string; displayName: string; role: TenantRole }[];
  /** Effective capabilities in the active tenant plus platform capabilities. Advisory for UI only. */
  capabilities: string[];
  session: {
    id: string;
    expiresAt: string;
    idleExpiresAt: string;
    reauthenticatedUntil: string | null;
  };
}

export interface SessionSummary {
  id: string;
  createdAt: string;
  lastSeenAt: string;
  expiresAt: string;
  userAgent: string | null;
  current: boolean;
}

export interface AssetDto {
  id: string;
  name: string;
  assetType: AssetType;
  environment: Environment;
  criticality: Criticality;
  status: AssetStatus;
  coverageState: CoverageState;
  description: string | null;
  authorizationScope: AuthorizationScope;
  version: number;
  createdAt: string;
  updatedAt: string;
}

export interface CapabilityDeclaration {
  key: string;
  description: string;
  requiredPermissions: string[];
  implemented: boolean;
}

export interface ProviderDto {
  id: string;
  displayName: string;
  description: string;
  testAdapter: boolean;
  version: string;
  capabilities: CapabilityDeclaration[];
  permissions: { key: string; description: string }[];
  configFields: {
    key: string;
    label: string;
    type: 'string' | 'url' | 'number' | 'enum';
    required: boolean;
    options?: string[];
    help?: string;
  }[];
  supportsCredential: boolean;
}

export interface IntegrationDto {
  id: string;
  name: string;
  provider: string;
  providerDisplayName: string;
  testAdapter: boolean;
  status: IntegrationStatus;
  /** Status adjusted for freshness: a stale health result is reported as STALE. */
  effectiveStatus: IntegrationStatus | 'STALE';
  config: Record<string, unknown>;
  configVersion: number;
  hasCredential: boolean;
  credentialRef: string | null;
  declaredCapabilities: string[];
  grantedPermissions: string[];
  /** Capabilities usable with the granted permissions. */
  availableCapabilities: string[];
  assetId: string | null;
  lastHealthStatus: HealthCheckResult | null;
  lastHealthAt: string | null;
  lastErrorCode: string | null;
  version: number;
  createdAt: string;
  updatedAt: string;
}

export interface HealthCheckDto {
  id: string;
  result: HealthCheckResult;
  observedAt: string;
  latencyMs: number | null;
  errorCode: string | null;
  configVersion: number;
}

export interface JobDto {
  id: string;
  kind: string;
  status: JobStatus;
  attempts: number;
  maxAttempts: number;
  lastErrorCode: string | null;
  createdAt: string;
  finishedAt: string | null;
}

export interface MemberDto {
  id: string;
  principalId: string;
  displayName: string;
  email: string | null;
  kind: PrincipalKind;
  role: TenantRole;
  status: MembershipStatus;
  createdAt: string;
}

export interface AuditEventDto {
  id: string;
  chainPosition: string;
  occurredAt: string;
  tenantId: string | null;
  actorPrincipalId: string | null;
  actorType: AuditActorType;
  action: string;
  targetType: string | null;
  targetId: string | null;
  outcome: AuditOutcome;
  reasonCode: string | null;
  requestId: string | null;
  correlationId: string | null;
  metadata: Record<string, unknown>;
}

export interface ComponentStatusDto {
  key: string;
  label: string;
  state: ComponentState;
  required: boolean;
  observedAt: string | null;
  detail: string;
}

export interface SetupIssueDto {
  code: string;
  severity: 'info' | 'warning' | 'critical';
  message: string;
}

export interface OverviewDto {
  generatedAt: string;
  tenant: { id: string; displayName: string };
  assets: {
    total: number;
    byEnvironment: Partial<Record<Environment, number>>;
    byCriticality: Partial<Record<Criticality, number>>;
    byCoverage: Partial<Record<CoverageState, number>>;
  };
  integrations: {
    total: number;
    byEffectiveStatus: Partial<Record<IntegrationStatus | 'STALE', number>>;
    testAdapters: number;
  };
  telemetry: {
    state: ComponentState;
    detail: string;
    eventsLast24h: number;
    lastEventAt: string | null;
  };
  findings: {
    state: ComponentState;
    detail: string;
    open: number;
    openBySeverity: Partial<Record<Severity, number>>;
  };
  components: ComponentStatusDto[];
  setupIssues: SetupIssueDto[];
  recentAudit: AuditEventDto[] | null;
}

export interface IngestTokenDto {
  id: string;
  prefix: string;
  createdAt: string;
  lastUsedAt: string | null;
  revokedAt: string | null;
}

export interface TelemetryEventDto {
  id: string;
  eventType: TelemetryEventType;
  severity: Severity;
  observedAt: string;
  receivedAt: string;
  actorUserId: string | null;
  actorIp: string | null;
  attributes: Record<string, string | number | boolean>;
  integrationId: string;
  assetId: string | null;
}

export interface FindingDto {
  id: string;
  ruleId: string;
  ruleVersion: number;
  title: string;
  severity: Severity;
  status: FindingStatus;
  groupKey: string;
  assetId: string | null;
  integrationId: string | null;
  occurrenceCount: number;
  firstSeenAt: string;
  lastSeenAt: string;
  summary: Record<string, unknown>;
  resolutionNote: string | null;
  assigneePrincipalId: string | null;
  version: number;
  createdAt: string;
  updatedAt: string;
}

export interface EvidenceDto {
  id: string;
  kind: EvidenceKind;
  /** True only for kinds that can ever count as proof. */
  probative: boolean;
  findingId: string | null;
  investigationId: string | null;
  telemetryEventId: string | null;
  provenance: {
    collectorType: 'INTEGRATION' | 'PLATFORM' | 'HUMAN' | 'AI_MODEL';
    collectorId: string;
    collectorVersion: string;
    collectedAt: string;
    sourceRef: string;
    contentSha256: string;
  };
  body: Record<string, unknown> | null;
  verificationStatus: VerificationStatus;
  verifiedAt: string | null;
  createdBy: string | null;
  createdAt: string;
}

export interface InvestigationDto {
  id: string;
  title: string;
  status: 'OPEN' | 'CLOSED';
  summary: string | null;
  findingIds: string[];
  closedAt: string | null;
  version: number;
  createdAt: string;
  updatedAt: string;
}

export interface CoverageDto {
  assetId: string;
  assetName: string;
  state: CoverageState;
  reasons: string[];
  evaluatedAt: string;
}

export interface RelationshipDto {
  id: string;
  fromAssetId: string;
  toAssetId: string;
  kind: RelationshipKind;
  createdAt: string;
}

export interface GraphDto {
  nodes: { id: string; type: 'asset' | 'finding' | 'integration'; label: string; state: string }[];
  edges: { from: string; to: string; kind: string }[];
  truncated: boolean;
}
