/**
 * Canonical enumerations for AEGIS.
 *
 * These are the only accepted values for security-sensitive state. The
 * database mirrors them with CHECK constraints (see apps/server/migrations),
 * and the server validates every inbound value against them. Adding a value
 * here requires a matching migration.
 */

export const PRINCIPAL_KINDS = ['HUMAN', 'SERVICE', 'AI_WORKER'] as const;
export type PrincipalKind = (typeof PRINCIPAL_KINDS)[number];

export const PRINCIPAL_STATUSES = ['ACTIVE', 'DISABLED'] as const;
export type PrincipalStatus = (typeof PRINCIPAL_STATUSES)[number];

/** Platform-wide roles. Deliberately tiny: platform roles do not grant tenant data access. */
export const PLATFORM_ROLES = ['SYSTEM_OWNER'] as const;
export type PlatformRole = (typeof PLATFORM_ROLES)[number];

/** Tenant-scoped roles. Each maps to an explicit capability set on the server. */
export const TENANT_ROLES = [
  'TENANT_ADMIN',
  'SECURITY_ADMIN',
  'SECURITY_OPERATOR',
  'INTEGRATION_ADMIN',
  'AUDITOR',
  'READ_ONLY_ANALYST',
  'SERVICE',
  'AI_WORKER',
  'RECOVERY_AUTHORITY',
] as const;
export type TenantRole = (typeof TENANT_ROLES)[number];

export const TENANT_STATUSES = ['ACTIVE', 'SUSPENDED'] as const;
export type TenantStatus = (typeof TENANT_STATUSES)[number];

export const MEMBERSHIP_STATUSES = ['ACTIVE', 'SUSPENDED', 'REMOVED'] as const;
export type MembershipStatus = (typeof MEMBERSHIP_STATUSES)[number];

export const ASSET_TYPES = [
  'APPLICATION',
  'API',
  'REPOSITORY',
  'CLOUD_ACCOUNT',
  'HOST',
  'CONTAINER_WORKLOAD',
  'DATABASE',
  'DOMAIN',
  'NETWORK',
  'OTHER',
] as const;
export type AssetType = (typeof ASSET_TYPES)[number];

export const ENVIRONMENTS = ['PRODUCTION', 'STAGING', 'DEVELOPMENT', 'TEST'] as const;
export type Environment = (typeof ENVIRONMENTS)[number];

export const CRITICALITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;
export type Criticality = (typeof CRITICALITIES)[number];

export const ASSET_STATUSES = ['ACTIVE', 'INACTIVE', 'DECOMMISSIONED'] as const;
export type AssetStatus = (typeof ASSET_STATUSES)[number];

/**
 * Coverage of an asset by AEGIS security controls. Phase 1 has no coverage
 * computation, so every asset is UNKNOWN until Phase 2 implements it.
 */
export const COVERAGE_STATES = [
  'VERIFIED_WITHIN_DEFINED_SCOPE',
  'PARTIALLY_COVERED',
  'DEGRADED',
  'DISCONNECTED',
  'STALE',
  'VERIFICATION_REQUIRED',
  'UNKNOWN',
] as const;
export type CoverageState = (typeof COVERAGE_STATES)[number];

export const INTEGRATION_STATUSES = [
  'UNCONFIGURED',
  'CONFIGURED',
  'CONNECTING',
  'CONNECTED',
  'DEGRADED',
  'DISCONNECTED',
  'SUSPENDED',
  'REVOKED',
  'UNKNOWN',
] as const;
export type IntegrationStatus = (typeof INTEGRATION_STATUSES)[number];

/** Result of a single integration health check. */
export const HEALTH_CHECK_RESULTS = ['CONNECTED', 'DEGRADED', 'DISCONNECTED', 'UNKNOWN'] as const;
export type HealthCheckResult = (typeof HEALTH_CHECK_RESULTS)[number];

export const VERIFICATION_STATUSES = [
  'VERIFIED',
  'FAILED',
  'PARTIALLY_VERIFIED',
  'INCONCLUSIVE',
  'NOT_RUN',
  'BLOCKED',
  'STALE',
  'NOT_APPLICABLE',
] as const;
export type VerificationStatus = (typeof VERIFICATION_STATUSES)[number];

export const ACTION_STATUSES = [
  'PROPOSED',
  'PENDING_APPROVAL',
  'AUTHORIZED',
  'EXECUTING',
  'EXECUTED',
  'PARTIALLY_EXECUTED',
  'VERIFYING',
  'VERIFIED',
  'FAILED',
  'INCONCLUSIVE',
  'CANCELLED',
] as const;
export type ActionStatus = (typeof ACTION_STATUSES)[number];

export const AUDIT_OUTCOMES = ['SUCCESS', 'DENIED', 'FAILURE'] as const;
export type AuditOutcome = (typeof AUDIT_OUTCOMES)[number];

export const AUDIT_ACTOR_TYPES = ['HUMAN', 'SERVICE', 'AI_WORKER', 'SYSTEM', 'ANONYMOUS'] as const;
export type AuditActorType = (typeof AUDIT_ACTOR_TYPES)[number];

export const JOB_STATUSES = ['QUEUED', 'RUNNING', 'SUCCEEDED', 'FAILED', 'CANCELLED'] as const;
export type JobStatus = (typeof JOB_STATUSES)[number];

/**
 * Operational state of a platform component or product module.
 * "Unknown" and "foundation only" are first-class: they must never be
 * rendered as healthy.
 */
export const COMPONENT_STATES = [
  'OPERATIONAL',
  'DEGRADED',
  'UNAVAILABLE',
  'UNCONFIGURED',
  'UNSUPPORTED',
  'UNVERIFIED',
  'STALE',
  'FAILED',
  'FOUNDATION_ONLY',
  'NOT_IMPLEMENTED',
  'UNKNOWN',
] as const;
export type ComponentState = (typeof COMPONENT_STATES)[number];

/** Documentation classification used for every capability claim. */
export const IMPLEMENTATION_STATUSES = [
  'IMPLEMENTED_AND_VERIFIED',
  'IMPLEMENTED_NOT_FULLY_VERIFIED',
  'PARTIALLY_IMPLEMENTED',
  'INTERFACE_ONLY',
  'PLANNED',
  'UNSUPPORTED',
  'BLOCKED',
  'DEPRECATED',
] as const;
export type ImplementationStatus = (typeof IMPLEMENTATION_STATUSES)[number];
