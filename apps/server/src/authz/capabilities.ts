import type { Criticality, Environment, PlatformRole, TenantRole } from '@aegis/shared';

/**
 * Capability catalogue. Every protected operation names exactly one
 * capability; roles map to explicit capability sets. Nothing is implied by
 * a role name, and no role is a superuser.
 */

export type Sensitivity = 'read' | 'write' | 'privileged';

export interface ResourceRef {
  type: string;
  tenantId: string | null;
  id?: string;
  environment?: Environment;
  criticality?: Criticality;
}

export interface CapabilityDef {
  scope: 'tenant' | 'platform';
  sensitivity: Sensitivity;
  /** Require a password re-entry within the reauthentication window. */
  requiresRecentAuth?: boolean | ((resource: ResourceRef | undefined) => boolean);
  /** Reserved for a later phase: defined for contracts, no endpoint uses it yet. */
  reserved?: boolean;
  description: string;
}

const productionOrCritical = (r: ResourceRef | undefined) =>
  r?.environment === 'PRODUCTION' || r?.criticality === 'CRITICAL';

export const CAPABILITIES = {
  'tenant.read': { scope: 'tenant', sensitivity: 'read', description: 'View tenant details' },
  'system.status.read': {
    scope: 'tenant',
    sensitivity: 'read',
    description: 'View platform component status',
  },
  'membership.read': { scope: 'tenant', sensitivity: 'read', description: 'List tenant members' },
  'membership.manage': {
    scope: 'tenant',
    sensitivity: 'privileged',
    requiresRecentAuth: true,
    description: 'Add members and change roles or status',
  },
  'asset.read': { scope: 'tenant', sensitivity: 'read', description: 'View assets' },
  'asset.create': { scope: 'tenant', sensitivity: 'write', description: 'Register assets' },
  'asset.update': { scope: 'tenant', sensitivity: 'write', description: 'Modify assets' },
  'asset.delete': {
    scope: 'tenant',
    sensitivity: 'write',
    requiresRecentAuth: productionOrCritical,
    description: 'Delete assets (production or critical assets require reauthentication)',
  },
  'integration.read': { scope: 'tenant', sensitivity: 'read', description: 'View integrations' },
  'integration.manage': {
    scope: 'tenant',
    sensitivity: 'privileged',
    description: 'Create, configure, suspend and resume integrations',
  },
  'integration.credential.manage': {
    scope: 'tenant',
    sensitivity: 'privileged',
    requiresRecentAuth: true,
    description: 'Set or change integration credential references',
  },
  'integration.revoke': {
    scope: 'tenant',
    sensitivity: 'privileged',
    requiresRecentAuth: true,
    description: 'Permanently revoke an integration',
  },
  'integration.health_check': {
    scope: 'tenant',
    sensitivity: 'write',
    description: 'Run integration connection checks',
  },
  'job.read': { scope: 'tenant', sensitivity: 'read', description: 'View background job status' },
  'audit.read': { scope: 'tenant', sensitivity: 'read', description: 'Read tenant audit events' },

  'platform.tenant.read': { scope: 'platform', sensitivity: 'read', description: 'List tenants' },
  'platform.tenant.manage': {
    scope: 'platform',
    sensitivity: 'privileged',
    requiresRecentAuth: true,
    description: 'Create tenants',
  },
  'platform.audit.read': {
    scope: 'platform',
    sensitivity: 'read',
    description: 'Read platform-level audit events',
  },
  'platform.audit.verify': {
    scope: 'platform',
    sensitivity: 'read',
    description: 'Verify the audit hash chain',
  },

  // Reserved for Phase 3 (defensive actions and recovery). No endpoint grants execution.
  'action.propose': {
    scope: 'tenant',
    sensitivity: 'write',
    reserved: true,
    description: 'Propose a defensive action',
  },
  'action.approve': {
    scope: 'tenant',
    sensitivity: 'privileged',
    requiresRecentAuth: true,
    reserved: true,
    description: 'Approve a defensive action',
  },
  'recovery.execute': {
    scope: 'tenant',
    sensitivity: 'privileged',
    requiresRecentAuth: true,
    reserved: true,
    description: 'Execute a recovery procedure',
  },
} as const satisfies Record<string, CapabilityDef>;

export type Capability = keyof typeof CAPABILITIES;

export function isCapability(value: string): value is Capability {
  return Object.prototype.hasOwnProperty.call(CAPABILITIES, value);
}

const READ_BASE: Capability[] = ['tenant.read', 'system.status.read'];

export const TENANT_ROLE_CAPABILITIES: Readonly<Record<TenantRole, readonly Capability[]>> = {
  TENANT_ADMIN: [
    ...READ_BASE,
    'membership.read',
    'membership.manage',
    'asset.read',
    'asset.create',
    'asset.update',
    'asset.delete',
    'integration.read',
    'integration.manage',
    'integration.credential.manage',
    'integration.revoke',
    'integration.health_check',
    'job.read',
    'audit.read',
  ],
  SECURITY_ADMIN: [
    ...READ_BASE,
    'membership.read',
    'asset.read',
    'asset.create',
    'asset.update',
    'asset.delete',
    'integration.read',
    'integration.health_check',
    'job.read',
    'audit.read',
    'action.approve',
  ],
  SECURITY_OPERATOR: [
    ...READ_BASE,
    'asset.read',
    'asset.create',
    'asset.update',
    'integration.read',
    'integration.health_check',
    'job.read',
    'action.propose',
  ],
  INTEGRATION_ADMIN: [
    ...READ_BASE,
    'asset.read',
    'integration.read',
    'integration.manage',
    'integration.credential.manage',
    'integration.revoke',
    'integration.health_check',
    'job.read',
  ],
  AUDITOR: [
    ...READ_BASE,
    'membership.read',
    'asset.read',
    'integration.read',
    'job.read',
    'audit.read',
  ],
  READ_ONLY_ANALYST: [...READ_BASE, 'asset.read', 'integration.read'],
  SERVICE: [
    'tenant.read',
    'asset.read',
    'integration.read',
    'integration.health_check',
    'job.read',
  ],
  AI_WORKER: ['tenant.read', 'asset.read', 'integration.read'],
  RECOVERY_AUTHORITY: ['tenant.read', 'recovery.execute'],
};

export const PLATFORM_ROLE_CAPABILITIES: Readonly<Record<PlatformRole, readonly Capability[]>> = {
  SYSTEM_OWNER: [
    'platform.tenant.read',
    'platform.tenant.manage',
    'platform.audit.read',
    'platform.audit.verify',
  ],
};
