import { TENANT_ROLES } from '@aegis/shared';
import { describe, expect, it } from 'vitest';
import { authorize, effectiveCapabilities, type Actor } from '../src/authz/authorize.js';
import {
  CAPABILITIES,
  PLATFORM_ROLE_CAPABILITIES,
  TENANT_ROLE_CAPABILITIES,
  type Capability,
} from '../src/authz/capabilities.js';

const T1 = '11111111-1111-4111-8111-111111111111';
const T2 = '22222222-2222-4222-8222-222222222222';
const WINDOW = 10 * 60_000;

function actor(overrides: Partial<Actor> = {}): Actor {
  return {
    principalId: '33333333-3333-4333-8333-333333333333',
    kind: 'HUMAN',
    status: 'ACTIVE',
    platformRole: null,
    tenantId: T1,
    tenantStatus: 'ACTIVE',
    role: 'TENANT_ADMIN',
    membershipStatus: 'ACTIVE',
    sessionId: 's',
    reauthenticatedAt: new Date(),
    ...overrides,
  };
}

const check = (a: Actor | null, cap: string, extra: Partial<Parameters<typeof authorize>[2]> = {}) =>
  authorize(a, cap, { reauthWindowMs: WINDOW, ...extra });

describe('authorize', () => {
  it('denies when there is no actor or the capability is unknown', () => {
    expect(check(null, 'asset.read')).toEqual({ allowed: false, reason: 'NO_ACTOR' });
    expect(check(actor(), 'asset.obliterate')).toEqual({ allowed: false, reason: 'UNKNOWN_CAPABILITY' });
    expect(check(actor(), '__proto__')).toEqual({ allowed: false, reason: 'UNKNOWN_CAPABILITY' });
  });

  it('allows a granted capability in the active tenant', () => {
    expect(check(actor(), 'asset.create')).toEqual({ allowed: true });
  });

  it('denies capabilities the role does not grant', () => {
    expect(check(actor({ role: 'READ_ONLY_ANALYST' }), 'asset.create')).toEqual({
      allowed: false,
      reason: 'CAPABILITY_NOT_GRANTED',
    });
    expect(check(actor({ role: 'AUDITOR' }), 'integration.manage').allowed).toBe(false);
    expect(check(actor({ role: 'SECURITY_OPERATOR' }), 'asset.delete').allowed).toBe(false);
  });

  it('denies resources belonging to another tenant even when the role allows the action', () => {
    expect(check(actor(), 'asset.read', { resource: { type: 'asset', tenantId: T2, id: 'x' } })).toEqual({
      allowed: false,
      reason: 'TENANT_MISMATCH',
    });
  });

  it('denies without tenant context, membership, or with inactive state', () => {
    expect(check(actor({ tenantId: null }), 'asset.read').allowed).toBe(false);
    expect(check(actor({ role: null, membershipStatus: null }), 'asset.read')).toEqual({
      allowed: false,
      reason: 'NOT_A_MEMBER',
    });
    expect(check(actor({ membershipStatus: 'SUSPENDED' }), 'asset.read')).toEqual({
      allowed: false,
      reason: 'MEMBERSHIP_INACTIVE',
    });
    expect(check(actor({ tenantStatus: 'SUSPENDED' }), 'asset.read')).toEqual({
      allowed: false,
      reason: 'TENANT_INACTIVE',
    });
    expect(check(actor({ status: 'DISABLED' }), 'asset.read')).toEqual({
      allowed: false,
      reason: 'PRINCIPAL_INACTIVE',
    });
  });

  it('requires recent reauthentication for sensitive operations', () => {
    const stale = actor({ reauthenticatedAt: new Date(Date.now() - WINDOW - 1000) });
    expect(check(stale, 'membership.manage')).toEqual({ allowed: false, reason: 'REAUTH_REQUIRED' });
    expect(check(actor({ reauthenticatedAt: null }), 'integration.credential.manage').allowed).toBe(false);
    expect(check(actor({ reauthenticatedAt: new Date(Date.now() + 3600_000) }), 'membership.manage').allowed).toBe(
      false,
    );
    expect(check(actor(), 'membership.manage').allowed).toBe(true);
  });

  it('requires reauthentication to delete production or critical assets only', () => {
    const stale = actor({ reauthenticatedAt: null });
    const res = (environment: 'PRODUCTION' | 'STAGING', criticality: 'LOW' | 'CRITICAL') => ({
      resource: { type: 'asset', tenantId: T1, environment, criticality },
    });
    expect(check(stale, 'asset.delete', res('STAGING', 'LOW')).allowed).toBe(true);
    expect(check(stale, 'asset.delete', res('PRODUCTION', 'LOW'))).toEqual({ allowed: false, reason: 'REAUTH_REQUIRED' });
    expect(check(stale, 'asset.delete', res('STAGING', 'CRITICAL')).allowed).toBe(false);
  });

  it('keeps AI workers read-only regardless of role', () => {
    const ai = actor({ kind: 'AI_WORKER', role: 'AI_WORKER', reauthenticatedAt: null });
    expect(check(ai, 'asset.read').allowed).toBe(true);
    for (const cap of ['asset.create', 'asset.update', 'integration.health_check', 'action.propose']) {
      expect(check(ai, cap)).toEqual({ allowed: false, reason: 'ACTOR_TYPE_RESTRICTED' });
    }
    // Even if a database inconsistency gave an AI worker an admin role:
    const misassigned = actor({ kind: 'AI_WORKER', role: 'TENANT_ADMIN' });
    expect(check(misassigned, 'membership.manage')).toEqual({ allowed: false, reason: 'ACTOR_TYPE_RESTRICTED' });
    expect(check(misassigned, 'asset.delete')).toEqual({ allowed: false, reason: 'ACTOR_TYPE_RESTRICTED' });
  });

  it('never lets non-human identities perform privileged operations', () => {
    const svc = actor({ kind: 'SERVICE', role: 'TENANT_ADMIN' });
    expect(check(svc, 'integration.manage')).toEqual({ allowed: false, reason: 'ACTOR_TYPE_RESTRICTED' });
    expect(check(actor({ kind: 'SERVICE', role: 'SERVICE' }), 'integration.health_check').allowed).toBe(true);
  });

  it('gives the system owner platform capabilities but no tenant data access', () => {
    const owner = actor({ platformRole: 'SYSTEM_OWNER', tenantId: null, role: null, membershipStatus: null, tenantStatus: null });
    expect(check(owner, 'platform.tenant.manage').allowed).toBe(true);
    expect(check(owner, 'asset.read').allowed).toBe(false);
    expect(check(owner, 'audit.read').allowed).toBe(false);
    expect(check(owner, 'platform.audit.read', { resource: { type: 'audit', tenantId: T1 } })).toEqual({
      allowed: false,
      reason: 'TENANT_MISMATCH',
    });
    expect(check(actor(), 'platform.tenant.manage')).toEqual({ allowed: false, reason: 'CAPABILITY_NOT_GRANTED' });
  });

  it('is deterministic', () => {
    const a = actor({ role: 'SECURITY_OPERATOR' });
    const first = (Object.keys(CAPABILITIES) as Capability[]).map((c) => check(a, c, { now: new Date(0) }));
    const second = (Object.keys(CAPABILITIES) as Capability[]).map((c) => check(a, c, { now: new Date(0) }));
    expect(second).toEqual(first);
  });
});

describe('role catalogue', () => {
  it('defines a capability set for every tenant role and only known capabilities', () => {
    for (const role of TENANT_ROLES) {
      expect(TENANT_ROLE_CAPABILITIES[role]).toBeDefined();
      for (const cap of TENANT_ROLE_CAPABILITIES[role]) {
        expect(CAPABILITIES[cap].scope).toBe('tenant');
      }
    }
    for (const cap of PLATFORM_ROLE_CAPABILITIES.SYSTEM_OWNER) expect(CAPABILITIES[cap].scope).toBe('platform');
  });

  it('has no superuser role: no tenant role holds every tenant capability', () => {
    const tenantCaps = (Object.keys(CAPABILITIES) as Capability[]).filter((c) => CAPABILITIES[c].scope === 'tenant');
    for (const role of TENANT_ROLES) {
      expect(tenantCaps.every((c) => TENANT_ROLE_CAPABILITIES[role].includes(c)), role).toBe(false);
    }
  });

  it('grants reserved (future) capabilities only as declarations', () => {
    const reserved = (Object.keys(CAPABILITIES) as Capability[]).filter(
      (c) => (CAPABILITIES[c] as { reserved?: boolean }).reserved,
    );
    expect(reserved.sort()).toEqual(['action.approve', 'action.propose', 'recovery.execute']);
  });

  it('reports effective capabilities consistent with authorize()', () => {
    const caps = effectiveCapabilities(actor({ role: 'AUDITOR' }));
    expect(caps).toContain('audit.read');
    expect(caps).not.toContain('asset.create');
  });
});
