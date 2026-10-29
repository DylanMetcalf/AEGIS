import { describe, expect, it } from 'vitest';
import {
  ACTION_STATUSES,
  INTEGRATION_STATUSES,
  actionStateMachine,
  assetStateMachine,
  integrationStateMachine,
} from './index.js';
import { PRODUCT_MODULES } from './modules.js';
import { createAssetRequestSchema, createIntegrationRequestSchema } from './schemas.js';

describe('state machines', () => {
  it('covers every integration status', () => {
    for (const s of INTEGRATION_STATUSES) {
      expect(integrationStateMachine.transitions[s]).toBeDefined();
    }
  });

  it('never lets a configuration change land directly in CONNECTED', () => {
    expect(integrationStateMachine.canTransition('CONFIGURED', 'CONNECTED')).toBe(false);
    expect(integrationStateMachine.canTransition('UNCONFIGURED', 'CONNECTED')).toBe(false);
    expect(integrationStateMachine.canTransition('CONNECTING', 'CONNECTED')).toBe(true);
  });

  it('treats REVOKED and DECOMMISSIONED as terminal', () => {
    expect(integrationStateMachine.isTerminal('REVOKED')).toBe(true);
    expect(integrationStateMachine.canTransition('REVOKED', 'CONFIGURED')).toBe(false);
    expect(assetStateMachine.isTerminal('DECOMMISSIONED')).toBe(true);
    expect(assetStateMachine.canTransition('DECOMMISSIONED', 'ACTIVE')).toBe(false);
  });

  it('requires authorization before execution and verification after it', () => {
    for (const s of ACTION_STATUSES) {
      if (s !== 'AUTHORIZED') {
        expect(actionStateMachine.canTransition(s, 'EXECUTING')).toBe(false);
      }
    }
    expect(actionStateMachine.canTransition('EXECUTED', 'VERIFIED')).toBe(false);
    expect(actionStateMachine.canTransition('EXECUTED', 'VERIFYING')).toBe(true);
    expect(actionStateMachine.canTransition('PROPOSED', 'EXECUTED')).toBe(false);
  });

  it('rejects unknown states', () => {
    expect(integrationStateMachine.canTransition('CONFIGURED', 'HACKED' as never)).toBe(false);
    expect(integrationStateMachine.canTransition('NOPE' as never, 'CONFIGURED')).toBe(false);
  });
});

describe('product modules', () => {
  it('has unique keys and paths', () => {
    const keys = PRODUCT_MODULES.map((m) => m.key);
    const paths = PRODUCT_MODULES.map((m) => m.path);
    expect(new Set(keys).size).toBe(keys.length);
    expect(new Set(paths).size).toBe(paths.length);
  });

  it('only marks Phase 1 modules operational', () => {
    for (const m of PRODUCT_MODULES) {
      if (m.state === 'OPERATIONAL') expect(m.phase).toBe(1);
    }
    expect(PRODUCT_MODULES.find((m) => m.key === 'sentinel')?.state).toBe('FOUNDATION_ONLY');
  });
});

describe('request schemas', () => {
  const validAsset = {
    name: 'Payments API',
    assetType: 'API',
    environment: 'PRODUCTION',
    criticality: 'HIGH',
    authorizationScope: {
      statement: 'Owner authorizes monitoring of the payments API.',
      identifiers: ['api.example.com'],
      authorizedBy: 'Jane Owner',
      authorizedAt: '2026-01-01T00:00:00Z',
    },
  };

  it('accepts a valid asset', () => {
    expect(createAssetRequestSchema.safeParse(validAsset).success).toBe(true);
  });

  it('rejects smuggled tenantId and unknown enum values', () => {
    expect(createAssetRequestSchema.safeParse({ ...validAsset, tenantId: 'x' }).success).toBe(
      false,
    );
    expect(createAssetRequestSchema.safeParse({ ...validAsset, assetType: 'SPACESHIP' }).success).toBe(
      false,
    );
  });

  it('rejects control characters and oversized names', () => {
    expect(createAssetRequestSchema.safeParse({ ...validAsset, name: 'a\u0000b' }).success).toBe(
      false,
    );
    expect(createAssetRequestSchema.safeParse({ ...validAsset, name: 'x'.repeat(201) }).success).toBe(
      false,
    );
  });

  it('restricts credential references to the AEGIS_SECRET_ namespace', () => {
    const base = { provider: 'http.endpoint_probe', name: 'x', config: {} };
    expect(
      createIntegrationRequestSchema.safeParse({ ...base, credentialRef: 'env:AEGIS_SECRET_TOKEN' })
        .success,
    ).toBe(true);
    for (const bad of ['env:DATABASE_URL', 'env:SESSION_SECRET', 'file:/etc/passwd', 'AEGIS_SECRET_X']) {
      expect(createIntegrationRequestSchema.safeParse({ ...base, credentialRef: bad }).success).toBe(
        false,
      );
    }
  });
});
