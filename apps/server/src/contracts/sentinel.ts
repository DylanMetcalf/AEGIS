import type { ComponentState } from '@aegis/shared';

/**
 * SENTINEL contract. STATUS: INTERFACE_ONLY (FOUNDATION_ONLY in the UI).
 *
 * SENTINEL is meant to supervise AEGIS independently. In Phase 1 nothing
 * runs; these types fix the observation format so that the main application
 * can expose data SENTINEL will later consume, and so the independence
 * requirements are explicit and reviewable.
 */

export type SentinelObservationKind =
  | 'HEALTH'
  | 'POLICY_EVALUATION'
  | 'COVERAGE'
  | 'EVIDENCE_FRESHNESS'
  | 'CONFIG_INTEGRITY'
  | 'INTEGRATION_PERMISSION_DRIFT'
  | 'RESTRICTED_ACTION_REQUEST'
  | 'INDEPENDENT_VERIFICATION'
  | 'RECOVERY_READINESS';

export interface SentinelObservation {
  id: string;
  kind: SentinelObservationKind;
  subject: { type: string; id: string; tenantId: string | null };
  state: ComponentState;
  observedAt: string;
  /** Observations older than this must be treated as STALE. */
  validUntil: string;
  observer: { id: string; independentOfMainApp: boolean };
  evidenceIds: string[];
}

export interface AssuranceFinding {
  id: string;
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  observationIds: string[];
  summary: string;
  raisedAt: string;
}

/**
 * Independence requirements for future SENTINEL functions. Each entry lists
 * what must be separate from the main application for the function to be
 * meaningful. `currentlyShared` lists what Phase 1 still shares.
 */
export const SENTINEL_INDEPENDENCE: readonly {
  fn: SentinelObservationKind;
  requires: (
    | 'process'
    | 'credential'
    | 'storage'
    | 'account'
    | 'administrator'
    | 'external_logging'
    | 'deployment'
  )[];
  currentlyShared: string[];
}[] = [
  {
    fn: 'HEALTH',
    requires: ['process', 'deployment'],
    currentlyShared: ['process', 'database', 'deployment'],
  },
  {
    fn: 'CONFIG_INTEGRITY',
    requires: ['process', 'credential', 'storage'],
    currentlyShared: ['database', 'credentials'],
  },
  {
    fn: 'INTEGRATION_PERMISSION_DRIFT',
    requires: ['credential', 'process'],
    currentlyShared: ['integration credentials'],
  },
  {
    fn: 'RESTRICTED_ACTION_REQUEST',
    requires: ['process', 'credential', 'administrator'],
    currentlyShared: ['identity provider', 'administrators'],
  },
  {
    fn: 'INDEPENDENT_VERIFICATION',
    requires: ['process', 'credential', 'storage', 'account'],
    currentlyShared: ['everything'],
  },
  {
    fn: 'EVIDENCE_FRESHNESS',
    requires: ['storage', 'external_logging'],
    currentlyShared: ['database'],
  },
  {
    fn: 'RECOVERY_READINESS',
    requires: ['account', 'administrator', 'storage', 'deployment'],
    currentlyShared: ['everything'],
  },
];
