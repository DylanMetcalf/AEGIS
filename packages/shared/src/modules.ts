import type { ComponentState } from './enums.js';

/**
 * The AEGIS product structure and the honest implementation state of each
 * area. The UI renders navigation from this list, and pages for modules that
 * are not OPERATIONAL show their status instead of pretending to work.
 *
 * Update this when a phase lands a module; it is asserted by tests.
 */
export interface ProductModule {
  key: string;
  label: string;
  path: string;
  group: 'operate' | 'defend' | 'assure' | 'govern';
  state: ComponentState;
  /** Phase in which the module's core capability is planned. */
  phase: 1 | 2 | 3 | 4 | 5;
  summary: string;
  /** What exists today, stated precisely. */
  currentCapability: string;
}

export const PRODUCT_MODULES: readonly ProductModule[] = [
  {
    key: 'overview',
    label: 'Overview',
    path: '/',
    group: 'operate',
    state: 'OPERATIONAL',
    phase: 1,
    summary: 'Platform, asset, and integration status from live backend data.',
    currentCapability:
      'Shows registered assets, integration status, recent audit activity, and setup gaps. No threat telemetry is collected yet.',
  },
  {
    key: 'world',
    label: 'Security World',
    path: '/world',
    group: 'operate',
    state: 'NOT_IMPLEMENTED',
    phase: 4,
    summary: 'Backend-connected spatial view of the defended estate.',
    currentCapability: 'Not implemented. Planned for Phase 4 once real security data exists.',
  },
  {
    key: 'assets',
    label: 'Assets',
    path: '/assets',
    group: 'operate',
    state: 'OPERATIONAL',
    phase: 1,
    summary: 'Registry of authorized, in-scope assets.',
    currentCapability:
      'Create, update, decommission, and delete assets with authorization scope, environment, and criticality.',
  },
  {
    key: 'findings',
    label: 'Findings',
    path: '/findings',
    group: 'defend',
    state: 'NOT_IMPLEMENTED',
    phase: 2,
    summary: 'Security findings with lifecycle and evidence.',
    currentCapability:
      'Not implemented. No detection engine exists, so the absence of findings says nothing about safety.',
  },
  {
    key: 'incidents',
    label: 'Incidents',
    path: '/incidents',
    group: 'defend',
    state: 'NOT_IMPLEMENTED',
    phase: 2,
    summary: 'Investigation workflows.',
    currentCapability: 'Not implemented. Planned for Phase 2.',
  },
  {
    key: 'integrations',
    label: 'Integrations',
    path: '/integrations',
    group: 'operate',
    state: 'OPERATIONAL',
    phase: 1,
    summary: 'External connections with declared capabilities and honest health.',
    currentCapability:
      'Registry with capability and permission declarations, credential references, real HTTPS endpoint probing, and a labelled test adapter.',
  },
  {
    key: 'agents',
    label: 'Agents',
    path: '/agents',
    group: 'assure',
    state: 'NOT_IMPLEMENTED',
    phase: 4,
    summary: 'Bounded AI workers.',
    currentCapability:
      'Not implemented. AI worker identities and resource-budget contracts exist; no agent runs.',
  },
  {
    key: 'evolution',
    label: 'Evolution',
    path: '/evolution',
    group: 'assure',
    state: 'NOT_IMPLEMENTED',
    phase: 4,
    summary: 'Controlled research and verified improvement.',
    currentCapability: 'Not implemented. Planned for Phase 4.',
  },
  {
    key: 'sentinel',
    label: 'SENTINEL',
    path: '/sentinel',
    group: 'assure',
    state: 'FOUNDATION_ONLY',
    phase: 3,
    summary: 'Independent supervision of AEGIS itself.',
    currentCapability:
      'Foundation only: observation and assurance contracts are defined. No independent supervision runs; SENTINEL currently shares every dependency with the main application.',
  },
  {
    key: 'verification',
    label: 'Verification',
    path: '/verification',
    group: 'assure',
    state: 'FOUNDATION_ONLY',
    phase: 3,
    summary: 'Independent verification of controls and actions.',
    currentCapability:
      'Foundation only: verification status model and aggregation rules exist. No verifier runs.',
  },
  {
    key: 'policy',
    label: 'Policy',
    path: '/policy',
    group: 'govern',
    state: 'FOUNDATION_ONLY',
    phase: 3,
    summary: 'Deterministic policy definitions and evaluation.',
    currentCapability: 'Foundation only: policy definition contract. No policy engine runs.',
  },
  {
    key: 'evidence',
    label: 'Evidence',
    path: '/evidence',
    group: 'govern',
    state: 'FOUNDATION_ONLY',
    phase: 2,
    summary: 'Evidence with provenance.',
    currentCapability:
      'Foundation only: evidence reference and provenance contract. The tamper-evident audit log is the only evidence source today.',
  },
  {
    key: 'coverage',
    label: 'Coverage',
    path: '/coverage',
    group: 'govern',
    state: 'NOT_IMPLEMENTED',
    phase: 2,
    summary: 'Computed security coverage per asset.',
    currentCapability: 'Not implemented. Every asset reports coverage UNKNOWN until Phase 2.',
  },
  {
    key: 'recovery',
    label: 'Recovery',
    path: '/recovery',
    group: 'govern',
    state: 'FOUNDATION_ONLY',
    phase: 3,
    summary: 'Recovery readiness and execution.',
    currentCapability:
      'Foundation only: recovery readiness contract. Readiness is reported UNVERIFIED.',
  },
  {
    key: 'audit',
    label: 'Audit Log',
    path: '/audit',
    group: 'govern',
    state: 'OPERATIONAL',
    phase: 1,
    summary: 'Hash-chained record of security and administrative events.',
    currentCapability:
      'Append-only, hash-chained audit events for authentication, authorization denials, and administrative changes.',
  },
  {
    key: 'reports',
    label: 'Reports',
    path: '/reports',
    group: 'govern',
    state: 'NOT_IMPLEMENTED',
    phase: 5,
    summary: 'Exportable assurance reports.',
    currentCapability: 'Not implemented.',
  },
  {
    key: 'settings',
    label: 'Settings',
    path: '/settings',
    group: 'govern',
    state: 'OPERATIONAL',
    phase: 1,
    summary: 'Account, sessions, and tenant membership.',
    currentCapability: 'Password change, session management, and tenant member administration.',
  },
];
