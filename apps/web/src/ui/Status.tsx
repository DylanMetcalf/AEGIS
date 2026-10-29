import type { ComponentState } from '@aegis/shared';
import type { ReactNode } from 'react';

/**
 * Status labels pair a tone with a glyph and words, so state is never
 * conveyed by colour alone. Unknown and foundation-only states have their
 * own tones and are never rendered as healthy.
 */

type Tone = 'ok' | 'warn' | 'crit' | 'neutral' | 'info' | 'foundation';

const TONES: Record<string, { tone: Tone; icon: string; label?: string }> = {
  // Component states
  OPERATIONAL: { tone: 'ok', icon: '●', label: 'Operational' },
  DEGRADED: { tone: 'warn', icon: '▲', label: 'Degraded' },
  UNAVAILABLE: { tone: 'crit', icon: '■', label: 'Unavailable' },
  UNCONFIGURED: { tone: 'neutral', icon: '○', label: 'Not configured' },
  UNSUPPORTED: { tone: 'neutral', icon: '⊘', label: 'Unsupported' },
  UNVERIFIED: { tone: 'warn', icon: '?', label: 'Unverified' },
  STALE: { tone: 'warn', icon: '◷', label: 'Stale' },
  FAILED: { tone: 'crit', icon: '✕', label: 'Failed' },
  FOUNDATION_ONLY: { tone: 'foundation', icon: '◇', label: 'Foundation only' },
  NOT_IMPLEMENTED: { tone: 'neutral', icon: '◌', label: 'Not yet implemented' },
  UNKNOWN: { tone: 'neutral', icon: '?', label: 'Unknown' },
  // Integration states
  CONFIGURED: { tone: 'info', icon: '○', label: 'Configured, not checked' },
  CONNECTING: { tone: 'info', icon: '◔', label: 'Checking' },
  CONNECTED: { tone: 'ok', icon: '●', label: 'Connected' },
  DISCONNECTED: { tone: 'crit', icon: '■', label: 'Disconnected' },
  SUSPENDED: { tone: 'neutral', icon: '❚❚', label: 'Suspended' },
  REVOKED: { tone: 'neutral', icon: '⊘', label: 'Revoked' },
  // Asset / membership states
  ACTIVE: { tone: 'ok', icon: '●', label: 'Active' },
  INACTIVE: { tone: 'neutral', icon: '○', label: 'Inactive' },
  DECOMMISSIONED: { tone: 'neutral', icon: '⊘', label: 'Decommissioned' },
  REMOVED: { tone: 'neutral', icon: '⊘', label: 'Removed' },
  // Coverage
  VERIFIED_WITHIN_DEFINED_SCOPE: { tone: 'ok', icon: '●', label: 'Verified (in scope)' },
  PARTIALLY_COVERED: { tone: 'warn', icon: '◑', label: 'Partially covered' },
  VERIFICATION_REQUIRED: { tone: 'warn', icon: '?', label: 'Verification required' },
  // Audit / jobs
  SUCCESS: { tone: 'ok', icon: '✓', label: 'Success' },
  DENIED: { tone: 'warn', icon: '⊘', label: 'Denied' },
  FAILURE: { tone: 'crit', icon: '✕', label: 'Failure' },
  QUEUED: { tone: 'info', icon: '◷', label: 'Queued' },
  RUNNING: { tone: 'info', icon: '◔', label: 'Running' },
  SUCCEEDED: { tone: 'ok', icon: '✓', label: 'Succeeded' },
  CANCELLED: { tone: 'neutral', icon: '⊘', label: 'Cancelled' },
  // Criticality
  LOW: { tone: 'neutral', icon: '▁', label: 'Low' },
  MEDIUM: { tone: 'info', icon: '▃', label: 'Medium' },
  HIGH: { tone: 'warn', icon: '▅', label: 'High' },
  CRITICAL: { tone: 'crit', icon: '▇', label: 'Critical' },
  // Setup issue severities
  info: { tone: 'info', icon: 'i', label: 'Info' },
  warning: { tone: 'warn', icon: '▲', label: 'Warning' },
  critical: { tone: 'crit', icon: '■', label: 'Critical' },
};

export function statusLabel(state: string): string {
  return TONES[state]?.label ?? state.replace(/_/g, ' ').toLowerCase();
}

export function StatusBadge({ state, label }: { state: ComponentState | string; label?: string }) {
  const t = TONES[state] ?? { tone: 'neutral' as Tone, icon: '?' };
  return (
    <span className={`badge tone-${t.tone}`} data-state={state}>
      <span className="badge-icon" aria-hidden="true">
        {t.icon}
      </span>
      {label ?? statusLabel(state)}
    </span>
  );
}

export function Notice({
  tone,
  title,
  children,
}: {
  tone: Tone;
  title?: string;
  children: ReactNode;
}) {
  const role = tone === 'crit' ? 'alert' : 'status';
  return (
    <div className={`notice tone-${tone}`} role={role}>
      <div>
        {title && <strong>{title} </strong>}
        <span style={{ color: 'var(--color-text)' }}>{children}</span>
      </div>
    </div>
  );
}
