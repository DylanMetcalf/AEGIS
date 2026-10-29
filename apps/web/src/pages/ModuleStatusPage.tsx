import type { ProductModule } from '@aegis/shared';
import { Link } from 'react-router-dom';
import { StatusBadge } from '../ui/Status';

const SENTINEL_SHARED = [
  ['Identity provider', 'SENTINEL would trust the same login system it is meant to supervise.'],
  ['Credentials', 'A compromised application credential would also silence SENTINEL.'],
  ['Database', 'An attacker able to rewrite the database could rewrite SENTINEL’s evidence.'],
  ['Administrators', 'The same people could disable both the system and its supervisor.'],
  ['Infrastructure', 'One outage or misconfiguration takes both down together.'],
];

/**
 * Honest page for modules that are not operational. It states what exists
 * and what does not; it never shows sample data.
 */
export function ModuleStatusPage({ module }: { module: ProductModule }) {
  return (
    <div className="page">
      <div className="page-header">
        <div className="titles">
          <span className="eyebrow">Phase {module.phase}</span>
          <h1>{module.label}</h1>
          <p className="muted">{module.summary}</p>
        </div>
        <StatusBadge state={module.state} />
      </div>
      <section className="card stack" aria-labelledby="cap-h">
        <h2 id="cap-h" style={{ fontSize: 'var(--text-base)' }}>
          What exists today
        </h2>
        <p>{module.currentCapability}</p>
        <p className="small muted">
          {module.state === 'FOUNDATION_ONLY'
            ? 'Foundation only: the data contracts this module will use are defined and tested, but nothing operates yet. No status or results are shown because none exist.'
            : `Awaiting Phase ${module.phase} implementation. This section contains no functioning security capability yet.`}
        </p>
      </section>
      {module.key === 'sentinel' && (
        <section className="card stack" aria-labelledby="indep-h">
          <h2 id="indep-h" style={{ fontSize: 'var(--text-base)' }}>
            Independence gaps that remain
          </h2>
          <p className="small muted">
            Supervision is only meaningful if the supervisor fails independently. Today SENTINEL
            would share all of these with AEGIS:
          </p>
          <table className="table">
            <caption className="visually-hidden">
              Dependencies SENTINEL currently shares with the main application
            </caption>
            <thead>
              <tr>
                <th scope="col">Shared dependency</th>
                <th scope="col">Common-mode failure</th>
              </tr>
            </thead>
            <tbody>
              {SENTINEL_SHARED.map(([dep, why]) => (
                <tr key={dep}>
                  <td>{dep}</td>
                  <td className="small muted">{why}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
      <p className="small">
        <Link to="/">Back to overview</Link>
      </p>
    </div>
  );
}
