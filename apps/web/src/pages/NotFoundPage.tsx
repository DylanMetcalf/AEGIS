import { Link } from 'react-router-dom';
import { EmptyState } from '../ui/States';

export function NotFoundPage() {
  return (
    <div className="page">
      <div className="card">
        <EmptyState title="Page not found" action={<Link to="/">Go to overview</Link>} />
      </div>
    </div>
  );
}
