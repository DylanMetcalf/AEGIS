import { useState, type FormEvent } from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';
import { ApiError } from '../api/client';
import { useSession } from '../auth/SessionContext';
import { Button } from '../ui/Button';
import { TextField } from '../ui/Field';
import { Logo } from '../ui/Logo';
import { Notice } from '../ui/Status';

/**
 * Only plain in-app paths are accepted as a post-login destination, which
 * rules out open redirects such as //evil.example or /\evil.example.
 */
export function safeReturnPath(from: unknown): string {
  return typeof from === 'string' && /^\/(?![/\\])[A-Za-z0-9\-._~/]*$/.test(from) ? from : '/';
}

export function LoginPage() {
  const { login, status } = useSession();
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (status === 'authenticated') return <Navigate to="/" replace />;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(email, password);
      navigate(safeReturnPath((location.state as { from?: unknown } | null)?.from), {
        replace: true,
      });
    } catch (err) {
      setPassword('');
      setError(
        err instanceof ApiError
          ? err.code === 'RATE_LIMITED'
            ? 'Too many attempts. Wait a few minutes and try again.'
            : err.message
          : 'Sign-in failed',
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="auth-screen">
      <main className="card auth-card stack">
        <div className="brand">
          <Logo size={28} />
          AEGIS
        </div>
        <h1 className="visually-hidden">Sign in to AEGIS</h1>
        <p className="muted small" style={{ textAlign: 'center' }}>
          Sign in with your organization account.
        </p>
        {error && <Notice tone="crit">{error}</Notice>}
        <form onSubmit={submit} className="stack" noValidate>
          <TextField
            label="Email"
            type="email"
            autoComplete="username"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            autoFocus
          />
          <TextField
            label="Password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
          <Button type="submit" variant="primary" loading={busy} disabled={!email || !password}>
            Sign in
          </Button>
        </form>
        <p className="subtle small" style={{ textAlign: 'center' }}>
          Accounts are created by an administrator. There is no self-service sign-up.
        </p>
      </main>
    </div>
  );
}
