import { useState, type FormEvent } from 'react';
import { api, ApiError } from '../api/client';
import { Button } from '../ui/Button';
import { Modal } from '../ui/Modal';
import { TextField } from '../ui/Field';

/** Password confirmation for sensitive operations ("sudo mode"). */
export function ReauthDialog({ open, onDone }: { open: boolean; onDone: (ok: boolean) => void }) {
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api('/api/auth/reauthenticate', { method: 'POST', body: { password }, retried: true });
      setPassword('');
      onDone(true);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not confirm your password');
    } finally {
      setBusy(false);
    }
  };

  const cancel = () => {
    setPassword('');
    setError(null);
    onDone(false);
  };

  return (
    <Modal open={open} title="Confirm it’s you" onClose={cancel}>
      <form onSubmit={submit} className="stack" noValidate>
        <p className="muted small">
          This action is sensitive. Re-enter your password to continue. Confirmation lasts a few
          minutes.
        </p>
        <TextField
          label="Password"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          error={error}
          required
          autoFocus
        />
        <div className="form-actions">
          <Button type="button" variant="ghost" onClick={cancel}>
            Cancel
          </Button>
          <Button type="submit" variant="primary" loading={busy} disabled={!password}>
            Confirm
          </Button>
        </div>
      </form>
    </Modal>
  );
}
