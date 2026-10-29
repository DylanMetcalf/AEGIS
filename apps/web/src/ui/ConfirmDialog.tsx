import { useState } from 'react';
import { Button } from './Button';
import { TextField } from './Field';
import { Modal } from './Modal';

interface ConfirmProps {
  open: boolean;
  title: string;
  description: string;
  confirmLabel: string;
  /** When set, the user must type this text to enable the action. */
  typeToConfirm?: string;
  destructive?: boolean;
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

export function ConfirmDialog({
  open,
  title,
  description,
  confirmLabel,
  typeToConfirm,
  destructive,
  busy,
  onConfirm,
  onCancel,
}: ConfirmProps) {
  const [typed, setTyped] = useState('');
  const ready = !typeToConfirm || typed === typeToConfirm;
  const cancel = () => {
    setTyped('');
    onCancel();
  };
  return (
    <Modal
      open={open}
      title={title}
      onClose={cancel}
      footer={
        <>
          <Button variant="ghost" onClick={cancel}>
            Cancel
          </Button>
          <Button
            variant={destructive ? 'danger' : 'primary'}
            disabled={!ready}
            loading={busy}
            onClick={onConfirm}
          >
            {confirmLabel}
          </Button>
        </>
      }
    >
      <p className="muted">{description}</p>
      {typeToConfirm && (
        <TextField
          label={`Type “${typeToConfirm}” to confirm`}
          value={typed}
          onChange={(e) => setTyped(e.target.value)}
          autoComplete="off"
        />
      )}
    </Modal>
  );
}
