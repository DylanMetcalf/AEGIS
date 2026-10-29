import {
  useId,
  type InputHTMLAttributes,
  type ReactNode,
  type SelectHTMLAttributes,
  type TextareaHTMLAttributes,
} from 'react';

interface FieldShellProps {
  id: string;
  label: string;
  hint?: ReactNode;
  error?: string | null;
  required?: boolean;
  children: ReactNode;
}

function FieldShell({ id, label, hint, error, required, children }: FieldShellProps) {
  return (
    <div className="field">
      <label htmlFor={id}>
        {label}
        {required && (
          <span aria-hidden="true" className="subtle">
            {' '}
            *
          </span>
        )}
      </label>
      {children}
      {hint && !error && (
        <span id={`${id}-hint`} className="hint">
          {hint}
        </span>
      )}
      {error && (
        <span id={`${id}-error`} className="error" role="alert">
          <span aria-hidden="true">✕</span> {error}
        </span>
      )}
    </div>
  );
}

function describedBy(id: string, hint: unknown, error: unknown) {
  return error ? `${id}-error` : hint ? `${id}-hint` : undefined;
}

type Common = { label: string; hint?: ReactNode; error?: string | null };

export function TextField({
  label,
  hint,
  error,
  id,
  ...rest
}: Common & InputHTMLAttributes<HTMLInputElement>) {
  const generated = useId();
  const fid = id ?? generated;
  return (
    <FieldShell id={fid} label={label} hint={hint} error={error} required={rest.required}>
      <input
        {...rest}
        id={fid}
        className="input"
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy(fid, hint, error)}
      />
    </FieldShell>
  );
}

export function TextAreaField({
  label,
  hint,
  error,
  id,
  ...rest
}: Common & TextareaHTMLAttributes<HTMLTextAreaElement>) {
  const generated = useId();
  const fid = id ?? generated;
  return (
    <FieldShell id={fid} label={label} hint={hint} error={error} required={rest.required}>
      <textarea
        {...rest}
        id={fid}
        className="textarea"
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy(fid, hint, error)}
      />
    </FieldShell>
  );
}

export function SelectField({
  label,
  hint,
  error,
  id,
  options,
  ...rest
}: Common &
  SelectHTMLAttributes<HTMLSelectElement> & {
    options: readonly { value: string; label: string }[];
  }) {
  const generated = useId();
  const fid = id ?? generated;
  return (
    <FieldShell id={fid} label={label} hint={hint} error={error} required={rest.required}>
      <select
        {...rest}
        id={fid}
        className="select"
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy(fid, hint, error)}
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </FieldShell>
  );
}
