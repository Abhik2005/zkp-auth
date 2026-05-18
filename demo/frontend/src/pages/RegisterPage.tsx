import { useEffect, useState, type FormEvent, type JSX } from 'react';
import type { ZKPUser } from '@zkp-auth/react';
import type { ZkpClientError } from '@zkp-auth/client';
import { KeyIcon } from '../components/icons.js';
import { Spinner } from '../components/Spinner.js';

interface RegisterPageProps {
  readonly onSwitchToLogin: () => void;
  readonly onRegistered: () => void;
  /** `register()` from useZKPAuth, passed down from App. */
  readonly register: (username: string, password: string) => Promise<void>;
  readonly loading: boolean;
  readonly error: ZkpClientError | null;
  /** `user` from useZKPAuth — becomes non-null after successful registration. */
  readonly user: ZKPUser | null;
}

/**
 * Registration page.
 *
 * Generates an Ed25519 keypair in-browser, posts the public key to the server.
 * After success, `user` from the hook becomes non-null → `onRegistered()` fires
 * → App navigates to the login page.
 */
export function RegisterPage({
  onSwitchToLogin,
  onRegistered,
  register,
  loading,
  error,
  user,
}: RegisterPageProps): JSX.Element {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [localError, setLocalError] = useState<string | null>(null);

  // Navigate to login once registration succeeds (user becomes non-null).
  useEffect(() => {
    if (user !== null && error === null && !loading) {
      onRegistered();
    }
  }, [user, error, loading, onRegistered]);

  async function handleSubmit(e: FormEvent<HTMLFormElement>): Promise<void> {
    e.preventDefault();
    setLocalError(null);
    if (password !== confirmPassword) {
      setLocalError('Passwords do not match');
      return;
    }
    await register(username, password);
  }

  const displayError =
    localError !== null
      ? localError
      : error !== null
        ? `${error.message} (${error.code})`
        : null;

  return (
    <div className="min-h-screen flex items-center justify-center px-4 bg-gradient-to-br from-slate-950 via-slate-900 to-brand-950">
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute -top-40 -right-40 w-96 h-96 bg-brand-600/10 rounded-full blur-3xl" />
        <div className="absolute -bottom-40 -left-40 w-96 h-96 bg-brand-800/10 rounded-full blur-3xl" />
      </div>

      <div className="relative w-full max-w-md">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-brand-600/20 border border-brand-500/30 mb-4">
            <KeyIcon className="w-8 h-8 text-brand-400" />
          </div>
          <h1 className="text-3xl font-bold text-white mb-2">Create account</h1>
          <p className="text-slate-400 text-sm">
            An Ed25519 keypair is generated locally — your password is never transmitted.
          </p>
        </div>

        <div className="card">
          <form id="register-form" onSubmit={(e) => { void handleSubmit(e); }} className="space-y-5">
            <div>
              <label htmlFor="register-username" className="field-label">Username</label>
              <input
                id="register-username"
                type="text"
                autoComplete="username"
                autoFocus
                required
                placeholder="alice"
                value={username}
                onChange={(e) => { setUsername(e.target.value); }}
                className="input"
              />
            </div>

            <div>
              <label htmlFor="register-password" className="field-label">Password</label>
              <input
                id="register-password"
                type="password"
                autoComplete="new-password"
                required
                placeholder="••••••••"
                value={password}
                onChange={(e) => { setPassword(e.target.value); }}
                className="input"
              />
            </div>

            <div>
              <label htmlFor="register-confirm" className="field-label">Confirm password</label>
              <input
                id="register-confirm"
                type="password"
                autoComplete="new-password"
                required
                placeholder="••••••••"
                value={confirmPassword}
                onChange={(e) => { setConfirmPassword(e.target.value); }}
                className="input"
              />
            </div>

            {displayError !== null && (
              <div role="alert" className="alert-error">{displayError}</div>
            )}

            <button
              id="register-submit"
              type="submit"
              disabled={loading || username.trim() === '' || password === ''}
              className="btn-primary flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <Spinner className="w-4 h-4" />
                  Generating keypair…
                </>
              ) : (
                'Generate keypair & register'
              )}
            </button>
          </form>

          <p className="text-center text-sm text-slate-500 mt-6">
            Already registered?{' '}
            <button id="go-to-login" type="button" onClick={onSwitchToLogin} className="btn-ghost">
              Sign in
            </button>
          </p>
        </div>

        <p className="text-center text-xs text-slate-600 mt-6">
          Schnorr Proof of Knowledge · Ed25519 · Fiat-Shamir · SHA-512
        </p>
      </div>
    </div>
  );
}
