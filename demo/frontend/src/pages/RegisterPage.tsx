import { useEffect, useState, type FormEvent, type JSX } from 'react';
import type { ZKPUser } from '@zkp-auth/react';
import type { ZkpClientError } from '@zkp-auth/client';
import { KeyIcon } from '../components/icons.js';
import { Spinner } from '../components/Spinner.js';

interface RegisterPageProps {
  readonly onSwitchToLogin: () => void;
  readonly onRegistered: () => void;
  /** `register(username, pin)` from useZKPAuth, passed down from App. */
  readonly register: (username: string, pin: string) => Promise<void>;
  readonly loading: boolean;
  readonly error: ZkpClientError | null;
  /** `user` from useZKPAuth — becomes non-null after successful registration. */
  readonly user: ZKPUser | null;
}

/**
 * Registration page.
 *
 * Generates a random Ed25519 keypair in the browser, encrypts the private key
 * with Argon2id + AES-256-GCM using the user's PIN, stores the encrypted blob
 * in IndexedDB, and posts only the public key to the server.
 *
 * The PIN is never transmitted — it only unlocks the local key store.
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
  const [pin, setPin] = useState('');
  const [confirmPin, setConfirmPin] = useState('');
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

    if (pin.length < 4) {
      setLocalError('PIN must be at least 4 characters');
      return;
    }
    if (pin !== confirmPin) {
      setLocalError('PINs do not match');
      return;
    }
    await register(username, pin);
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
            A random Ed25519 keypair is generated locally and encrypted with your PIN.
            <br />
            <span className="text-brand-400 font-medium">Your PIN never leaves this device.</span>
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
              <label htmlFor="register-pin" className="field-label">
                PIN
                <span className="ml-2 text-slate-500 font-normal text-xs">(unlocks your key on this device)</span>
              </label>
              <input
                id="register-pin"
                type="password"
                autoComplete="new-password"
                required
                placeholder="Choose a PIN — min 4 chars"
                value={pin}
                onChange={(e) => { setPin(e.target.value); }}
                className="input"
              />
            </div>

            <div>
              <label htmlFor="register-confirm-pin" className="field-label">Confirm PIN</label>
              <input
                id="register-confirm-pin"
                type="password"
                autoComplete="new-password"
                required
                placeholder="Repeat your PIN"
                value={confirmPin}
                onChange={(e) => { setConfirmPin(e.target.value); }}
                className="input"
              />
            </div>

            {displayError !== null && (
              <div role="alert" className="alert-error">{displayError}</div>
            )}

            {/* What happens callout */}
            <div className="rounded-lg bg-brand-950/50 border border-brand-800/40 p-3 text-xs text-slate-400 space-y-1">
              <p className="font-medium text-brand-300 mb-1.5">What happens when you register:</p>
              <ol className="list-decimal list-inside space-y-0.5 ml-0.5">
                <li>A random Ed25519 keypair is generated in your browser</li>
                <li>The private key is encrypted with Argon2id + AES-256-GCM using your PIN</li>
                <li>The encrypted blob is stored in IndexedDB on this device</li>
                <li>Only the 32-byte <strong className="text-slate-200">public key</strong> is sent to the server</li>
              </ol>
            </div>

            <button
              id="register-submit"
              type="submit"
              disabled={loading || username.trim() === '' || pin === ''}
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
          Schnorr Proof of Knowledge · Ed25519 · Argon2id · AES-256-GCM
        </p>
      </div>
    </div>
  );
}
