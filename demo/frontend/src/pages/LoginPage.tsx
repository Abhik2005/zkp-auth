import { useState, type FormEvent, type JSX } from 'react';
import type { ZkpClientError } from '@zkp-auth/client';
import { LockIcon } from '../components/icons.js';
import { Spinner } from '../components/Spinner.js';

interface LoginPageProps {
  readonly onSwitchToRegister: () => void;
  /** `login(username, pin)` from useZKPAuth, passed down from App. */
  readonly login: (username: string, pin: string) => Promise<void>;
  readonly loading: boolean;
  readonly error: ZkpClientError | null;
}

/**
 * Login page — accepts username + PIN and calls the ZKP `login()`.
 *
 * What happens:
 *   1. Loads the encrypted key blob from IndexedDB
 *   2. Decrypts the private key using Argon2id (PIN + stored salt) → AES-256-GCM
 *   3. Computes a Schnorr proof over the server-issued challenge
 *   4. Zeros the private key from memory (finally block)
 *   5. Server verifies the proof and sets an HttpOnly JWT cookie
 *
 * The PIN is never transmitted. The JWT is delivered as an HttpOnly cookie;
 * no token is stored in React state. App.tsx calls /api/me after login
 * to hydrate the session.
 */
export function LoginPage({ onSwitchToRegister, login, loading, error }: LoginPageProps): JSX.Element {
  const [username, setUsername] = useState('');
  const [pin, setPin] = useState('');

  async function handleSubmit(e: FormEvent<HTMLFormElement>): Promise<void> {
    e.preventDefault();
    await login(username, pin);
    // App.tsx watches isAuthenticated and calls /api/me when it flips.
  }

  const errorMessage = error !== null ? ((): string => {
    if (error.code === 'DECRYPTION_FAILED') return 'Wrong PIN — could not decrypt local key.';
    if (error.code === 'KEY_NOT_FOUND') return 'No key found for this username on this device. Register first.';
    if (error.code === 'PROOF_REJECTED' || error.code === 'CHALLENGE_FAILED') {
      return 'Server does not have a public key for this username. '
        + 'The demo backend is in-memory — it loses all registrations on restart. '
        + 'Please register again.';
    }
    return `${error.message} (${error.code})`;
  })() : null;

  return (
    <div className="min-h-screen flex items-center justify-center px-4 bg-gradient-to-br from-slate-950 via-slate-900 to-brand-950">
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute -top-40 -left-40 w-96 h-96 bg-brand-600/10 rounded-full blur-3xl" />
        <div className="absolute -bottom-40 -right-40 w-96 h-96 bg-brand-800/10 rounded-full blur-3xl" />
      </div>

      <div className="relative w-full max-w-md">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-brand-600/20 border border-brand-500/30 mb-4">
            <LockIcon className="w-8 h-8 text-brand-400" />
          </div>
          <h1 className="text-3xl font-bold text-white mb-2">Sign in</h1>
          <p className="text-slate-400 text-sm">
            Enter your PIN to unlock your local key and prove your identity.
            <br />
            <span className="text-brand-400 font-medium">No password is ever transmitted.</span>
          </p>
        </div>

        <div className="card">
          <form id="login-form" onSubmit={(e) => { void handleSubmit(e); }} className="space-y-5">
            <div>
              <label htmlFor="login-username" className="field-label">Username</label>
              <input
                id="login-username"
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
              <label htmlFor="login-pin" className="field-label">
                PIN
                <span className="ml-2 text-slate-500 font-normal text-xs">(decrypts your local key — never sent)</span>
              </label>
              <input
                id="login-pin"
                type="password"
                autoComplete="current-password"
                required
                placeholder="Your PIN"
                value={pin}
                onChange={(e) => { setPin(e.target.value); }}
                className="input"
              />
            </div>

            {errorMessage !== null && (
              <div role="alert" className="alert-error">
                <span className="font-medium">Authentication failed:</span>{' '}
                {errorMessage}
              </div>
            )}

            <button
              id="login-submit"
              type="submit"
              disabled={loading || username.trim() === '' || pin === ''}
              className="btn-primary flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <Spinner className="w-4 h-4" />
                  Proving identity…
                </>
              ) : (
                'Sign in with ZKP'
              )}
            </button>
          </form>

          <p className="text-center text-sm text-slate-500 mt-6">
            No account?{' '}
            <button id="go-to-register" type="button" onClick={onSwitchToRegister} className="btn-ghost">
              Create an account
            </button>
          </p>

          {/* In-memory store caveat */}
          <div className="mt-4 rounded-lg bg-amber-950/30 border border-amber-800/30 px-3 py-2 text-xs text-amber-400/80">
            <span className="font-semibold text-amber-300">Demo note:</span> the backend uses an in-memory store.
            Restarting the server clears all registrations — just register again if that happens.
          </div>
        </div>

        <p className="text-center text-xs text-slate-600 mt-6">
          Schnorr Proof of Knowledge · Ed25519 · Argon2id · AES-256-GCM
        </p>
      </div>
    </div>
  );
}
