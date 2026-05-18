import { useState, type FormEvent, type JSX } from 'react';
import type { ZkpClientError } from '@zkp-auth/client';
import { LockIcon } from '../components/icons.js';
import { Spinner } from '../components/Spinner.js';

interface LoginPageProps {
  readonly onSwitchToRegister: () => void;
  /** `login()` from useZKPAuth, passed down from App. */
  readonly login: (username: string, password: string) => Promise<void>;
  readonly loading: boolean;
  readonly error: ZkpClientError | null;
}

/**
 * Login page — accepts username + password and calls the ZKP `login()`.
 * The JWT is delivered by the server as an HttpOnly cookie; no token is
 * stored in React state. App.tsx calls /api/me after login to hydrate session.
 */
export function LoginPage({ onSwitchToRegister, login, loading, error }: LoginPageProps): JSX.Element {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  async function handleSubmit(e: FormEvent<HTMLFormElement>): Promise<void> {
    e.preventDefault();
    await login(username, password);
    // App.tsx watches isAuthenticated and calls /api/me when it flips.
  }

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
            Using Zero-Knowledge Proof — your password never leaves your device.
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
              <label htmlFor="login-password" className="field-label">Password</label>
              <input
                id="login-password"
                type="password"
                autoComplete="current-password"
                required
                placeholder="••••••••"
                value={password}
                onChange={(e) => { setPassword(e.target.value); }}
                className="input"
              />
            </div>

            {error !== null && (
              <div role="alert" className="alert-error">
                <span className="font-medium">Authentication failed:</span>{' '}
                {error.message}{' '}
                <span className="opacity-60">({error.code})</span>
              </div>
            )}

            <button
              id="login-submit"
              type="submit"
              disabled={loading || username.trim() === ''}
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
        </div>

        <p className="text-center text-xs text-slate-600 mt-6">
          Schnorr Proof of Knowledge · Ed25519 · Fiat-Shamir · SHA-512
        </p>
      </div>
    </div>
  );
}
