import { type JSX } from 'react';
import { ShieldCheckIcon, KeyIcon } from '../components/icons.js';

interface DashboardPageProps {
  /** Authenticated user from /api/me (cookie-based session). */
  readonly userId: string;
  /** Unix timestamp (seconds) when the session cookie expires. */
  readonly expiresAt: number;
  readonly onLogout: () => void;
}

/**
 * Dashboard shown after successful ZKP authentication.
 *
 * The JWT is intentionally NOT displayed — it lives in the HttpOnly cookie
 * and is inaccessible to JavaScript. What we show instead:
 *   - Authenticated username (from /api/me)
 *   - Session expiry (decoded from /api/me response, not from the token)
 *   - Step-by-step explanation of the ZKP + cookie auth flow
 *   - Logout button (calls POST /api/logout to clear the cookie)
 */
export function DashboardPage({ userId, expiresAt, onLogout }: DashboardPageProps): JSX.Element {
  function unixToLocal(unixSec: number): string {
    return new Date(unixSec * 1000).toLocaleString();
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-brand-950 px-4 py-12">
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[600px] h-64 bg-brand-600/10 rounded-full blur-3xl" />
      </div>

      <div className="relative max-w-2xl mx-auto space-y-6">
        {/* ── Page header ── */}
        <div className="text-center mb-10">
          <div className="inline-flex items-center justify-center w-20 h-20 rounded-3xl bg-emerald-600/20 border border-emerald-500/30 mb-4 shadow-lg shadow-emerald-900/30">
            <ShieldCheckIcon className="w-10 h-10 text-emerald-400" />
          </div>
          <h1 className="text-4xl font-bold text-white mb-2">Authenticated!</h1>
          <p className="text-slate-400">
            You proved knowledge of your private key without revealing it.
          </p>
        </div>

        {/* ── Identity card ── */}
        <div className="card">
          <div className="flex items-start justify-between mb-6">
            <div>
              <p className="text-xs font-medium text-slate-500 uppercase tracking-widest mb-1">
                Signed in as
              </p>
              <p id="dashboard-username" className="text-2xl font-bold text-white">{userId}</p>
            </div>
            <span className="badge-success">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              ZKP auth working
            </span>
          </div>

          {/* Session info from /api/me */}
          <dl className="grid grid-cols-2 gap-4 pt-4 border-t border-slate-800">
            <div>
              <dt className="field-label mb-1">Session expires</dt>
              <dd id="session-expiry" className="text-white font-medium text-sm">
                {unixToLocal(expiresAt)}
              </dd>
            </div>
            <div>
              <dt className="field-label mb-1">JWT location</dt>
              <dd className="text-emerald-400 font-medium text-sm flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                HttpOnly cookie (not in JS)
              </dd>
            </div>
          </dl>
        </div>

        {/* ── Security callout ── */}
        <div className="card border-emerald-800/30 bg-emerald-950/20">
          <div className="flex gap-3 items-start">
            <KeyIcon className="w-5 h-5 text-emerald-400 flex-shrink-0 mt-0.5" />
            <div>
              <p className="text-emerald-300 font-semibold text-sm mb-1">
                JWT is inaccessible to JavaScript
              </p>
              <p className="text-slate-400 text-sm leading-relaxed">
                The session token lives in an <span className="text-slate-200 font-mono text-xs">HttpOnly; SameSite=Strict</span> cookie.
                No JavaScript on this page — or any third-party script — can read it.
                It is sent automatically by the browser on every request to this origin,
                and survives full page refreshes.
              </p>
            </div>
          </div>
        </div>

        {/* ── How ZKP auth works ── */}
        <div className="card border-brand-800/50">
          <h2 className="text-sm font-semibold text-slate-300 mb-4">
            How this auth flow worked
          </h2>
          <ol className="space-y-3 text-sm text-slate-400">
            {([
              ['Register', 'Browser generated an Ed25519 keypair. Public key sent to server. Private key stored in JS memory.'],
              ['Challenge', 'Server issued a random 32-byte nonce, bound to your userId.'],
              ['Prove', 'Browser computed a Schnorr proof: R = k·G, c = SHA-512(R‖pubKey‖nonce), s = k − c·privKey.'],
              ['Verify', 'Server checked the proof using the public key — your password was never transmitted.'],
              ['Cookie', 'Server signed a JWT and returned it as an HttpOnly cookie. JS cannot read it.'],
              ['Hydrate', 'On every page load, GET /api/me reads the cookie server-side and restores your session.'],
            ] as const).map(([step, desc], i) => (
              <li key={step} className="flex gap-3">
                <span className="flex-shrink-0 w-6 h-6 rounded-full bg-brand-700/40 border border-brand-600/30 text-brand-400 text-xs flex items-center justify-center font-bold">
                  {i + 1}
                </span>
                <span>
                  <span className="text-slate-200 font-medium">{step}:</span>{' '}
                  {desc}
                </span>
              </li>
            ))}
          </ol>
        </div>

        {/* ── Logout ── */}
        <div className="text-center">
          <button
            id="logout-button"
            type="button"
            onClick={onLogout}
            className="text-slate-400 hover:text-red-400 text-sm font-medium transition-colors px-4 py-2 rounded-lg hover:bg-red-950/30"
          >
            Sign out — clear cookie &amp; private key
          </button>
        </div>
      </div>
    </div>
  );
}
