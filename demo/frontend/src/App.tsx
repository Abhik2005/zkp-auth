import { useState, useEffect, useCallback, type JSX } from 'react';
import { useZKPAuth } from '@zkp-auth/react';
import { LoginPage } from './pages/LoginPage.js';
import { RegisterPage } from './pages/RegisterPage.js';
import { DashboardPage } from './pages/DashboardPage.js';

// ---------------------------------------------------------------------------
// Session types
// ---------------------------------------------------------------------------

export interface SessionUser {
  readonly userId: string;
  readonly expiresAt: number; // Unix timestamp (seconds)
}

type SessionStatus = 'checking' | 'authenticated' | 'unauthenticated';

interface Session {
  readonly status: SessionStatus;
  readonly user: SessionUser | null;
}

/** Pages shown while unauthenticated. */
type UnauthView = 'login' | 'register';

// ---------------------------------------------------------------------------
// /api/me helper — reads the HttpOnly cookie server-side, returns user info
// ---------------------------------------------------------------------------

/**
 * Calls GET /api/me with credentials so the browser sends the HttpOnly cookie.
 * Returns the user object on success, or `null` on 401/error.
 */
async function fetchMe(): Promise<SessionUser | null> {
  try {
    const res = await fetch('/api/me', { credentials: 'include' });
    if (!res.ok) return null;
    const data = (await res.json()) as { userId: string; expiresAt: number };
    return { userId: data.userId, expiresAt: data.expiresAt };
  } catch {
    return null;
  }
}

/**
 * Calls POST /api/logout to clear the HttpOnly cookie server-side.
 */
async function postLogout(): Promise<void> {
  try {
    await fetch('/api/logout', { method: 'POST', credentials: 'include' });
  } catch {
    // Best-effort; proceed with local state clear regardless.
  }
}

// ---------------------------------------------------------------------------
// Root App
// ---------------------------------------------------------------------------

/**
 * Root application component.
 *
 * Session management strategy:
 *   - Auth truth lives in the HttpOnly cookie (server-side).
 *   - On mount, GET /api/me is called to hydrate the session.
 *   - After ZKP login() completes (hook isAuthenticated flips), /api/me
 *     is called again to obtain the userId and expiresAt from the cookie.
 *   - Logout clears the cookie via POST /api/logout then resets local state.
 *   - The JWT is never stored in React state, localStorage, or any JS variable.
 */
export function App(): JSX.Element {
  const { isAuthenticated, login, register, logout: zkpLogout, loading: zkpLoading, error: zkpError, user: zkpUser } = useZKPAuth();

  const [session, setSession] = useState<Session>({ status: 'checking', user: null });
  const [view, setView] = useState<UnauthView>('login');

  // ── On mount: hydrate session from cookie ────────────────────────────────

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const me = await fetchMe();
      if (!cancelled) {
        setSession(me !== null
          ? { status: 'authenticated', user: me }
          : { status: 'unauthenticated', user: null },
        );
      }
    })();
    return () => { cancelled = true; };
  }, []);

  // ── After ZKP login() succeeds, hydrate session from the new cookie ──────

  useEffect(() => {
    if (!isAuthenticated) return;
    void (async () => {
      const me = await fetchMe();
      if (me !== null) {
        setSession({ status: 'authenticated', user: me });
      }
    })();
  }, [isAuthenticated]);

  // ── After ZKP register() succeeds, navigate to login ────────────────────

  useEffect(() => {
    // zkpUser becomes non-null after register(); at that point no cookie is
    // set yet (registration doesn't log in), so just redirect to login page.
    if (zkpUser !== null && !isAuthenticated) {
      setView('login');
    }
  }, [zkpUser, isAuthenticated]);

  // ── Logout ───────────────────────────────────────────────────────────────

  const handleLogout = useCallback(async () => {
    await postLogout();       // clear the HttpOnly cookie
    zkpLogout();              // zero private key from ZkpAuthClient memory
    setSession({ status: 'unauthenticated', user: null });
  }, [zkpLogout]);

  // ── Render ───────────────────────────────────────────────────────────────

  // Show a neutral loading screen while /api/me is in flight on mount.
  if (session.status === 'checking') {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-950">
        <div className="flex flex-col items-center gap-4">
          <div className="w-10 h-10 border-2 border-brand-500 border-t-transparent rounded-full animate-spin" />
          <p className="text-slate-400 text-sm">Restoring session…</p>
        </div>
      </div>
    );
  }

  if (session.status === 'authenticated' && session.user !== null) {
    return (
      <DashboardPage
        userId={session.user.userId}
        expiresAt={session.user.expiresAt}
        onLogout={() => { void handleLogout(); }}
      />
    );
  }

  if (view === 'register') {
    return (
      <RegisterPage
        onSwitchToLogin={() => { setView('login'); }}
        onRegistered={() => { setView('login'); }}
        register={register}
        loading={zkpLoading}
        error={zkpError}
        user={zkpUser}
      />
    );
  }

  return (
    <LoginPage
      onSwitchToRegister={() => { setView('register'); }}
      login={login}
      loading={zkpLoading}
      error={zkpError}
    />
  );
}
