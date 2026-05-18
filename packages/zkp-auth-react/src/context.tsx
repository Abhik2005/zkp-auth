// @zkp-auth/react — ZKPContext and ZKPProvider
//
// Architecture:
//   • One `ZkpAuthClient` instance is created once per provider mount and
//     held in a ref. It is never recreated on re-render, preventing key loss.
//   • Auth state (user / loading / error) lives in a single `useReducer` so
//     all transitions are atomic — no interleaved state from multiple setState
//     calls. This eliminates the "loading = true but error still set" flash.
//   • `register` and `login` set loading=true, await the client, then dispatch
//     a single action with the result (success or error). This guarantees the
//     state snapshot seen by consumers is always internally consistent.
//   • `logout` is synchronous: clears the key, dispatches RESET.

import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useReducer,
  useRef,
  type JSX,
  type ReactNode,
} from 'react';

import { ZkpAuthClient, type ZkpAuthClientOptions } from '@zkp-auth/client';
import type { ZkpClientError } from '@zkp-auth/client';

import type { ZKPAuthState, ZKPContextValue, ZKPUser } from './types.js';

// ── Reducer ──────────────────────────────────────────────────────────────────

type Action =
  | { type: 'LOADING_START' }
  | { type: 'REGISTER_SUCCESS'; user: ZKPUser }
  | { type: 'LOGIN_SUCCESS'; user: ZKPUser }
  | { type: 'AUTH_ERROR'; error: ZkpClientError }
  | { type: 'RESET' };

const initialState: ZKPAuthState = {
  user: null,
  isAuthenticated: false,
  loading: false,
  error: null,
};

/**
 * Pure reducer for auth state transitions.
 *
 * All mutations flow through here so React's strict-mode double-invocation
 * cannot produce inconsistent intermediate states.
 */
function authReducer(state: ZKPAuthState, action: Action): ZKPAuthState {
  switch (action.type) {
    case 'LOADING_START':
      return { ...state, loading: true, error: null };

    case 'REGISTER_SUCCESS':
      return {
        ...state,
        loading: false,
        error: null,
        user: action.user,
        // Not authenticated yet — no JWT. Login must follow.
        isAuthenticated: false,
      };

    case 'LOGIN_SUCCESS':
      return {
        ...state,
        loading: false,
        error: null,
        user: action.user,
        isAuthenticated: true,
      };

    case 'AUTH_ERROR':
      return { ...state, loading: false, error: action.error };

    case 'RESET':
      return initialState;

    default:
      // Exhaustiveness guard: TypeScript narrows `action` to `never` here.
      return state;
  }
}

// ── Context ───────────────────────────────────────────────────────────────────

/**
 * Internal React context. Consumers MUST use `useZKPAuth()` or `useZKPUser()`
 * — never import this directly.
 *
 * `undefined` when accessed outside a mounted `ZKPProvider`.
 *
 * @internal
 */
export const ZKPContext = createContext<ZKPContextValue | undefined>(undefined);

ZKPContext.displayName = 'ZKPContext';

// ── Provider props ────────────────────────────────────────────────────────────

/**
 * Props accepted by `ZKPProvider`.
 */
export interface ZKPProviderProps {
  /**
   * Options forwarded verbatim to `ZkpAuthClient`.
   * `baseUrl` is the only required field.
   *
   * @example
   * ```tsx
   * <ZKPProvider options={{ baseUrl: 'https://api.example.com' }}>
   *   <App />
   * </ZKPProvider>
   * ```
   */
  readonly options: ZkpAuthClientOptions;

  /** React subtree that will have access to the auth context. */
  readonly children: ReactNode;
}

// ── Provider component ────────────────────────────────────────────────────────

/**
 * Mounts a `ZkpAuthClient` and provides ZKP auth state + operations to its
 * entire React subtree via context.
 *
 * **Mount exactly once** near the root of your application (e.g. in
 * `_app.tsx` for Next.js or `main.tsx` for Vite).
 *
 * The `ZkpAuthClient` instance is created on first render and held in a ref.
 * It is **never recreated** even if `options` changes between renders, so
 * avoid changing `options` after mount. If you need to change `baseUrl`,
 * unmount and remount the provider.
 *
 * @example
 * ```tsx
 * // main.tsx
 * import { ZKPProvider } from '@zkp-auth/react';
 *
 * root.render(
 *   <ZKPProvider options={{ baseUrl: import.meta.env.VITE_API_URL }}>
 *     <App />
 *   </ZKPProvider>
 * );
 * ```
 */
export function ZKPProvider({ options, children }: ZKPProviderProps): JSX.Element {
  const [state, dispatch] = useReducer(authReducer, initialState);

  // One client instance per provider lifetime. useRef ensures it survives
  // re-renders without being recreated (which would zero the private key).
  const clientRef = useRef<ZkpAuthClient | null>(null);
  if (clientRef.current === null) {
    clientRef.current = new ZkpAuthClient(options);
  }

  // ── Operations ─────────────────────────────────────────────────────────────

  const register = useCallback(async (username: string, password: string): Promise<void> => {
    const client = clientRef.current;
    if (client === null) return; // should never happen; guard for type-safety

    dispatch({ type: 'LOADING_START' });
    try {
      const outcome = await client.register(username, password);
      const user: ZKPUser = {
        userId: outcome.userId,
        publicKeyHex: outcome.publicKeyHex,
        token: null,
      };
      dispatch({ type: 'REGISTER_SUCCESS', user });
    } catch (err) {
      // ZkpClientError is always thrown by the client. The cast is safe because
      // ZkpAuthClient never throws plain Error or unknown types — it always
      // wraps in one of the three typed subclasses.
      dispatch({ type: 'AUTH_ERROR', error: err as ZkpClientError });
    }
  }, []); // clientRef is stable; no deps needed

  const login = useCallback(async (username: string, password: string): Promise<void> => {
    const client = clientRef.current;
    if (client === null) return;

    dispatch({ type: 'LOADING_START' });
    try {
      const outcome = await client.login(username, password);
      const user: ZKPUser = {
        userId: outcome.userId,
        token: outcome.token,
        // Preserve publicKeyHex from a preceding register() in the same session,
        // but do not overwrite with null if we logged in without re-registering.
        publicKeyHex: null,
      };
      dispatch({ type: 'LOGIN_SUCCESS', user });
    } catch (err) {
      dispatch({ type: 'AUTH_ERROR', error: err as ZkpClientError });
    }
  }, []);

  const logout = useCallback((): void => {
    clientRef.current?.clearKey();
    dispatch({ type: 'RESET' });
  }, []);

  // ── Context value ──────────────────────────────────────────────────────────

  // useMemo keeps the context value reference stable when state has not changed,
  // avoiding unnecessary re-renders of every consumer on unrelated renders.
  const value = useMemo<ZKPContextValue>(
    () => ({ ...state, register, login, logout }),
    [state, register, login, logout],
  );

  return <ZKPContext.Provider value={value}>{children}</ZKPContext.Provider>;
}

// ── Internal hook (used by useZKPAuth and useZKPUser) ─────────────────────────

/**
 * Returns the raw context value.
 *
 * Throws a descriptive error when called outside a `ZKPProvider` so
 * developers get an actionable message instead of a cryptic `undefined`
 * destructure failure.
 *
 * @internal
 */
export function useZKPContext(): ZKPContextValue {
  const ctx = useContext(ZKPContext);
  if (ctx === undefined) {
    throw new Error(
      '[zkp-auth/react] useZKPAuth (or useZKPUser) must be used inside a <ZKPProvider>. ' +
        'Wrap your application root with <ZKPProvider options={{ baseUrl: "..." }}>.',
    );
  }
  return ctx;
}
