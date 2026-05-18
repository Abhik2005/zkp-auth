// @zkp-auth/react — useZKPUser hook
//
// Read-only hook for consuming the current user anywhere inside ZKPProvider.
//
// Intentionally returns only `ZKPUser | null` — not the full context value.
// This is the right primitive for components that only need to know *who*
// is logged in (e.g. a navbar avatar, a protected route guard) without
// pulling in the mutable operations or causing re-renders on loading/error
// state changes they don't care about.
//
// NOTE: This hook still re-renders when `loading` or `error` changes because
// all state lives in one context. If surgical re-render isolation becomes
// a requirement, split the context into a state-context and an
// actions-context (a future optimisation, not needed now).

import type { ZKPUser } from './types.js';
import { useZKPContext } from './context.js';

// ── Hook ──────────────────────────────────────────────────────────────────────

/**
 * Read-only hook that returns the currently authenticated user.
 *
 * Returns `null` when no user is logged in. Components that only need the
 * user object (e.g. avatar, display name, protected-route guard) should
 * prefer this hook over `useZKPAuth()` — the narrower surface makes intent
 * explicit and the return type is simpler to work with.
 *
 * **Must be called inside a `<ZKPProvider>`.**
 *
 * ### Returned shape (`ZKPUser | null`)
 *
 * | Field          | Type             | Description                                       |
 * |----------------|------------------|---------------------------------------------------|
 * | `userId`       | `string`         | Username / user identifier.                       |
 * | `token`        | `string \| null` | Signed JWT. `null` until `login()` succeeds.      |
 * | `publicKeyHex` | `string \| null` | Ed25519 public key. Set only after `register()`.  |
 *
 * @returns The current `ZKPUser`, or `null` when unauthenticated.
 *
 * @throws `Error` when called outside a `<ZKPProvider>`.
 *
 * @example
 * ```tsx
 * import { useZKPUser } from '@zkp-auth/react';
 *
 * function Navbar() {
 *   const user = useZKPUser();
 *
 *   return (
 *     <nav>
 *       <span>{user ? `Hello, ${user.userId}` : 'Not logged in'}</span>
 *     </nav>
 *   );
 * }
 * ```
 *
 * @example Protected route guard
 * ```tsx
 * import { Navigate } from 'react-router-dom';
 * import { useZKPUser } from '@zkp-auth/react';
 *
 * function RequireAuth({ children }: { children: React.ReactNode }) {
 *   const user = useZKPUser();
 *   if (user === null) return <Navigate to="/login" replace />;
 *   return <>{children}</>;
 * }
 * ```
 */
export function useZKPUser(): ZKPUser | null {
  const { user } = useZKPContext();
  return user;
}
