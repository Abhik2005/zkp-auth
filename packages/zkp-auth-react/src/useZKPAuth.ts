// @zkp-auth/react — useZKPAuth hook
//
// The primary hook for interacting with ZKP authentication.
//
// Returns the full `ZKPContextValue`: all read-only state fields and all
// mutable operations. Delegates every operation to the `ZkpAuthClient`
// instance held inside `ZKPProvider` — zero crypto logic lives here.
//
// Must be called inside a mounted `ZKPProvider`; throws a descriptive
// error otherwise (via `useZKPContext`).

import type { ZKPContextValue } from './types.js';
import { useZKPContext } from './context.js';

// ── Return type (re-exported for consumer convenience) ────────────────────────

/**
 * Return type of `useZKPAuth()`.
 *
 * Alias of `ZKPContextValue` — documented here so consumers can type
 * their own variables without importing from the internal types module.
 *
 * @example
 * ```ts
 * import { useZKPAuth, type ZKPAuthHookResult } from '@zkp-auth/react';
 *
 * function LoginPage() {
 *   const auth: ZKPAuthHookResult = useZKPAuth();
 *   // ...
 * }
 * ```
 */
export type ZKPAuthHookResult = ZKPContextValue;

// ── Hook ──────────────────────────────────────────────────────────────────────

/**
 * Primary hook for ZKP authentication.
 *
 * Returns the full auth context: state fields and async operations.
 * All operations delegate to `ZkpAuthClient` — this hook contains no
 * crypto logic.
 *
 * **Must be called inside a `<ZKPProvider>`.**
 *
 * ### State fields
 *
 * | Field             | Type                     | Description                                       |
 * |-------------------|--------------------------|---------------------------------------------------|
 * | `user`            | `ZKPUser \| null`        | Authenticated user, or `null`.                    |
 * | `isAuthenticated` | `boolean`                | `true` after a successful `login()`.              |
 * | `loading`         | `boolean`                | `true` while an async operation is in flight.     |
 * | `error`           | `ZkpClientError \| null` | Last error, or `null`. Narrow via `.code`.        |
 *
 * ### Operations
 *
 * | Operation      | Description                                                    |
 * |----------------|----------------------------------------------------------------|
 * | `register`     | Generate keypair + encrypt with PIN + POST `/auth/register`.  |
 * | `login`        | Decrypt key with PIN → compute proof → POST `/auth/verify`.   |
 * | `hasLocalKey`  | Check if an encrypted key exists in storage (no network).     |
 * | `logout`       | Reset auth state. Encrypted key stays in IndexedDB.           |
 *
 * @returns `ZKPAuthHookResult` — full context value.
 *
 * @throws `Error` when called outside a `<ZKPProvider>`.
 *
 * @example
 * ```tsx
 * import { useZKPAuth } from '@zkp-auth/react';
 *
 * function LoginForm() {
 *   const { login, loading, error, isAuthenticated } = useZKPAuth();
 *
 *   async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
 *     e.preventDefault();
 *     const form = new FormData(e.currentTarget);
 *     await login(
 *       form.get('username') as string,
 *       form.get('pin') as string,       // PIN never sent to server
 *     );
 *   }
 *
 *   if (isAuthenticated) return <p>Logged in!</p>;
 *
 *   return (
 *     <form onSubmit={handleSubmit}>
 *       <input name="username" />
 *       <input name="pin" type="password" />
 *       <button type="submit" disabled={loading}>
 *         {loading ? 'Authenticating…' : 'Log in'}
 *       </button>
 *       {error && <p role="alert">{error.message} ({error.code})</p>}
 *     </form>
 *   );
 * }
 * ```
 */
export function useZKPAuth(): ZKPAuthHookResult {
  return useZKPContext();
}
