// @zkp-auth/react — public API surface
//
// Public surface:
//   Component : ZKPProvider
//   Hooks     : useZKPAuth, useZKPUser
//   Types     : ZKPProviderProps, ZKPUser, ZKPAuthState, ZKPContextValue,
//               ZKPAuthHookResult
//
// Error classes (ZkpClientError, ZkpCryptoError, ZkpNetworkError,
// ZkpServerError) and ClientErrorCode are NOT re-exported here.
// Import them directly from '@zkp-auth/client' when you need to narrow
// on error types — this keeps the dependency graph explicit and avoids
// consumers accidentally taking a transitive dependency on internals.

// ── Component ─────────────────────────────────────────────────────────────────

export { ZKPProvider } from './context.js';
export type { ZKPProviderProps } from './context.js';

// ── Hooks ─────────────────────────────────────────────────────────────────────

export { useZKPAuth } from './useZKPAuth.js';
export type { ZKPAuthHookResult } from './useZKPAuth.js';

export { useZKPUser } from './useZKPUser.js';

// ── Types ─────────────────────────────────────────────────────────────────────

export type {
  ZKPUser,
  ZKPAuthState,
  ZKPContextValue,
} from './types.js';
