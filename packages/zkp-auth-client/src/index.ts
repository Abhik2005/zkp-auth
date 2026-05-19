// @zkp-auth/client — public API surface
//
// Only the developer-facing symbols are exported here. The internal modules
// (crypto.ts, http.ts) are implementation details and are NOT re-exported —
// their APIs may change without a semver bump.
//
// Public surface:
//   Classes  : ZkpAuthClient, IndexedDBKeyStorage, MemoryKeyStorage
//   Interface: KeyStorage
//   Types    : ZkpAuthClientOptions, RegisterOutcome, LoginOutcome
//   Errors   : ZkpClientError, ZkpCryptoError, ZkpNetworkError,
//              ZkpServerError, ZkpStorageError
//   Error type: ClientErrorCode

// ── Client class and its option/result types ──────────────────────────────
export { ZkpAuthClient } from './client.js';
export type {
  ZkpAuthClientOptions,
  RegisterOutcome,
  LoginOutcome,
} from './client.js';

// ── Key storage interface and implementations ─────────────────────────────
export { IndexedDBKeyStorage, MemoryKeyStorage } from './key-storage.js';
export type { KeyStorage } from './key-storage.js';

// ── Error classes and the stable code union ───────────────────────────────
export {
  ZkpClientError,
  ZkpCryptoError,
  ZkpNetworkError,
  ZkpServerError,
  ZkpStorageError,
} from './errors.js';
export type { ClientErrorCode } from './errors.js';