/**
 * @zkp-auth/core — Public API surface
 *
 * Re-exports the four public functions of the Schnorr Proof of
 * Knowledge protocol on Ed25519 with Fiat-Shamir transform, plus
 * the typed-error classes and the `ErrorCode` discriminator type
 * callers pattern-match on.
 *
 * NOTHING else is exported. Helper modules (`encoding.ts`,
 * `transcript.ts`, `validate.ts`, `compare.ts`, `rng.ts`) and
 * test-only hooks (`__forTesting__`) are intentionally absent —
 * they are implementation details of the four public functions.
 *
 * See design.md "Components and Interfaces → index.ts" and
 * requirements.md Requirement 7.1.
 */

export { generateKeyPair } from './keypair.js';
export { generateChallenge } from './challenge.js';
export { computeProof } from './compute-proof.js';
export { verifyProof } from './verify-proof.js';
export { InvalidInputError, RandomnessError, CryptoError } from './errors.js';
export type { ErrorCode } from './errors.js';
