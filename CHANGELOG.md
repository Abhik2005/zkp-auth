# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.0] — 2026-05-19 — Passwordless architecture

This release eliminates the PBKDF2 password-oracle vulnerability and ships the `KeyStorage` abstraction that makes WebAuthn a drop-in future upgrade.

### `@zkp-auth/client` — Breaking changes

**Removed**
- `browserDeriveKeyPair(username, password)` — deterministic PBKDF2 key derivation removed entirely
- `encodePassword(password)` — encoding helper removed
- `PBKDF2_DOMAIN` / `PBKDF2_ITERATIONS` constants removed
- `register(username, password)` and `login(username, password)` password-based signatures removed

**Added**
- `register(username, pin)` — generates a cryptographically random Ed25519 keypair; encrypts the private key with `Argon2id + AES-256-GCM` (64 MB memory, 3 passes, 1 lane) using `pin` as the passphrase; stores the encrypted blob in IndexedDB; registers the public key with the server. PIN is never transmitted.
- `login(username, pin)` — decrypts the stored key using `pin`; computes a Schnorr proof; zeroes the private key in a `finally` block.
- `hasLocalKey(userId): Promise<boolean>` — check if an encrypted key exists for `userId` without a network call (use this to route users to register vs. login UI)
- `exportKeyBlob(userId, pin): Promise<string>` — export the encrypted key as a JSON blob for device transfer
- `importKeyBlob(userId, blob, pin): Promise<void>` — import a blob (verifies PIN before writing to storage)
- `KeyStorage` interface — pluggable storage abstraction (`generateAndStore`, `unlock`, `hasKey`, `exportBlob`, `importBlob`, `deleteKey`)
- `IndexedDBKeyStorage` — production default; persists encrypted key records in IndexedDB
- `MemoryKeyStorage` — in-process implementation for tests and Electron; no IndexedDB required
- `ZkpStorageError` class with codes: `KEY_NOT_FOUND`, `STORAGE_ERROR`
- `ZkpCryptoError` code `INVALID_PIN` — thrown when an empty PIN is passed
- `ZkpCryptoError` code `DECRYPTION_FAILED` — thrown when the PIN is wrong (AES-GCM tag mismatch)
- `validatePin(pin)` exported from `crypto.ts`
- `__TEST_ARGON2_MEMORY__` build define (replaces `__TEST_PBKDF2_ITERATIONS__`) for fast test builds

**Changed**
- `ZkpAuthClientOptions` gains optional `storage?: KeyStorage` (defaults to `IndexedDBKeyStorage`)
- `browserComputeProof(privateKey, challenge)` — `passwordBytes` parameter removed (was unused in proof math)

### `@zkp-auth/react`

**Changed**
- `register(username, pin)` — password argument replaced by PIN
- `login(username, pin)` — password argument replaced by PIN
- `ZKPContextValue` gains `hasLocalKey(userId): Promise<boolean>`
- `ZKPContextValue.logout()` — no longer calls `clearKey()` on an in-memory key (keys are not cached between calls)
- All JSDoc examples updated to use PIN

### Security impact

| Vulnerability | Status |
|---|---|
| Public-key oracle (PBKDF2 derived key → offline dict attack against DB) | **Fixed** — public key is now random, derived from nothing |
| Password reaches server | Was already prevented; now eliminated at the protocol level |
| Weak password → weak key | **Fixed** — key entropy is 252 bits regardless of PIN strength |
| Device loss → key loss | Mitigated — `exportKeyBlob` / `importKeyBlob` for transfer |

---

## [0.1.2] — 2026-05-18

### Changed
- Updated GitHub repository URLs to `Abhik2005/zkp-auth`
- All package `repository`, `homepage`, and `bugs` fields corrected

---

## [0.1.0] — 2026-05-18

### Initial Release 🎉

First public release of the ZKP Auth library suite.

#### `@zkp-auth/core` v0.1.0

**Added**
- `generateKeyPair()` — Ed25519 key pair generation using `@noble/curves`
- `createProof(privateKey, message, nonce?)` — Schnorr Proof of Knowledge construction with Fiat–Shamir transform (`SHA-512(R ‖ publicKey ‖ message)`)
- `verifyProof(publicKey, message, proof)` — constant-time proof verification (`s·G = R + c·P`)
- `ZkpError` typed error class with `code` discriminant for structured error handling
- Full adversarial test suite: invalid scalar, point-at-infinity, tampered commitment, tampered response, replay detection

#### `@zkp-auth/server` v0.1.0

**Added**
- `zkpAuthRouter(options)` — Express router factory providing:
  - `POST /register` — stores user public key
  - `POST /challenge` — issues a nonce-bound server challenge
  - `POST /verify` — verifies ZK proof and issues JWT
- `ZkpServerStore` interface for pluggable user storage
- Challenge TTL and single-use enforcement (replays rejected)
- Integration tests via Supertest

#### `@zkp-auth/client` v0.1.0

**Added**
- `ZkpAuthClient` with `register(username, password)` and `login(username, password)` (PBKDF2-based; superseded in v0.2.0)

#### `@zkp-auth/react` v0.1.0

**Added**
- `useZKPAuth()` hook — `{ register, login, logout, user, isAuthenticated, loading, error }`
- `useZKPUser()` hook — read-only user state
- `ZKPProvider` context provider

#### Documentation

**Added**
- VitePress documentation site with Getting Started, Security model, API reference, Migration guide

---

[0.2.0]: https://github.com/Abhik2005/zkp-auth/releases/tag/v0.2.0
[0.1.2]: https://github.com/Abhik2005/zkp-auth/releases/tag/v0.1.2
[0.1.0]: https://github.com/Abhik2005/zkp-auth/releases/tag/v0.1.0
