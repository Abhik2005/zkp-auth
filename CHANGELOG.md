# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- `ZkpClient` class with:
  - `register(username, password)` — derives deterministic Ed25519 key pair via PBKDF2 (`SHA-512`, 210,000 iterations), registers public key with server
  - `login(username, password)` — derives key pair, fetches challenge, constructs ZK proof, verifies with server, returns JWT
- `deriveKeyPair(username, password, salt?)` — exported KDF primitive for custom flows
- Browser-compatible (no Node.js built-ins required in hot path)

#### `@zkp-auth/react` v0.1.0

**Added**
- `useZkpAuth(options)` hook — `{ login, logout, token, isLoading, error }`
- `useZkpRegister(options)` hook — `{ register, isLoading, error }`
- `ZkpAuthProvider` context provider for shared client instance
- TypeScript generics for typed user payload extraction from JWT claims

#### Documentation

**Added**
- VitePress documentation site with:
  - Getting Started guide
  - Security model explanation
  - API reference (TypeDoc-generated)
  - Migration guide
  - Contributing and security policies

---

[0.1.0]: https://github.com/vedadkovacevic/zkp-auth/releases/tag/v0.1.0
