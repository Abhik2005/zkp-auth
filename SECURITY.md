# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.2.x | ✅ Yes |
| 0.1.x | ⚠️ Security fixes only |

Older versions receive no security updates once a new minor version is released.

---

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability, please follow the responsible disclosure process below.

### Step 1 — Contact

Email **security@zkp-auth.dev** with:

- A clear description of the vulnerability
- The affected package(s) and version(s)
- Steps to reproduce or a proof-of-concept (do not include live exploit code)
- Your assessment of severity (Critical / High / Medium / Low)
- Your name / handle for acknowledgment (optional)

Encrypt sensitive reports using our PGP key (published on [keys.openpgp.org](https://keys.openpgp.org)).

### Step 2 — Response Timeline

| Milestone | Target |
|---|---|
| Acknowledgment | Within 48 hours |
| Initial assessment | Within 5 business days |
| Fix or mitigation plan | Within 30 days for Critical/High; 90 days for Medium/Low |
| Public disclosure | Coordinated with reporter after fix is released |

### Step 3 — Coordinated Disclosure

We follow coordinated disclosure: we will work with you to understand and fix the issue before public announcement. We will credit you in the release notes unless you prefer to remain anonymous.

---

## Scope

**In scope:**

- Cryptographic weaknesses in proof generation or verification (`@zkp-auth/core`)
- Timing side-channel vulnerabilities in comparison or verification logic
- Authentication bypass — forging a valid proof without knowing the private scalar
- Key storage weaknesses — bypassing Argon2id or AES-256-GCM in `@zkp-auth/client`
- PIN brute-force feasibility (Argon2id parameters, memory cost)
- Token forgery or privilege escalation in `@zkp-auth/server`
- IndexedDB data leakage from the encrypted key store

**Out of scope:**

- Vulnerabilities in third-party dependencies (report upstream)
- Attacks requiring physical device access (mitigated by Argon2id; in scope only if the KDF is bypassable)
- Social engineering
- Issues in the demo application that do not affect library code

---

## Security Model Summary

ZKP Auth uses the **Schnorr Proof of Knowledge** scheme over **Ed25519** with the **Fiat–Shamir transform**:

### Key Generation
- Ed25519 keypairs are generated using **bounded rejection sampling** over `globalThis.crypto.getRandomValues`
- Private scalars are uniform over `[1, L)` — no modular-reduction bias
- The public key has **no relationship to any password** — public-key oracle attacks against the server DB are impossible

### Local Key Storage
- Private keys are encrypted with **AES-256-GCM** before being written to IndexedDB
- The AES wrapping key is derived from a user PIN via **Argon2id** (`m = 65536 KB, t = 3, p = 1`)
- A fresh random 16-byte **salt** and 12-byte **IV** are generated for every `generateAndStore` call
- The PIN **never leaves the browser** — it is never transmitted or logged

### Proof Construction
- Private scalars are loaded into memory only during proof computation
- Private key buffers are **unconditionally zeroed** in `finally` blocks after use
- Each proof is bound to a fresh server-issued challenge — proofs are not replayable
- Challenge hashing: `SHA-512(R ‖ publicKey ‖ message) mod L` — domain-separated
- Scalar range is validated before any curve operation
- All byte comparisons use `crypto.timingSafeEqual()` to prevent timing attacks

### What the server stores
- Only a 32-byte Ed25519 **public key** — no password, no hash, no PIN
- A compromised server DB reveals only public keys, which are mathematically useless without the corresponding private scalar

This library has **not** undergone a formal third-party cryptographic audit. Use accordingly.

---

## Acknowledgments

We thank all responsible security reporters. A public hall-of-fame will be maintained here once reports are received and resolved.
