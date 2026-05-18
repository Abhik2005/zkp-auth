# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ Yes |

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
- Key derivation weaknesses in `@zkp-auth/client`
- Token forgery or privilege escalation in `@zkp-auth/server`

**Out of scope:**

- Vulnerabilities in third-party dependencies (report upstream)
- Attacks requiring physical device access
- Social engineering
- Issues in the demo application that do not affect library code

---

## Security Model Summary

ZKP Auth uses the **Schnorr Proof of Knowledge** scheme over **Ed25519** with the **Fiat–Shamir transform**:

- Private scalars never leave the client
- Each proof is bound to a fresh random nonce — proofs are not replayable
- Challenge hashing: `SHA-512(R ‖ publicKey ‖ message)` — domain-separated
- Point validation is performed on every deserialized curve point
- Scalar range is validated before any curve operation
- All byte comparisons use `crypto.timingSafeEqual()` to prevent timing attacks

This library has **not** undergone a formal third-party cryptographic audit. Use accordingly.

---

## Acknowledgments

We thank all responsible security reporters. A public hall-of-fame will be maintained here once reports are received and resolved.
