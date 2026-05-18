# Contributing to ZKP Auth

Thank you for considering a contribution. This document describes how to set up the project, the standards we enforce, and the process for submitting changes.

---

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Repository Structure](#repository-structure)
4. [Development Workflow](#development-workflow)
5. [Crypto Safety Rules](#crypto-safety-rules)
6. [Code Standards](#code-standards)
7. [Testing Requirements](#testing-requirements)
8. [Submitting a Pull Request](#submitting-a-pull-request)
9. [Reporting Bugs](#reporting-bugs)

---

## Code of Conduct

We follow the [Contributor Covenant v2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). Be respectful and constructive.

---

## Getting Started

**Requirements**

- Node.js ≥ 20
- pnpm ≥ 9 (`npm install -g pnpm`)
- Git

**Setup**

```bash
git clone https://github.com/Abhik2005/zkp-auth.git
cd zkp-auth
pnpm install
pnpm build
pnpm test       # Must be all green before you start
```

---

## Repository Structure

```
packages/
  zkp-auth-core/     Core crypto — key generation, proof creation/verification
  zkp-auth-server/   Express middleware for challenge/verify endpoints
  zkp-auth-client/   Browser SDK — KDF, proof construction, HTTP layer
  zkp-auth-react/    React hooks wrapping the client
demo/
  frontend/          Vite + React demo application
  backend/           Express demo server
docs/                VitePress documentation site
```

---

## Development Workflow

1. **Fork** the repository and create a feature branch from `main`:
   ```bash
   git checkout -b feat/my-feature
   ```

2. **Make changes** following the [code standards](#code-standards) below.

3. **Write or update tests** — no exceptions, see [Testing Requirements](#testing-requirements).

4. **Run the full pipeline locally** before pushing:
   ```bash
   pnpm typecheck
   pnpm lint
   pnpm build
   pnpm test
   ```

5. **Commit** using [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat:` new feature
   - `fix:` bug fix
   - `docs:` documentation only
   - `refactor:` code restructure, no behaviour change
   - `test:` adding or updating tests
   - `chore:` build scripts, CI, dependencies

6. **Open a Pull Request** to `main`.

---

## Crypto Safety Rules

These rules are **non-negotiable** and will cause a PR rejection if violated:

| Rule | Reason |
|---|---|
| Use `crypto.timingSafeEqual()` for all comparison of crypto values | Prevents timing side-channels |
| Generate a fresh nonce per invocation; never reuse | Reuse breaks ZK proof security |
| Validate scalar range before curve operations | Prevents invalid point edge cases |
| Validate points are on curve and not the point at infinity | Prevents small-subgroup attacks |
| Use `@noble/curves` Ed25519 — never implement curve math manually | Manual implementations are error-prone and unaudited |
| Hash construction: `SHA-512(R ‖ publicKey ‖ message)` | Matches the Fiat–Shamir spec; changing order breaks cross-version compat |

---

## Code Standards

- **TypeScript `strict: true`** everywhere — no `any` types without a comment justifying it.
- **JSDoc on every exported symbol** — include `@param`, `@returns`, `@throws`.
- **Named constants** — no magic numbers or literal strings inline.
- **Explicit error handling** — typed error classes, never raw string throws.
- **No dead code** — commented-out code blocks are rejected.

---

## Testing Requirements

Every PR touching `packages/` **must** include tests:

| Change type | Required test tier |
|---|---|
| New crypto function | Unit (happy path + adversarial inputs + boundary) |
| New API endpoint | Integration via Supertest |
| New hook / browser API | Unit with jsdom |
| Bug fix | Regression test that fails before fix, passes after |

Run tests:
```bash
pnpm test                          # All packages
pnpm --filter @zkp-auth/core test  # Single package
```

Coverage is not gated but aim for >90% on `packages/zkp-auth-core`.

---

## Submitting a Pull Request

- Target branch: `main`
- Title: follow Conventional Commits (`feat: add TOTP fallback`)
- Description: what changed, why, how to test
- Link any related issue (`Closes #42`)
- CI must be green — the PR will not be merged otherwise
- At least one maintainer review is required

---

## Reporting Bugs

Use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md) and fill in every section. For **security vulnerabilities**, follow [SECURITY.md](SECURITY.md) instead — do not open a public issue.
