# ZKP Auth Library — Project Context

## What This Is
Zero-Knowledge Proof authentication library. Schnorr Proof of Knowledge 
on Ed25519 with Fiat-Shamir transform. TypeScript. Open source npm package.

## Monorepo Structure
packages/zkp-auth-core     → core crypto
packages/zkp-auth-server   → Express middleware  
packages/zkp-auth-client   → browser SDK
packages/zkp-auth-react    → React hooks
demo/frontend              → Vite + React
demo/backend               → Express
docs/                      → VitePress

## Tech Stack
- Language: TypeScript strict mode
- Runtime: Node.js 20+
- Crypto: @noble/curves, @noble/hashes, Node built-in crypto
- Bundler: tsup (CJS + ESM + types)
- Monorepo: pnpm workspaces
- Testing: Vitest + Supertest
- Docs: VitePress + TypeDoc

## Crypto Rules (NEVER VIOLATE)
- Never use === for comparing crypto values. Always crypto.timingSafeEqual()
- Always generate fresh nonce per invocation. Never reuse.
- Always validate scalar range before curve operations
- Always validate point is on curve, not point at infinity
- Use @noble/curves Ed25519 — never implement curve math manually
- Hash construction for Fiat-Shamir: SHA-512(R || publicKey || message)

## Code Rules
- TypeScript strict: true always
- Every function has JSDoc
- Every crypto function has adversarial unit test
- No any types
- Errors typed, never throw raw strings

### Current Phase
- Phase 1 complete. Skeleton done.
- Phase 2 starting — crypto core implementation.

### Completed
- pnpm monorepo scaffolded
- All package.json files created
- CI/CD workflow created
- tsup configs done