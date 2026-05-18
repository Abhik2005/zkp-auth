// @zkp-auth/core — package-pin regression test
//
// Validates: Requirement 7.6
//
// WHY THIS TEST EXISTS
//
// Requirement 7.6 mandates that `packages/zkp-auth-core/package.json`
// pin `@noble/curves` to `^1.9.7` and `@noble/hashes` to `^1.8.0` —
// the versions whose `.d.ts` API surface was inspected directly during
// the requirements-review phase and enumerated in
// `requirements.md` → "External API Surface (verified against
// installed files) — APPROVAL GATE". A SemVer minor or major bump on
// either dependency MAY introduce changes — additions, deprecations,
// signature shifts, or rename of `Point.toBytes()` etc. — that
// invalidate the verified surface. Such a bump MUST trigger a fresh
// verification pass against the new `node_modules` and a documented
// update of the External API Surface section.
//
// This test exists as a regression guard: it intentionally FAILS when
// a maintainer (or a careless `pnpm up`) silently bumps either pin
// past the verified `^1.9.x` / `^1.8.x` ranges. A failing test is the
// signal that the External API Surface section MUST be re-read,
// re-verified, and re-approved before the bump merges. It is NOT a
// blocker against legitimate version updates — it is a blocker
// against UNEXAMINED ones.
//
// As a bonus this file also locks the `fast-check` major-version pin
// from design "Tooling", so the property-test arsenal in tasks
// 5.x–10.x cannot drift onto a major version whose generator API
// (`fc.uint8Array`, `fc.bigInt`, etc.) may have changed shape.
//
// HOW THE TEST WORKS
//
// We read `package.json` AT RUNTIME via `fs.readFileSync` + `JSON.parse`
// rather than `import`-ing it. Three reasons:
//   1. The repo is ESM-only ("module": "ESNext", per `tsconfig.base.json`)
//      and importing JSON in ESM requires either an experimental import
//      assertion or a bundler-specific shim — runtime read is portable
//      across both `vitest run` and `tsc --noEmit` without dragging in
//      `--experimental-json-modules`.
//   2. Reading at runtime guarantees we observe the on-disk pin at the
//      moment the test runs, not whatever the bundler captured at
//      type-check time. This is the value `pnpm install` would consume.
//   3. It keeps the test free of any structural dependency on
//      `package.json`'s field layout — a missing `dependencies` block
//      surfaces as a clear test failure rather than a TypeScript
//      compile error in unrelated code.
//
// The path is resolved via `fileURLToPath(import.meta.url)` →
// `dirname(...)` → `resolve(testDir, '..', 'package.json')`, matching
// the project's ESM-only convention.
//
// FUTURE-PROOFING NOTE
//
// When a deliberate, reviewed pin bump lands (e.g. `@noble/curves` →
// `^1.10.0`), the test owner MUST:
//   1. Re-read the new package's installed `.d.ts` files under
//      `node_modules/@noble/curves` and confirm every symbol
//      enumerated in requirements.md "External API Surface §A–§E"
//      still resolves with the same signature shape.
//   2. Update the `requirements.md` External API Surface section to
//      record the new verified version.
//   3. Update the `startsWith` prefix in the corresponding
//      assertion below (e.g. `'^1.10.'`).
// Failing this test without performing all three steps is the bug
// this guard exists to catch.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

/**
 * Structural shape of the subset of `package.json` this test inspects.
 *
 * The full `package.json` has many fields (`name`, `version`, `scripts`,
 * `exports`, …) — we deliberately type ONLY the fields we read so a
 * future field addition does not perturb this test, and so a missing
 * `dependencies` or `devDependencies` block surfaces as a clean
 * `expect(...).toBeDefined()` failure rather than a `TypeError`.
 *
 * `Record<string, string>` is the correct shape for both blocks
 * because npm pins are always string-valued.
 *
 * The structural cast keeps the file free of `any` per the project
 * rule "No `any` types" (PROJECT.md → "Code Rules").
 */
type PackageJsonShape = {
  readonly dependencies?: Record<string, string>;
  readonly devDependencies?: Record<string, string>;
};

/**
 * Absolute path to this test file's directory, derived from the ESM
 * module URL. Used as the anchor for resolving the sibling
 * `package.json` one directory up.
 */
const TEST_DIR = dirname(fileURLToPath(import.meta.url));

/**
 * Absolute path to `packages/zkp-auth-core/package.json`. Resolved
 * once at module load time; the `package.json` file is static for
 * the duration of a test run, so re-reading it inside each `it`
 * block would only add I/O without adding signal.
 */
const PACKAGE_JSON_PATH = resolve(TEST_DIR, '..', 'package.json');

/**
 * Parsed `package.json` contents. Read with UTF-8 encoding because
 * `package.json` is mandated UTF-8 by the npm spec, and parsed with
 * `JSON.parse` — the structural cast on the result is what keeps the
 * downstream `.dependencies['@noble/curves']` access type-safe under
 * `strict: true` without resorting to `any`.
 */
const pkg = JSON.parse(readFileSync(PACKAGE_JSON_PATH, 'utf8')) as PackageJsonShape;

describe('package.json dependency pins (regression guard for Requirement 7.6)', () => {
  /**
   * Locks `@noble/curves` to the SemVer minor range `^1.9.x`. This pin
   * protects the curve-math import surface enumerated in
   * `requirements.md` → "External API Surface §B" (`ed25519.Point`,
   * `Point.BASE`, `Point.fromBytes`, `Point.Fn.ORDER`,
   * `Point.Fn.create`, `point.toBytes`, `point.multiply`,
   * `point.add`, `point.is0`, …) and §C (`bytesToNumberLE`,
   * `numberToBytesLE`, `concatBytes`).
   *
   * A bump that escapes the `^1.9.` prefix (e.g. `^1.10.0` or
   * `^2.0.0`) MUST re-verify every signature listed in those
   * sections against the new `node_modules/@noble/curves/*.d.ts`.
   */
  it('pins @noble/curves to ^1.9.x', () => {
    expect(pkg.dependencies).toBeDefined();
    expect(pkg.dependencies?.['@noble/curves']).toBeDefined();
    expect(typeof pkg.dependencies?.['@noble/curves']).toBe('string');
    expect(pkg.dependencies?.['@noble/curves']?.startsWith('^1.9.')).toBe(true);
  });

  /**
   * Locks `@noble/hashes` to the SemVer minor range `^1.8.x`. This
   * pin protects the hash import surface enumerated in
   * `requirements.md` → "External API Surface §D" — specifically
   * `sha512(data: Uint8Array): Uint8Array` from
   * `@noble/hashes/sha512.js`, the sole hash primitive used by
   * `transcript.ts` for the Fiat-Shamir scalar derivation
   * (Requirement 8.4).
   *
   * A bump that escapes the `^1.8.` prefix MUST re-verify the
   * `sha512` signature and the existence of the
   * `@noble/hashes/sha512.js` submodule path against the new
   * `node_modules/@noble/hashes/*.d.ts`.
   */
  it('pins @noble/hashes to ^1.8.x', () => {
    expect(pkg.dependencies).toBeDefined();
    expect(pkg.dependencies?.['@noble/hashes']).toBeDefined();
    expect(typeof pkg.dependencies?.['@noble/hashes']).toBe('string');
    expect(pkg.dependencies?.['@noble/hashes']?.startsWith('^1.8.')).toBe(true);
  });

  /**
   * Locks `fast-check` to major version 3. This is a test-tooling
   * pin from design "Tooling" — every property-based test under
   * `test/property-*.test.ts` consumes `fast-check`'s `fc.uint8Array`,
   * `fc.bigInt`, `fc.constantFrom`, and `fc.assert` APIs. A jump to
   * fast-check 4.x has historically reshaped some of these
   * generators' option objects, so a major-version drift here would
   * silently change generator semantics underneath the property
   * tests.
   *
   * The pin is `^3` (no minor) per `package.json`, so the prefix
   * check is the entire string `'^3'` — `'^3.x.y'` would also be
   * valid, hence `startsWith('^3')` rather than `===`.
   */
  it('pins fast-check to ^3.x (test-tooling lock)', () => {
    expect(pkg.devDependencies).toBeDefined();
    expect(pkg.devDependencies?.['fast-check']).toBeDefined();
    expect(typeof pkg.devDependencies?.['fast-check']).toBe('string');
    expect(pkg.devDependencies?.['fast-check']?.startsWith('^3')).toBe(true);
  });
});
