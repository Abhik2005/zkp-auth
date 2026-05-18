// @zkp-auth/core — source-tree audit guard
//
// Validates: Requirements 5.1, 5.2, 5.4, 7.3
//
// WHY THIS TEST EXISTS
//
// Requirements 5 and 7 mandate two structural rules across
// `packages/zkp-auth-core/src/**/*.ts` that no individual unit or
// property test can fully enforce on its own:
//
//   • Side-channel discipline (Requirements 5.1, 5.2, 5.4): every
//     byte-array equality over secret or attacker-chosen data routes
//     through `crypto.timingSafeEqual`. The `===`, `!==`,
//     `Buffer.equals`, `Buffer.compare`, and short-circuit
//     `Uint8Array`-compare paths are forbidden ANYWHERE in `src/`,
//     not merely "preferred against". A single stray `===` on
//     attacker-chosen bytes silently weakens the entire library.
//   • Closed error taxonomy (Requirement 7.3): no raw throws —
//     `throw '...string...'`, `throw 0`, `throw "..."` — appear in
//     `src/`. Every fault path emits one of the three typed-error
//     classes from `errors.ts`, so callers can pattern-match on a
//     stable `.code`.
//
// Beyond those two rules this file also locks the architectural
// chokepoints the design pinned in "Components and Interfaces":
//
//   • `crypto.timingSafeEqual` is imported in exactly one file
//     (`compare.ts`).
//   • `randomBytes` (the `node:crypto` named export) is imported in
//     exactly one file (`rng.ts`).
//   • The `// __forTesting__ — DO NOT IMPORT FROM PRODUCTION CODE`
//     audit-marker comment that gates the `compute-proof.ts` test
//     hook appears exactly once in `src/`, locking the contract
//     that no other module pulls in the test-only nonce hook.
//
// HOW THE AUDIT WORKS
//
// The test enumerates every `.ts` file under `src/` dynamically via
// `fs.readdirSync`, so a future file addition is picked up
// automatically — the audit cannot drift behind the directory tree.
// For each file, the test:
//
//   1. Reads the raw text and splits on lines (preserving 1-indexed
//      line numbers for diagnostic output).
//   2. Builds a "code-only" projection of the file by stripping
//      block comments (`/* ... */`, multi-line aware) and line
//      comments (`// ...`). The stripping is character-level rather
//      than regex-based so block comments that span multiple lines
//      and `//` occurring after `/* ... */` on the same line are
//      handled correctly. Pedagogical comments that mention
//      forbidden patterns (e.g. `verify-proof.ts`'s "We MUST NOT
//      use `lhs.equals(rhs)`") are exempt by construction —
//      stripping happens BEFORE the forbidden-pattern checks.
//   3. Detects `// audit: allow` opt-out markers on the raw line.
//      The opt-out is the documented escape hatch (per task 13.1
//      "Lines may opt out via `// audit: allow` trailing comment
//      for intentional exemptions"); it is checked against the raw
//      line BEFORE stripping so that the marker itself isn't
//      stripped away.
//   4. Applies four line-level rules to the code-only projection,
//      skipping lines that carry the `// audit: allow` marker:
//        a. `errors.ts` is the ONLY file allowed to compare error
//           `code` strings, so it is exempt from rule (a). For
//           every other file: a line containing any forbidden-data
//           identifier (word-boundary match against the set
//           `privateKey, nonce, password, secret, r_bytes,
//           r_scalar, proof, challenge, publicKey, R_bytes,
//           s_bytes, lhs_bytes, rhs_bytes`) MUST NOT contain
//           `===` or `!==`.
//        b. NO `.equals(` substring anywhere in code.
//        c. NO `Buffer.compare(` substring anywhere in code.
//        d. NO raw throw (`/^\s*throw\s+(['"\d])/`).
//   5. Applies three file-level "exactly one file" rules. These
//      operate on the code-only projection so a comment that
//      mentions `crypto.timingSafeEqual` for documentation purposes
//      does not count toward the locked import site:
//        e. `timingSafeEqual` (word boundary, excluding
//           `timingSafeEqualBytes`) appears in exactly one file:
//           `compare.ts`.
//        f. `randomBytes` (word boundary, excluding `randomBytes32`)
//           appears in exactly one file: `rng.ts`.
//        g. The literal marker comment
//           `// __forTesting__ — DO NOT IMPORT FROM PRODUCTION CODE`
//           appears in exactly one file: `compute-proof.ts`. This
//           rule operates on the RAW file content (not the
//           code-only projection), since the marker IS a comment.
//
// On a violation, every `it` block accumulates the offending
// `file:line: snippet` entries into an array and asserts
// `expect(violations).toEqual([])` so a failure prints every
// location that needs to change in a single test run.
//
// KEY ASSUMPTION — COMMENT STRIPPING vs. LITERAL "ANYWHERE"
//
// Task 13.1's wording for rules (b)–(d) says "anywhere in the
// scanned files". Read literally, a pedagogical comment such as
// `verify-proof.ts`'s "We MUST NOT use `lhs.equals(rhs)`" would
// trigger rule (b) — even though the comment is the OPPOSITE of a
// real violation. The task's `// audit: allow` opt-out exists to
// handle exactly this kind of false positive, but adding the
// opt-out comment to every pedagogical reference across `src/`
// would be noise. This audit takes the principled stance instead:
// strip comments before applying the literal-substring checks, so
// only EXECUTABLE CODE is scanned. The `// audit: allow` opt-out
// remains as a fallback for code lines that genuinely need to
// invoke a forbidden pattern (no such case exists today, but the
// hatch is preserved for future additions).
//
// This interpretation is documented as an explicit assumption in
// the task summary alongside the test file. Reviewers who prefer
// the strict-literal interpretation can flip a single boolean
// (`STRIP_COMMENTS_BEFORE_SCAN` below) to `false` and re-run; doing
// so against the current source tree will surface one comment-only
// false positive (`verify-proof.ts:318` — see file-header comment
// of that file for the pedagogical context).

import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, basename } from 'node:path';

// ---------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------

/**
 * When `true`, comments are stripped from each source file before the
 * literal-substring rules ((b)–(d), (e)–(f)) are applied. See the
 * "KEY ASSUMPTION" section of the file header for the rationale.
 *
 * Flipping this to `false` enables the strict-literal reading of
 * task 13.1; against the current source tree that produces one
 * documented false-positive (`verify-proof.ts:318`'s comment).
 */
const STRIP_COMMENTS_BEFORE_SCAN = true;

/**
 * The forbidden-data identifier set per task 13.1. Each is matched as a
 * whole word (`\b<id>\b`). When ANY of these appears on a line of code,
 * that line MUST NOT contain `===` or `!==`. The case is significant —
 * `password` (lowercase) is forbidden but `INVALID_PASSWORD` (uppercase
 * inside a string literal) is fine, because `\bpassword\b` does not
 * match the uppercase form.
 */
const FORBIDDEN_DATA_IDENTIFIERS = [
  'privateKey',
  'nonce',
  'password',
  'secret',
  'r_bytes',
  'r_scalar',
  'proof',
  'challenge',
  'publicKey',
  'R_bytes',
  's_bytes',
  'lhs_bytes',
  'rhs_bytes',
] as const;

/**
 * The literal marker comment that gates the `__forTesting__` test hook
 * in `compute-proof.ts`. The audit asserts this exact string appears
 * in exactly one file under `src/`.
 *
 * Note: the `—` is a true em-dash (U+2014), matching the source. A
 * naive ASCII hyphen would silently disagree.
 */
const FOR_TESTING_MARKER_COMMENT =
  '// __forTesting__ — DO NOT IMPORT FROM PRODUCTION CODE';

/**
 * The `// audit: allow` opt-out marker. A line whose trim ends with
 * this exact suffix is considered intentionally exempt from all
 * line-level rules.
 */
const AUDIT_ALLOW_SUFFIX = '// audit: allow';

// ---------------------------------------------------------------------
// File enumeration
// ---------------------------------------------------------------------

/**
 * Absolute path to this test file's directory, derived from the ESM
 * module URL. The sibling `src/` directory is one level up.
 */
const TEST_DIR = dirname(fileURLToPath(import.meta.url));

/**
 * Absolute path to `packages/zkp-auth-core/src/`, the directory the
 * audit walks.
 */
const SRC_DIR = resolve(TEST_DIR, '..', 'src');

/**
 * Per-file structural record: absolute path, basename, raw text, raw
 * lines, and the comment-stripped lines used by the line-level rules.
 *
 * The enumeration is dynamic — `readdirSync` filtered by `.ts` extension
 * — so a future source file landing under `src/` is automatically
 * picked up by the audit on the next test run.
 */
type SourceFile = {
  readonly absPath: string;
  readonly base: string;
  readonly rawText: string;
  readonly rawLines: readonly string[];
  readonly codeLines: readonly string[];
};

/**
 * Strips block comments (`/_ ... _/`) and line comments (`// ...`) from
 * a full file's text, returning a per-line array whose length matches
 * the input's line count. Block comments that span multiple lines are
 * replaced with whitespace on each line, preserving the 1-indexed line
 * numbers used in violation messages.
 *
 * String-literal handling is intentionally simplistic: the function
 * does not parse strings and could in principle mis-strip a `//`
 * appearing inside a string literal. The current source tree has no
 * such case, so the simpler implementation is preferred over a full
 * tokenizer. Any future source file that introduces `//` inside a
 * string literal will need to either avoid the construct or guard
 * the line with `// audit: allow`.
 */
function stripComments(text: string): string[] {
  const lines = text.split(/\r?\n/);
  const out: string[] = [];
  let inBlockComment = false;

  for (const line of lines) {
    let result = '';
    let i = 0;
    const n = line.length;

    while (i < n) {
      if (inBlockComment) {
        const end = line.indexOf('*/', i);
        if (end === -1) {
          // Block comment continues past end of line.
          i = n;
        } else {
          i = end + 2;
          inBlockComment = false;
        }
      } else {
        const lineCommentStart = line.indexOf('//', i);
        const blockCommentStart = line.indexOf('/*', i);
        const noLine = lineCommentStart === -1;
        const noBlock = blockCommentStart === -1;

        if (noLine && noBlock) {
          result += line.slice(i);
          i = n;
        } else if (!noLine && (noBlock || lineCommentStart < blockCommentStart)) {
          // Line comment wins; everything from `//` to EOL is stripped.
          result += line.slice(i, lineCommentStart);
          i = n;
        } else {
          // Block comment opens before any line comment on this line.
          result += line.slice(i, blockCommentStart);
          i = blockCommentStart + 2;
          inBlockComment = true;
        }
      }
    }

    out.push(result);
  }

  return out;
}

/**
 * Reads every `.ts` file under `SRC_DIR` and produces a `SourceFile`
 * record for each. The enumeration is performed once at module load
 * because the source tree is static for the duration of a test run.
 */
function loadSourceFiles(): SourceFile[] {
  const entries = readdirSync(SRC_DIR, { withFileTypes: true });
  const files: SourceFile[] = [];

  for (const entry of entries) {
    if (!entry.isFile()) continue;
    if (!entry.name.endsWith('.ts')) continue;

    const absPath = resolve(SRC_DIR, entry.name);
    const rawText = readFileSync(absPath, 'utf8');
    const rawLines = rawText.split(/\r?\n/);
    const codeLines = STRIP_COMMENTS_BEFORE_SCAN ? stripComments(rawText) : rawLines.slice();

    files.push({
      absPath,
      base: basename(absPath),
      rawText,
      rawLines,
      codeLines,
    });
  }

  // Sort for stable diagnostic output; readdir order is platform-dependent.
  files.sort((a, b) => a.base.localeCompare(b.base));
  return files;
}

const SOURCE_FILES = loadSourceFiles();

/**
 * Counts non-overlapping matches of `regex` in `text`. Used by the
 * file-level "exactly one file" rules below.
 */
function countMatches(text: string, regex: RegExp): number {
  const flags = regex.flags.includes('g') ? regex.flags : `${regex.flags}g`;
  const re = new RegExp(regex.source, flags);
  let count = 0;
  // `String.prototype.matchAll` requires a `g` flag; spread to count.
  for (const _ of text.matchAll(re)) {
    count += 1;
  }
  return count;
}

/**
 * Builds a regex that matches `id` as a whole word, where the surrounding
 * characters are not `[A-Za-z0-9_]`. JavaScript's `\b` already does this,
 * but we wrap explicitly for readability.
 */
function wholeWordRegex(id: string): RegExp {
  // Escape regex special characters in `id` defensively, even though all
  // current ids are plain identifier characters.
  const escaped = id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`\\b${escaped}\\b`);
}

/**
 * Returns `true` iff the trimmed raw line ends with the `// audit: allow`
 * opt-out marker. The check is performed against the raw line so the
 * marker itself isn't stripped by `stripComments`.
 */
function isAuditAllowed(rawLine: string): boolean {
  return rawLine.trim().endsWith(AUDIT_ALLOW_SUFFIX);
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

describe('audit: no forbidden comparators in src/**/*.ts', () => {
  it('enumerates every .ts file under src/ dynamically (sanity check)', () => {
    // Sanity: at least the 11 known files are present. A drop in count
    // would indicate the enumeration is broken (e.g. wrong path) rather
    // than a real file removal.
    expect(SOURCE_FILES.length).toBeGreaterThanOrEqual(11);

    // Every loaded file lives under SRC_DIR.
    for (const f of SOURCE_FILES) {
      expect(f.absPath.startsWith(SRC_DIR)).toBe(true);
      expect(f.base.endsWith('.ts')).toBe(true);
    }
  });

  it('rule (a): no === or !== on lines containing a forbidden-data identifier (errors.ts skipped)', () => {
    const violations: string[] = [];
    const forbiddenIdRegexes = FORBIDDEN_DATA_IDENTIFIERS.map(wholeWordRegex);

    for (const f of SOURCE_FILES) {
      // errors.ts is allowed to compare error `code` strings via `===`
      // (per task 13.1 spec exemption).
      if (f.base === 'errors.ts') continue;

      for (let i = 0; i < f.codeLines.length; i += 1) {
        const codeLine = f.codeLines[i] ?? '';
        const rawLine = f.rawLines[i] ?? '';

        if (isAuditAllowed(rawLine)) continue;

        const hasForbiddenId = forbiddenIdRegexes.some((re) => re.test(codeLine));
        if (!hasForbiddenId) continue;

        if (codeLine.includes('===') || codeLine.includes('!==')) {
          violations.push(`${f.base}:${i + 1}: ${rawLine.trim()}`);
        }
      }
    }

    expect(violations, `forbidden-data identifier compared with === or !==:\n${violations.join('\n')}`).toEqual([]);
  });

  it('rule (b): no `.equals(` anywhere in code', () => {
    const violations: string[] = [];

    for (const f of SOURCE_FILES) {
      for (let i = 0; i < f.codeLines.length; i += 1) {
        const codeLine = f.codeLines[i] ?? '';
        const rawLine = f.rawLines[i] ?? '';

        if (isAuditAllowed(rawLine)) continue;
        if (codeLine.includes('.equals(')) {
          violations.push(`${f.base}:${i + 1}: ${rawLine.trim()}`);
        }
      }
    }

    expect(violations, `\`.equals(\` found in code:\n${violations.join('\n')}`).toEqual([]);
  });

  it('rule (c): no `Buffer.compare(` anywhere in code', () => {
    const violations: string[] = [];

    for (const f of SOURCE_FILES) {
      for (let i = 0; i < f.codeLines.length; i += 1) {
        const codeLine = f.codeLines[i] ?? '';
        const rawLine = f.rawLines[i] ?? '';

        if (isAuditAllowed(rawLine)) continue;
        if (codeLine.includes('Buffer.compare(')) {
          violations.push(`${f.base}:${i + 1}: ${rawLine.trim()}`);
        }
      }
    }

    expect(violations, `\`Buffer.compare(\` found in code:\n${violations.join('\n')}`).toEqual([]);
  });

  it('rule (d): no raw throws (`throw \'...\'`, `throw "..."`, `throw 0`)', () => {
    // Per task 13.1 and Requirement 7.3, every fault path emits a typed
    // error class. A raw `throw 'message'` or `throw 0` would bypass the
    // typed-error taxonomy.
    //
    // The regex `/^\s*throw\s+(['"\d])/` matches a `throw` statement
    // whose first non-space character after `throw` is a quote or a
    // digit. `throw new InvalidInputError(...)` is fine (the next char
    // is `n`, an identifier start). The check runs on each line of the
    // CODE-only projection so a comment block discussing raw-throw
    // semantics doesn't trigger it.
    const rawThrowRegex = /^\s*throw\s+(['"\d])/;
    const violations: string[] = [];

    for (const f of SOURCE_FILES) {
      for (let i = 0; i < f.codeLines.length; i += 1) {
        const codeLine = f.codeLines[i] ?? '';
        const rawLine = f.rawLines[i] ?? '';

        if (isAuditAllowed(rawLine)) continue;
        if (rawThrowRegex.test(codeLine)) {
          violations.push(`${f.base}:${i + 1}: ${rawLine.trim()}`);
        }
      }
    }

    expect(violations, `raw throw found:\n${violations.join('\n')}`).toEqual([]);
  });

  it('rule (e): `timingSafeEqual` appears in exactly one file: compare.ts', () => {
    // Whole-word match excludes `timingSafeEqualBytes` (the wrapper).
    // Operates on the code-only projection so that the file-header
    // comments in `verify-proof.ts` and `compare.ts` that reference
    // `timingSafeEqual` for documentation don't count toward the
    // chokepoint.
    const re = /\btimingSafeEqual\b/;
    const filesWithMatch: string[] = [];

    for (const f of SOURCE_FILES) {
      const code = f.codeLines.join('\n');
      if (re.test(code)) {
        filesWithMatch.push(f.base);
      }
    }

    expect(filesWithMatch).toEqual(['compare.ts']);
  });

  it('rule (f): `randomBytes` (from node:crypto) appears in exactly one file: rng.ts', () => {
    // Whole-word match excludes `randomBytes32` (the wrapper exported
    // by `rng.ts`). Operates on the code-only projection so that
    // docstrings/comments mentioning `randomBytes` for diagnostic
    // explanation (e.g. errors.ts's JSDoc) don't count toward the
    // chokepoint.
    //
    // This is the cleaner of the two approaches the task hints
    // outlined: the alternative ("import line `from 'node:crypto'`
    // appears in exactly two files") would require a separate rule
    // for `compare.ts`'s `timingSafeEqual` import, whereas the
    // word-boundary `randomBytes` check naturally locks the
    // chokepoint without conflating it with `compare.ts`. The
    // assumption is documented in the test summary.
    const re = /\brandomBytes\b/;
    const filesWithMatch: string[] = [];

    for (const f of SOURCE_FILES) {
      const code = f.codeLines.join('\n');
      if (re.test(code)) {
        filesWithMatch.push(f.base);
      }
    }

    expect(filesWithMatch).toEqual(['rng.ts']);
  });

  it('rule (g): the `__forTesting__` marker comment appears in exactly one file: compute-proof.ts', () => {
    // The marker IS a comment, so this rule operates on the RAW file
    // content (not the code-only projection). The literal substring
    // `// __forTesting__ — DO NOT IMPORT FROM PRODUCTION CODE` must
    // appear in exactly one file. Note: the dash is U+2014 (em-dash)
    // — an ASCII hyphen would not match.
    const filesWithMarker: string[] = [];
    let totalOccurrences = 0;

    for (const f of SOURCE_FILES) {
      const occurrences = countMatches(
        f.rawText,
        new RegExp(FOR_TESTING_MARKER_COMMENT.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')),
      );
      if (occurrences > 0) {
        filesWithMarker.push(f.base);
        totalOccurrences += occurrences;
      }
    }

    // File-level: exactly one file contains the marker.
    expect(filesWithMarker).toEqual(['compute-proof.ts']);
    // Occurrence-level: the marker appears exactly once total. The
    // task wording "exactly once in src/" is honored at both
    // granularities to make accidental duplication (a copy-paste of
    // the marker into a second declaration in the same file) fail
    // loudly.
    expect(totalOccurrences).toBe(1);
  });
});
