# Hardening Model — v0.2.0

This release adds fail-closed source parsing, safe ZIP inspection/extraction, symlink rejection, archive resource ceilings, exact-value reuse deduplication, internal invariant verification, strict schemas, and a mutation-aware hardening harness.

## Tests of the tests

`harness/run_hardening.py` deliberately corrupts activation semantics, atom IDs, summary counts, reusable portability, exact values, and required schema fields. The harness passes only when the validators reject these mutants. This guards against a vacuous test suite that reports success without detecting known failures.

## Security boundary

The cataloger reads data. It does not activate identities. ZIP input is treated as hostile. Directory input may not contain symlinks. Semantic JSON fails closed by default. `normalized_value` is search metadata and is never used as exact identity.
