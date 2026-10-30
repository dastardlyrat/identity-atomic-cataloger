# Loose / Fuzzy / Metamorphic Test Suite

The strict harness asks whether a catalog is exactly valid. The fuzzy harness asks a different question: **does the mechanism remain semantically stable when harmless details drift, while still refusing to erase meaningful ambiguity?**

Run:

```bash
python harness/run_fuzzy.py
python harness/run_fuzzy.py --seed 12345 --iterations 1000
```

The run is deterministic for a given seed. It uses only the Python standard library.

## Loose equivalence boundary

The harness deliberately ignores atom IDs, artifact hashes, file hashes, and wrapper path prefixes when comparing metamorphic variants. Those are provenance and are expected to change when source bytes or packaging change. It compares JSON Pointer, derived type/reuse class, portability, value type, and exact canonical value.

Harmless changes tested include JSON indentation, key ordering, CRLF/LF differences, UTF-8 BOM, ZIP member ordering, wrapper directories, case variations, unrelated prose files, and randomized JSON structures.

Meaning-changing cases must remain visible or be rejected: array reordering, exact string whitespace differences, Unicode normalization differences, duplicate keys, NaN/Infinity, numeric overflow to non-finite values, malformed UTF-8, unpaired surrogates, malformed semantic JSON, and non-canonical ZIP paths.

This suite complements rather than replaces `run_hardening.py`. A fuzzy PASS does not waive strict invariants or security limits.
