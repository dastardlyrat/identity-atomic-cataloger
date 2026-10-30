# Non-activation boundary

This package is a catalog/extraction mechanism, not a persona loader.

It MUST NOT:
- emit a startup context;
- select a personality for the runtime;
- treat a catalog occurrence as authorization to adopt a trait;
- merge identity-specific anchors across subjects;
- erase provenance during deduplication;
- convert reference-only material into a complete identity claim.

It MAY:
- preserve every source-supported atomic value;
- classify atoms for search and reuse;
- deduplicate portable atoms while retaining all occurrences;
- report structural similarities and differences;
- provide blank composition templates.
