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

The separate `tools/build_desktop_agents.py` step may compose candidate
definition artifacts from the eight explicitly selected Desktop records.
Its selection manifests map every component leaf to an exact source occurrence.
The candidate artifacts remain `DEFINITION_ONLY`; they do not select a runtime
identity, emit startup contexts, grant capabilities, or execute their rules.
Historical runtime records and original source status labels remain data.
