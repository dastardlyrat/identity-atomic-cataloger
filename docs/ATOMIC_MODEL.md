# Atomic identity model

The extractor decomposes source JSON into leaf atoms. Each atom is independent and carries:

- stable catalog identifier;
- subject;
- semantic atom type;
- reuse classification;
- portable/non-portable flag;
- exact typed source value;
- normalized value for deduplication;
- artifact/file hash provenance;
- exact JSON Pointer;
- source completeness state;
- `CATALOG_ONLY` activation semantics.

## Reusable domains

1. **Identity anchors** — canonical name, machine ID, namespace. Usually identity-specific and non-portable.
2. **Identity class/boundaries** — machine class, personhood/sentience/autonomy/fusion claims.
3. **Role** — primary roles and assistant roles.
4. **Authority** — who may decide, authorize, modify canon, or cross a gate.
5. **Behavior** — temperament, interaction rules, operating preferences, doctrines, invariants, prohibitions.
6. **Relationships** — parents, peers, lineage, return targets. Usually source-specific.
7. **Control** — states, triggers, phases, transition rules, closure rules.
8. **Epistemics/validation** — evidence, inference, verification, confidence, unknown-state discipline.
9. **Recovery** — rollback, known-good-state, failure containment, recoverability.
10. **Lifecycle/gates** — staged/production/locked states and promotion boundaries.
11. **Provenance/attestation** — artifacts, hashes, source roles, attestations. Evidence metadata rather than personality.

The catalog does not flatten these domains into a new personality. Reuse requires a separate explicit selection or composition step.
