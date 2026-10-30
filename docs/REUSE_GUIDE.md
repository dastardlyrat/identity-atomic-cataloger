# Reuse guide

Recommended reuse workflow:

1. Select atoms by `atom_type`, `reuse_class`, or explicit `atom_id`.
2. Reject identity-specific anchors unless intentionally creating a derivative with documented lineage.
3. Preserve every selected atom's source occurrence list.
4. Resolve conflicts explicitly; do not silently pick one source value.
5. Record composition authority separately from source authority.
6. Produce a new identity artifact only in a separate composition step.
7. Validate that the resulting identity does not imply source identity fusion.

The core converter does not automatically compose identities. The separate
`tools/build_desktop_agents.py` build performs explicit, source-derived
composition for the approved Lattice and Vera Sol records. Its candidates,
selection manifests, source snapshots, and build hashes are available under
`agents/` and `source_records/desktop_ipb/`. New source sets or composition rules
need their own selection and provenance decisions. Runtime activation remains
separate from producing definition artifacts.
