# Lattice - source-composed candidate

[Definition](definition.json) | [Atom selection](selection.json) | [Build manifest](../BUILD_MANIFEST.json)

Identity source version: `0.2.0`. Build schema: `0.1`. Status: **candidate**, `DEFINITION_ONLY`.

This artifact reconstructs the selected identity record and fuller source profile from atoms, attaches the explicitly selected IPB control protocol, and applies the source's corrected user-design provenance. Original source assertions are retained as data, including any nested historical `current` or `active` labels. They do not promote this candidate or activate it.

The runtime profile is historical reference data, not a current capability declaration. Origin, action, and validation states remain separate. Prose principles remain source text; this build does not infer executable logic or enforce those principles at runtime.

Every component leaf has a source occurrence in [its catalog](../../catalogs/lattice_desktop_atomic_catalog.json) or the [shared-control catalog](../../catalogs/ipb_shared_control_atomic_catalog.json). The selection contains 175 explicit target mappings. Source coverage is complete for selected records and partial for the backend archive and wider identity history.
