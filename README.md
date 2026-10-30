# Identity Atomic Cataloger / Extractor v0.3.0

A Python toolkit for inspecting identity and personality artifacts as records
with explicit provenance. It reads JSON from a directory or ZIP archive,
produces one catalog atom per source-supported leaf value, and can merge
portable atoms into a reusable dictionary without losing their occurrences.

The mechanism is **non-activating**. A catalog entry records a source assertion;
it does not tell a model to adopt a personality, grant authority, or load a
startup context. Every atom retains `CATALOG_ONLY` activation semantics.

The named examples retain **Lattice, Vesper, Vera Sol, and Corda**. Source
spellings, typed values, source locators, hashes, and completeness labels are
preserved. The core converter performs structured decomposition for identity,
control, and agency records. A separate, explicit Desktop-source builder now
assembles candidate Lattice and Vera Sol definitions from selected atoms.
Original personality archives and startup-context loaders are not included.

## Lattice and Vera Sol Desktop build

The [build manifest](agents/BUILD_MANIFEST.json) records an explicit composition
from eight pinned JSON members of `IDENTITY_PROTOCOL_BACKEND_TWO_IDENTITIES_v1.1.1.zip`.
The reviewed [source snapshots](source_records/desktop_ipb/SOURCE_MANIFEST.json)
retain the original member bytes and hashes. The source ZIP stays outside Git.

| Output | Source scope | Result |
| --- | --- | --- |
| [Lattice atomic catalog](catalogs/lattice_desktop_atomic_catalog.json) | Lattice v0.2.0 source record, identity configuration, and historical runtime profile | 77 atoms. |
| [Vera Sol atomic catalog](catalogs/vera_sol_desktop_atomic_catalog.json) | Vera Sol v2.0.0 source record, identity configuration, and historical runtime profile | 77 atoms. |
| [Shared-control catalog](catalogs/ipb_shared_control_atomic_catalog.json) | IPB shared protocol and provenance correction `IPB-PROV-CORR-002` | 125 atoms. |
| [Desktop reusable dictionary](catalogs/desktop_reusable_atom_dictionary.json) | Exact portable values from these three catalogs | 24 unique atoms, 35 occurrences. |
| [Lattice candidate](agents/lattice/README.md) | Own identity/profile, selected shared control, corrected design provenance, and historical runtime reference | [Definition](agents/lattice/definition.json) and [175 target mappings](agents/lattice/selection.json). |
| [Vera Sol candidate](agents/vera_sol/README.md) | The same explicit component structure, with Vera Sol's own records | [Definition](agents/vera_sol/definition.json) and [175 target mappings](agents/vera_sol/selection.json). |

The candidate definitions reconstruct complete selected records, including
principles and traits omitted by the earlier eight-field example exports.
Their coverage is **partial for the backend archive and wider identity history**.
The original reference catalogs below remain unchanged and describe a different
source set; the new catalogs do not replace or upgrade those old coverage claims.

Each definition has `build_status: candidate` and `activation_semantics: DEFINITION_ONLY`.
Nested source labels such as `current` or `active` remain historical assertions,
not promotion of these builds. Runtime capabilities stay in a separately labeled
historical reference. The definitions preserve the source's declared control
protocol and separate origin, action, and validation states. Prose principles
remain source text; this build does not infer executable rules or run an agent.

The newer provenance correction records user design/authorship of the identities
separately from assistant implementation of artifacts. The source identity
packet metadata is retained alongside that correction, without silent rewriting.

Rebuild from the retained snapshots or verify deterministic output:

```powershell
.\.venv\Scripts\python.exe -B -X utf8 tools/build_desktop_agents.py
.\.venv\Scripts\python.exe -B -X utf8 tools/build_desktop_agents.py --check
.\.venv\Scripts\python.exe -B -X utf8 -m unittest discover -s tests -p test_desktop_composition.py -v
```

The builder is limited to this approved source fingerprint and explicit component
selection. It preserves exact values and proves every component leaf against a
pinned source occurrence. It rejects missing/duplicated selections, foreign
identity occurrences, altered source values, false provenance, and promoted
runtime or activation claims. It does not load definitions into this chat or a host.

## What the cataloger preserves

| Evidence | Purpose |
| --- | --- |
| Exact typed `value` and its canonical SHA-256 | Distinguish actual source values, including meaningful whitespace or Unicode differences. |
| `normalized_value` | Support search; normalization does not establish exact identity. |
| Artifact and file hashes, relative file path, and JSON Pointer | Locate the assertion and bind an atom to its recorded provenance. |
| Derived atom type, reuse class, and portability | Organize search and selection while keeping source values authoritative. |
| Source completeness and reference-only status | Keep a supported reference separate from a complete identity claim. |
| Occurrence lists in the reusable dictionary | Retain every contributing source when exact portable values are deduplicated. |

The source flow is: inspect the archive or directory, parse semantic JSON,
walk its leaves, attach provenance and indexing metadata, verify the catalog,
and optionally merge exact portable values. Reuse requires a separate explicit
selection step. See the [atomic model](docs/ATOMIC_MODEL.md),
[non-activation boundary](docs/NON_ACTIVATION_BOUNDARY.md), and
[reuse guide](docs/REUSE_GUIDE.md).

## Included catalogs

| File | Scope carried by the supplied package |
| --- | --- |
| [Vesper](catalogs/vesper_atomic_catalog.json) | 159 atoms, including 84 portable atoms. |
| [Corda](catalogs/corda_atomic_catalog.json) | 679 atoms, including 331 portable atoms. |
| [Vera Sol references](catalogs/vera_sol_reference_catalog.json) | Source-supported references; `REFERENCE_ONLY`, with no complete identity claim. |
| [Lattice references](catalogs/lattice_reference_catalog.json) | Source-supported references; `REFERENCE_ONLY`, with no complete identity claim. |
| [Reusable dictionary](catalogs/reusable_atom_dictionary.json) | 308 unique portable atoms and 415 contributing occurrences from Vesper and Corda. |
| [Structure templates](catalogs/structure_templates.json) | Decomposition domains and field shapes for explicit reuse. |
| [Source index](catalogs/source_index.json) | Artifact names, recorded fingerprints, and source-completeness declarations. |

`COMPLETE_SOURCE_PRESENT` labels are retained from the supplied catalogs as
records of their original cataloging inputs. The corresponding source ZIPs
are not included in this repository, and this repository preparation does not
independently re-verify those archives. Vera Sol and Lattice remain
reference-only; their references are not promoted to full personality catalogs.

## Install and run

Use Python **3.10 or newer** in a virtual environment. The runtime mechanism
uses the Python standard library. The optional test extra supplies the JSON
Schema validation dependency.

For PowerShell on Windows:

```powershell
git clone https://github.com/dastardlyrat/identity-atomic-cataloger.git
cd identity-atomic-cataloger
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install ".[test]"
.\.venv\Scripts\python.exe -m identity_atomic --help
```

The repository is private; cloning requires an account with access. On other
platforms, use the equivalent Python executable inside the virtual environment.

### Catalog a supplied source

Place an input archive under `private-inputs/` and create a separate output
folder. The examples below use generic artifact and identity labels:

```powershell
New-Item -ItemType Directory -Force generated | Out-Null
.\.venv\Scripts\python.exe -m identity_atomic catalog private-inputs/source.zip --artifact ExampleArtifact --version 1.0.0 --subject ExampleIdentity -o generated/catalog.json
```

A directory can be supplied instead of a ZIP. ZIP sources use the archive's
SHA-256; directory sources receive a canonical tree digest unless an artifact
hash is explicitly supplied through the library API. Inspection and cataloging
do not execute source artifacts.

Parsing fails closed by default. `--allow-json-errors` records parse errors
while retaining valid material; it does not automatically infer source
completeness. Supply an appropriate `--completeness` value and inspect the
returned `errors` and summary when working with partial sources.

### Verify and merge

```powershell
.\.venv\Scripts\python.exe -m identity_atomic verify generated/catalog.json
.\.venv\Scripts\python.exe -m identity_atomic merge catalogs/vesper_atomic_catalog.json catalogs/corda_atomic_catalog.json -o generated/reusable_atoms.json
.\.venv\Scripts\python.exe -m identity_atomic verify generated/reusable_atoms.json
```

The `verify` command checks internal invariants for atomic catalogs and reusable
atom dictionaries. It does not establish authorship, rights, truth of source
assertions, or possession of the original archives. Reference catalogs,
structure templates, and candidate definitions use separate document shapes
and are not supported by this CLI verification command. Verify the candidate
definitions and their selections with `tools/build_desktop_agents.py --check`.

## Privacy and distribution boundary

All supplied project files and decoded JSON values were reviewed for personal
contact details, user paths, credentials, and private human identity linkages.
No such information was identified in this preparation. The named machine
identities and their source-supported relationships are intentionally retained.
The original seven catalog JSON files, original schemas, and core mechanism
remain unchanged. New source snapshots, catalogs, definition/selection schemas,
and the separate composition builder are included for the Desktop build.

This preparation does **not** turn the extractor into an automatic anonymizer.
New inputs may contain personal names, addresses, credentials, private paths,
or confidential assertions. Those values can appear in output atoms and their
source locators. Review both input content and generated catalogs before sharing.

The [.gitignore](.gitignore) excludes virtual environments, Python caches, source
ZIPs, local secrets, and designated private-input, generated-output, report, and
temporary directories. Keep private source material in those directories;
ignore rules cannot identify every form of sensitive content. Copyright and
attribution notices remain part of their source material.

Source hashes, JSON Pointers, and exact values are linked by the model. A later
redaction needs its own documented provenance decision; changing a value while
retaining its former hash would create an invalid record. Keep an original and
a redacted derivative distinct when preparing a new distribution.

## Validation and current limits

The [validation report](VALIDATION.txt) preserves the original release results
and appends the current repository-preparation run. The current checks are:

| Check | Current result |
| --- | --- |
| Existing unit checks | 7/7 pass. |
| Fuzzy seed `260929`, 256 iterations | 29 pass, zero warnings or failures. |
| Fuzzy seed `99173`, 256 iterations | 29 pass, zero warnings or failures. |
| JSON Schema checks | Three schema documents and the Vesper, Corda, and reusable catalog documents pass. |
| Python syntax and CLI help | Pass. |
| Desktop composition checks | 12/12 pass, including schema checks, deterministic builds, full selected-record reconstruction, and adversarial selection/provenance checks. |
| Native Windows hardening harness | Incomplete: the directory-symlink fixture cannot be created in this session (`WinError 1314`). A fresh 32/32 pass is not claimed. |

Run the existing suites with UTF-8 mode enabled:

```powershell
.\.venv\Scripts\python.exe -B -X utf8 tests/test_cataloger.py
.\.venv\Scripts\python.exe -B -X utf8 harness/run_hardening.py
.\.venv\Scripts\python.exe -B -X utf8 harness/run_fuzzy.py --seed 260929 --iterations 256
.\.venv\Scripts\python.exe -B -X utf8 harness/run_fuzzy.py --seed 99173 --iterations 256
```

The hardening harness needs an environment able to create native symbolic
links. It stops while constructing that fixture on this Windows session;
remaining checks are not reported as completed. The original harness is
preserved. See the [hardening model](docs/HARDENING.md) and
[fuzzy testing guide](docs/FUZZY_TESTING.md) for their separate proof boundaries.
The [checksum manifest](CHECKSUMS.sha256) covers repository content other than
itself, excluding local test environments and generated files.

## Source map and contributor entry points

| Location | Responsibility |
| --- | --- |
| [cataloger.py](src/identity_atomic/cataloger.py) | Strict JSON parsing, archive and directory inspection, leaf extraction, classification, exact-value merging, and invariant checks. |
| [cli.py](src/identity_atomic/cli.py) | `catalog`, `merge`, and `verify` command handling. |
| [Schemas](schemas/identity_atom.schema.json) | Atom contracts and associated catalog/dictionary schemas in the same directory. |
| [Unit checks](tests/test_cataloger.py) | Focused checks for pointers, types, normalization, and supplied catalog invariants. |
| [Hardening harness](harness/run_hardening.py) | Hostile archives, source-tree handling, schemas, and deliberately corrupted validator inputs. |
| [Fuzzy harness](harness/run_fuzzy.py) | Seeded serialization, packaging, randomized-tree, and semantic near-miss checks. |
| [Blank selection blueprint](examples/blank_identity_blueprint.json) | Explicit atom selection without automatic personality assembly. |
| [Package metadata](PACKAGE.json) | Supplied catalog counts, version, and historical validation metadata. |
| [Desktop builder](tools/build_desktop_agents.py) | Pinned member selection, unchanged-core decomposition, explicit candidate composition, and deterministic rebuild checks. |
| [Composition checks](tests/test_desktop_composition.py) | Component reconstruction, source/identity isolation, artifact tampering, and candidate/runtime boundaries. |

When changing extraction or classification, use the documented atomic model and
source evidence as the basis. Preserve typed values and provenance, and keep
search normalization separate from exact-value identity. Validate intentional
catalog changes and refresh the checksum manifest together. Do not interpret
cataloged authority text as permission to execute or activate it.

No standalone project license file is currently included.
