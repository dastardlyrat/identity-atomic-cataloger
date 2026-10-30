"""Explicit, non-activating composition of two approved Desktop source records.

The extractor remains unchanged. Only pinned archive members are admitted;
candidate definitions are rebuilt from selected atoms, never loaded as roles.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from identity_atomic.cataloger import (  # noqa: E402
    canonical_json, catalog_directory, classify, file_kind, inspect_zip, iter_leaves, merge_reusable,
    normalize, parse_semantic_json, validate_catalog_internal,
)

ARTIFACT = "IDENTITY_PROTOCOL_BACKEND_TWO_IDENTITIES_v1.1.1.zip"
ARCHIVE_SHA256 = "89d49088e4a97dc23e0ba535729154f586bc8c87dadb0e4c650ca022a7684a9c"
PREFIX = "IDENTITY_PROTOCOL_BACKEND_TWO_IDENTITIES_v1.1.1/"
SNAPSHOTS = "source_records/desktop_ipb"
SHARED = "catalogs/ipb_shared_control_atomic_catalog.json"
PINNED = {
    "source_records/vera_sol_identity_v2.0.0.json": "d2ad13051ead83f8b600c30d9e8e6eef91ebbb31ca7316c234b1dec5bc9e40c4",
    "source_records/lattice_identity_v0.2.0.json": "6b29f58faf12faff13a348e3ac04c53034c1fb148d6910ec7661bac5df0867d2",
    "config/identities/vera_sol.json": "8c8188bdd5dc5a96599837c92751a1b605880164d4fb1bc8c6e600687ea8437a",
    "config/identities/lattice.json": "5347622dc0ef6750e79c04b15a7036c8d7c621e5a8628363efe8d9e1de77a5e8",
    "config/runtime_profiles/vera_sol.json": "7794877e613125b64bfdf2843384a49158be8b8022a232e3228096804d25d11a",
    "config/runtime_profiles/lattice.json": "57c8415569e9d7c84d3792e54424d898b403d5023832177e161d66d990ed1477",
    "config/shared_protocol.json": "b2612beaf3c31c9591647370d6f8e6130dfb377f8bdc15f37bb78099f6977e8e",
    "data/provenance_correction_v2.json": "801e52ab91a1bbe9e82fa44c13779db85bccd051537ae7dc30d1d09c2f886fd8",
}
IDENTITIES = {
    "lattice": ("Lattice", "source_records/lattice_identity_v0.2.0.json"),
    "vera_sol": ("Vera Sol", "source_records/vera_sol_identity_v2.0.0.json"),
}
RUNTIME_STATUS = "HISTORICAL_REFERENCE_NOT_CURRENT_CAPABILITIES"
AUTHORITY = "User-approved source-derived composition; no runtime activation."


class CompositionError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise CompositionError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def dump(obj):
    return (json.dumps(obj, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def artifact_info():
    return {"name": ARTIFACT, "version": "1.1.1", "sha256": ARCHIVE_SHA256,
            "coverage": "SELECTED_RECORDS_ONLY", "completeness": "PARTIAL_SOURCE_PRESENT"}


def catalog_path(identity):
    return f"catalogs/{identity}_desktop_atomic_catalog.json"


def groups():
    result = {}
    for identity, (name, source) in IDENTITIES.items():
        result[catalog_path(identity)] = (name, [source, f"config/identities/{identity}.json",
                                                  f"config/runtime_profiles/{identity}.json"])
    result[SHARED] = ("IPB Shared Control", ["config/shared_protocol.json", "data/provenance_correction_v2.json"])
    return result


def checked_records(records):
    require(set(records) == set(PINNED), "Exactly the eight approved records are required")
    docs = {}
    private = re.compile(r"(?:[A-Za-z]:[\\/]+Users[\\/]|/(?:home|Users|mnt/data)/|"
                         r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b)")
    for name, expected in PINNED.items():
        require(digest(records[name]) == expected, f"Pinned source hash mismatch: {name}")
        doc = parse_semantic_json(records[name])
        require(isinstance(doc, dict), f"Expected a source object: {name}")
        require(not private.search(canonical_json(doc)), f"Privacy review required: {name}")
        docs[name] = doc
    return docs


def read_archive(path):
    require(inspect_zip(path)["sha256"] == ARCHIVE_SHA256, "Archive fingerprint differs from approved source")
    with zipfile.ZipFile(path) as archive:
        records = {name: archive.read(PREFIX + name) for name in PINNED}
    checked_records(records)
    return records


def load_snapshots(root=ROOT):
    root = Path(root).resolve()
    records = {}
    for name in PINNED:
        path = root / SNAPSHOTS / name
        require(path.resolve().is_relative_to(root) and not path.is_symlink(), "Unsafe snapshot path")
        records[name] = path.read_bytes()
    checked_records(records)
    return records


def make_catalogs(records):
    checked_records(records)
    temporary_root = ROOT / "tmp"
    temporary_root.mkdir(exist_ok=True)
    require(temporary_root.resolve().is_relative_to(ROOT.resolve()), "Unsafe temporary root")
    temporary = tempfile.TemporaryDirectory(prefix="desktop-build-", dir=temporary_root)
    work = Path(temporary.name).resolve()
    require(work.is_relative_to(temporary_root.resolve()), "Unsafe temporary directory")
    try:
        catalogs = {}
        for index, (path, (subject, names)) in enumerate(groups().items()):
            directory = work / str(index)
            for name in names:
                target = directory / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(records[name])
            catalogs[path] = catalog_directory(
                directory, artifact=ARTIFACT, artifact_version="1.1.1",
                artifact_sha256=ARCHIVE_SHA256, subject=subject,
                completeness="PARTIAL_SOURCE_PRESENT")
        return catalogs
    finally:
        require(work.is_relative_to(temporary_root.resolve()), "Unsafe cleanup target")
        temporary.cleanup()


def resolve(document, pointer):
    if pointer == "":
        return document
    require(pointer.startswith("/") and not re.search(r"~(?![01])", pointer), "Invalid JSON Pointer")
    current = document
    for token in pointer[1:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            require(bool(re.fullmatch(r"0|[1-9][0-9]*", token)), "Invalid array index")
            current = current[int(token)]
        else:
            current = current[token]
    return current


def leaf_items(document, prefix=""):
    root_leaf = not isinstance(document, (dict, list)) or not document
    return [(prefix if root_leaf else prefix + pointer, value)
            for pointer, value in iter_leaves(document)]


def component_specs(identity, docs):
    require(identity in IDENTITIES, "Unapproved identity")
    config = f"config/identities/{identity}.json"
    correction = "data/provenance_correction_v2.json"
    return [
        ("/identity_id", catalog_path(identity), config, "/identity_id"),
        ("/identity_record", catalog_path(identity), config, ""),
        ("/source_profile", catalog_path(identity), IDENTITIES[identity][1], ""),
        ("/runtime_reference/profile", catalog_path(identity), f"config/runtime_profiles/{identity}.json", ""),
        ("/control_protocol", SHARED, "config/shared_protocol.json", ""),
        ("/design_provenance", SHARED, correction, f"/identity_design_model/{identity}"),
        ("/provenance_correction_id", SHARED, correction, "/correction_id"),
    ]


def index_atoms(catalogs, records):
    docs = checked_records(records)
    require(set(catalogs) == set(groups()), "Unexpected catalog set")
    index = {}
    for path, (subject, names) in groups().items():
        catalog = catalogs[path]
        require(not validate_catalog_internal(catalog), f"Invalid catalog: {path}")
        require(catalog["subject"] == subject and catalog["source_artifact"] == ARTIFACT
                and catalog["source_version"] == "1.1.1" and catalog["source_artifact_sha256"] == ARCHIVE_SHA256
                and catalog["source_digest_kind"] == "PROVIDED_ARTIFACT_SHA256" and not catalog["errors"],
                "Catalog identity or provenance mismatch")
        require(catalog["source_completeness"] == "PARTIAL_SOURCE_PRESENT", "Unsupported coverage claim")
        expected = {(name, pointer): value for name in names for pointer, value in leaf_items(docs[name])}
        actual = {}
        for atom in catalog["atoms"]:
            source = atom["source"]
            key = (source["file"], source["json_pointer"])
            require(key in expected and key not in actual, "Unexpected or duplicated source leaf")
            require(atom["subject"] == subject and source["artifact"] == ARTIFACT and source["artifact_version"] == "1.1.1"
                    and source["artifact_sha256"] == ARCHIVE_SHA256
                    and source["file_sha256"] == PINNED[source["file"]]
                    and source["source_kind"] == file_kind(source["file"])
                    and source["completeness"] == "PARTIAL_SOURCE_PRESENT", "Atom provenance mismatch")
            require(canonical_json(atom["value"]) == canonical_json(expected[key]), "Atom differs from pinned source")
            require((atom["atom_type"], atom["reuse_class"], atom["portable"])
                    == classify(source["file"], source["json_pointer"], atom["value"])
                    and atom["normalized_value"] == normalize(atom["value"]), "Derived indexing metadata mismatch")
            actual[key] = atom
        require(set(actual) == set(expected), "Incomplete source-leaf coverage")
        index[path] = actual
    return docs, index


def selection_row(target, catalog, atom):
    return {"target_pointer": target, "catalog": catalog, "atom_id": atom["atom_id"],
            "source_file": atom["source"]["file"], "source_pointer": atom["source"]["json_pointer"],
            "canonical_value_sha256": atom["canonical_value_sha256"]}


def catalog_refs(identity, catalogs):
    return [{"path": path, "sha256": digest(dump(catalogs[path])), "subject": catalogs[path]["subject"]}
            for path in [catalog_path(identity), SHARED]]


def compose(identity, catalogs, records):
    docs, index = index_atoms(catalogs, records)
    definition = {"schema": "source_composed_agent_definition", "schema_version": "0.1",
                  "build_status": "candidate", "activation_semantics": "DEFINITION_ONLY",
                  "source_artifact": artifact_info(), "selection_manifest": f"agents/{identity}/selection.json"}
    selections = []

    def rebuild(value, source_pointer, target_pointer, catalog, source_file):
        if isinstance(value, dict) and value:
            return {key: rebuild(child, source_pointer + "/" + key.replace("~", "~0").replace("/", "~1"),
                                 target_pointer + "/" + key.replace("~", "~0").replace("/", "~1"), catalog, source_file)
                    for key, child in value.items()}
        if isinstance(value, list) and value:
            return [rebuild(child, source_pointer + f"/{i}", target_pointer + f"/{i}", catalog, source_file)
                    for i, child in enumerate(value)]
        atom = index[catalog][(source_file, source_pointer or "/")]
        selections.append(selection_row(target_pointer, catalog, atom))
        return copy.deepcopy(atom["value"])

    for target, catalog, name, pointer in component_specs(identity, docs):
        value = rebuild(resolve(docs[name], pointer), pointer, target, catalog, name)
        if target == "/runtime_reference/profile":
            definition["runtime_reference"] = {"status": RUNTIME_STATUS, "profile": value}
        else:
            definition[target[1:]] = value
    selection = {"schema": "agent_atom_selection", "schema_version": "0.1", "identity_id": identity,
                 "build_status": "candidate", "activation_semantics": "DEFINITION_ONLY",
                 "composition_authority": AUTHORITY, "source_artifact": artifact_info(),
                 "catalogs": catalog_refs(identity, catalogs),
                 "selections": sorted(selections, key=lambda row: row["target_pointer"])}
    verify_definition(definition, selection, catalogs, records)
    return definition, selection


def verify_definition(definition, selection, catalogs, records):
    """Independently check every target leaf against a pinned source occurrence."""
    docs, index = index_atoms(catalogs, records)
    identity = definition.get("identity_id")
    require(identity in IDENTITIES, "Unapproved identity")
    expected_keys = {"schema", "schema_version", "build_status", "activation_semantics", "source_artifact",
                     "selection_manifest", "identity_id", "identity_record", "source_profile",
                     "runtime_reference", "control_protocol", "design_provenance", "provenance_correction_id"}
    require(set(definition) == expected_keys, "Unexpected definition fields")
    require(definition["schema"] == "source_composed_agent_definition" and definition["schema_version"] == "0.1"
            and definition["build_status"] == "candidate" and definition["activation_semantics"] == "DEFINITION_ONLY",
            "Definition status or activation semantics changed")
    require(definition["source_artifact"] == artifact_info()
            and definition["selection_manifest"] == f"agents/{identity}/selection.json", "Definition build metadata mismatch")
    require(set(definition["runtime_reference"]) == {"status", "profile"}
            and definition["runtime_reference"]["status"] == RUNTIME_STATUS, "Historical runtime reference promoted")
    require(set(selection) == {"schema", "schema_version", "identity_id", "build_status", "activation_semantics",
                              "composition_authority", "source_artifact", "catalogs", "selections"}, "Unexpected selection fields")
    require(selection["schema"] == "agent_atom_selection" and selection["schema_version"] == "0.1"
            and selection["identity_id"] == identity and selection["build_status"] == "candidate"
            and selection["activation_semantics"] == "DEFINITION_ONLY"
            and selection["composition_authority"] == AUTHORITY
            and selection["source_artifact"] == artifact_info()
            and selection["catalogs"] == catalog_refs(identity, catalogs), "Selection metadata mismatch")
    expected_rows = {}
    for target, catalog, name, pointer in component_specs(identity, docs):
        source_component = resolve(docs[name], pointer)
        require(canonical_json(resolve(definition, target)) == canonical_json(source_component),
                f"Component differs from selected source: {target}")
        for relative, _ in leaf_items(source_component):
            root_leaf = not isinstance(source_component, (dict, list)) or not source_component
            source_pointer = pointer if root_leaf else pointer + relative
            target_pointer = target if root_leaf else target + relative
            atom = index[catalog][(name, source_pointer or "/")]
            expected_rows[target_pointer] = selection_row(target_pointer, catalog, atom)
    rows = selection["selections"]
    require(isinstance(rows, list) and len(rows) == len(expected_rows), "Missing or duplicated selections")
    require([row["target_pointer"] for row in rows] == sorted(expected_rows), "Selection targets differ or repeat")
    require(all(row == expected_rows[row["target_pointer"]] for row in rows), "Selection crosses a source or identity boundary")
    require(definition["identity_record"]["identity_id"] == identity
            and definition["runtime_reference"]["profile"]["identity_id"] == identity, "Identity anchor mismatch")
    return True


def build_artifacts(records):
    docs = checked_records(records)
    catalogs = make_catalogs(records)
    outputs = {f"{SNAPSHOTS}/{name}": data for name, data in records.items()}
    source_manifest = {"schema": "selected_desktop_source_manifest", "schema_version": "0.1",
                       "source_artifact": artifact_info(), "selected_json_records": len(records),
                       "source_members": [{"archive_member": PREFIX + name, "repository_path": f"{SNAPSHOTS}/{name}",
                                           "sha256": PINNED[name], "bytes": len(records[name])} for name in sorted(records)]}
    outputs[f"{SNAPSHOTS}/SOURCE_MANIFEST.json"] = dump(source_manifest)
    outputs.update({path: dump(catalog) for path, catalog in catalogs.items()})
    outputs["catalogs/desktop_reusable_atom_dictionary.json"] = dump(merge_reusable(catalogs.values()))
    agents = []
    for identity, (name, _) in IDENTITIES.items():
        definition, selection = compose(identity, catalogs, records)
        outputs[f"agents/{identity}/definition.json"] = dump(definition)
        outputs[f"agents/{identity}/selection.json"] = dump(selection)
        version = definition["identity_record"]["identity_version"]
        readme = (f"# {name} - source-composed candidate\n\n"
                  f"[Definition](definition.json) | [Atom selection](selection.json) | [Build manifest](../BUILD_MANIFEST.json)\n\n"
                  f"Identity source version: `{version}`. Build schema: `0.1`. Status: **candidate**, `DEFINITION_ONLY`.\n\n"
                  "This artifact reconstructs the selected identity record and fuller source profile from atoms, "
                  "attaches the explicitly selected IPB control protocol, and applies the source's corrected "
                  "user-design provenance. Original source assertions are retained as data, including any "
                  "nested historical `current` or `active` labels. They do not promote this candidate or activate it.\n\n"
                  "The runtime profile is historical reference data, not a current capability declaration. "
                  "Origin, action, and validation states remain separate. Prose principles remain source text; "
                  "this build does not infer executable logic or enforce those principles at runtime.\n\n"
                  f"Every component leaf has a source occurrence in [its catalog](../../{catalog_path(identity)}) "
                  f"or the [shared-control catalog](../../{SHARED}). The selection contains {len(selection['selections'])} "
                  "explicit target mappings. Source coverage is complete for selected records and partial for "
                  "the backend archive and wider identity history.\n")
        outputs[f"agents/{identity}/README.md"] = readme.encode("utf-8")
        agents.append({"identity_id": identity, "name": name, "definition": f"agents/{identity}/definition.json",
                       "selection": f"agents/{identity}/selection.json", "selected_targets": len(selection["selections"])})
    manifest = {"schema": "desktop_identity_build_manifest", "schema_version": "0.1",
                "build_id": "desktop-ipb-lattice-vera-v1", "build_status": "candidate",
                "activation_semantics": "DEFINITION_ONLY", "source_artifact": artifact_info(),
                "extractor_version": "0.3.0", "composition_authority": AUTHORITY,
                "implementation": {"builder_sha256": digest(Path(__file__).read_bytes()),
                                   "extractor_sha256": digest((ROOT / "src/identity_atomic/cataloger.py").read_bytes())},
                "catalogs": [{"path": path, "subject": cat["subject"], "atoms": cat["summary"]["atoms"],
                              "portable_atoms": cat["summary"]["portable_atoms"]} for path, cat in catalogs.items()],
                "agents": agents,
                "outputs": [{"path": path, "sha256": digest(data), "bytes": len(data)} for path, data in sorted(outputs.items())]}
    outputs["agents/BUILD_MANIFEST.json"] = dump(manifest)
    return outputs


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, help="Use the approved original ZIP instead of retained source snapshots")
    parser.add_argument("--check", action="store_true", help="Compare a deterministic rebuild without writing generated artifacts")
    args = parser.parse_args(argv)
    records = read_archive(args.archive) if args.archive else load_snapshots()
    outputs = build_artifacts(records)
    for relative, data in outputs.items():
        path = ROOT / relative
        require(path.resolve().is_relative_to(ROOT.resolve()) and not path.is_symlink(), "Unsafe output path")
        if args.check:
            require(path.is_file() and path.read_bytes() == data, f"Rebuild mismatch: {relative}")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
    print(json.dumps({"status": "verified" if args.check else "built", "artifacts": len(outputs),
                      "identities": list(IDENTITIES), "activation_semantics": "DEFINITION_ONLY"}))


if __name__ == "__main__":
    main()
