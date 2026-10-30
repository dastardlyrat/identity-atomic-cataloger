"""Checks for explicit source composition; these tests never activate an agent."""
from pathlib import Path
import copy
import importlib.util
import json
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("desktop_builder", ROOT / "tools/build_desktop_agents.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)
from identity_atomic.cataloger import build_atom, canonical_json, validate_catalog_internal


class DesktopCompositionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = builder.load_snapshots(ROOT)
        cls.artifacts = builder.build_artifacts(cls.records)
        cls.catalogs = {path: json.loads(cls.artifacts[path]) for path in builder.groups()}

    def state(self, identity="lattice"):
        return (json.loads(self.artifacts[f"agents/{identity}/definition.json"]),
                json.loads(self.artifacts[f"agents/{identity}/selection.json"]),
                copy.deepcopy(self.catalogs))

    def test_schema_contracts(self):
        from jsonschema import Draft202012Validator
        from referencing import Registry, Resource
        schemas = [json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8")) for name in
                   ["identity_atom.schema.json", "atomic_identity_catalog.schema.json",
                    "reusable_identity_atom_dictionary.schema.json", "source_composed_agent_definition.schema.json",
                    "agent_atom_selection.schema.json"]]
        for schema in schemas:
            Draft202012Validator.check_schema(schema)
        registry = Registry().with_resources([(schema["$id"], Resource.from_contents(schema)) for schema in schemas])
        validators = {schema["$id"]: Draft202012Validator(schema, registry=registry) for schema in schemas}
        for catalog in self.catalogs.values():
            validators["atomic_identity_catalog.schema.json"].validate(catalog)
        validators["reusable_identity_atom_dictionary.schema.json"].validate(
            json.loads(self.artifacts["catalogs/desktop_reusable_atom_dictionary.json"]))
        for identity in builder.IDENTITIES:
            definition, selection, _ = self.state(identity)
            validators["source_composed_agent_definition.schema.json"].validate(definition)
            validators["agent_atom_selection.schema.json"].validate(selection)

    def test_complete_source_components_and_state_separation(self):
        docs = builder.checked_records(self.records)
        for identity in builder.IDENTITIES:
            definition, selection, catalogs = self.state(identity)
            self.assertTrue(builder.verify_definition(definition, selection, catalogs, self.records))
            self.assertEqual(definition["source_profile"], docs[builder.IDENTITIES[identity][1]])
            self.assertEqual(definition["identity_record"], docs[f"config/identities/{identity}.json"])
            self.assertEqual(definition["control_protocol"], docs["config/shared_protocol.json"])
            self.assertEqual(definition["design_provenance"],
                             docs["data/provenance_correction_v2.json"]["identity_design_model"][identity])
            self.assertEqual(definition["runtime_reference"]["status"], builder.RUNTIME_STATUS)
            self.assertEqual(definition["build_status"], "candidate")
            self.assertEqual(definition["activation_semantics"], "DEFINITION_ONLY")
        lattice, _, _ = self.state()
        vera, _, _ = self.state("vera_sol")
        self.assertEqual(len(lattice["source_profile"]["operating_principles"]), 8)
        self.assertEqual(len(vera["source_profile"]["core_operating_traits"]), 8)
        self.assertNotEqual(lattice["control_protocol"]["action_state"], lattice["control_protocol"]["validation_state"])

    def test_deterministic_rebuild(self):
        self.assertEqual(self.artifacts, builder.build_artifacts(self.records))

    def test_reject_changed_source_bytes(self):
        records = self.records.copy()
        name = builder.IDENTITIES["lattice"][1]
        records[name] = records[name].replace(b'"Lattice"', b'"Altered"', 1)
        with self.assertRaises(builder.CompositionError):
            builder.build_artifacts(records)

    def test_reject_even_internally_valid_atom_forgery(self):
        definition, selection, catalogs = self.state()
        row = next(row for row in selection["selections"] if row["target_pointer"] == "/identity_record/canonical_name")
        catalog = catalogs[row["catalog"]]
        index = next(i for i, atom in enumerate(catalog["atoms"]) if atom["atom_id"] == row["atom_id"])
        original = catalog["atoms"][index]
        source = original["source"]
        forged = build_atom(artifact=source["artifact"], artifact_version=source["artifact_version"],
                            artifact_sha256=source["artifact_sha256"], rel=source["file"],
                            file_sha256=source["file_sha256"], pointer=source["json_pointer"],
                            value="Altered", subject=original["subject"], completeness=source["completeness"])
        catalog["atoms"][index] = forged
        self.assertFalse(validate_catalog_internal(catalog))
        row.update(atom_id=forged["atom_id"], canonical_value_sha256=forged["canonical_value_sha256"])
        definition["identity_record"]["canonical_name"] = "Altered"
        selection["catalogs"] = builder.catalog_refs("lattice", catalogs)
        with self.assertRaises(builder.CompositionError):
            builder.verify_definition(definition, selection, catalogs, self.records)

    def test_reject_cross_identity_occurrence_with_identical_value(self):
        definition, selection, catalogs = self.state()
        row = next(row for row in selection["selections"] if row["target_pointer"] == "/design_provenance/identity_authorship")
        foreign = next(atom for atom in catalogs[builder.SHARED]["atoms"]
                       if atom["source"]["json_pointer"] == "/identity_design_model/vera_sol/identity_authorship")
        self.assertEqual(foreign["value"], definition["design_provenance"]["identity_authorship"])
        row.update(atom_id=foreign["atom_id"], source_pointer=foreign["source"]["json_pointer"])
        with self.assertRaises(builder.CompositionError):
            builder.verify_definition(definition, selection, catalogs, self.records)

    def test_reject_missing_control_selection(self):
        definition, selection, catalogs = self.state()
        selection["selections"] = [row for row in selection["selections"]
                                   if row["target_pointer"] != "/control_protocol/identity_policy/activation_requires"]
        with self.assertRaises(builder.CompositionError):
            builder.verify_definition(definition, selection, catalogs, self.records)

    def test_reject_duplicated_selection(self):
        definition, selection, catalogs = self.state()
        selection["selections"].append(copy.deepcopy(selection["selections"][0]))
        with self.assertRaises(builder.CompositionError):
            builder.verify_definition(definition, selection, catalogs, self.records)

    def test_reject_historical_runtime_promotion(self):
        definition, selection, catalogs = self.state()
        definition["runtime_reference"]["status"] = "CURRENT_CAPABILITIES"
        with self.assertRaises(builder.CompositionError):
            builder.verify_definition(definition, selection, catalogs, self.records)

    def test_reject_false_provenance_or_indexing_metadata(self):
        for field, value in [("artifact_version", "9.9.9"), ("source_kind", "unverified")]:
            definition, selection, catalogs = self.state()
            catalogs[builder.catalog_path("lattice")]["atoms"][0]["source"][field] = value
            selection["catalogs"] = builder.catalog_refs("lattice", catalogs)
            with self.assertRaises(builder.CompositionError):
                builder.verify_definition(definition, selection, catalogs, self.records)
        definition, selection, catalogs = self.state()
        catalogs[builder.catalog_path("lattice")]["atoms"][0]["normalized_value"] = "altered index text"
        selection["catalogs"] = builder.catalog_refs("lattice", catalogs)
        with self.assertRaises(builder.CompositionError):
            builder.verify_definition(definition, selection, catalogs, self.records)

    def test_reject_control_policy_or_candidate_promotion(self):
        for mutate in [lambda value: value["control_protocol"]["identity_policy"].update(merge_default="ALLOW"),
                       lambda value: value.update(build_status="active"),
                       lambda value: value.update(activation_semantics="ACTIVE")]:
            definition, selection, catalogs = self.state()
            mutate(definition)
            with self.assertRaises(builder.CompositionError):
                builder.verify_definition(definition, selection, catalogs, self.records)

    def test_reject_archive_outside_approved_fingerprint(self):
        directory = tempfile.TemporaryDirectory(dir=ROOT / "tmp")
        path = Path(directory.name).resolve()
        self.assertTrue(path.is_relative_to((ROOT / "tmp").resolve()))
        try:
            archive = path / "other.zip"
            with zipfile.ZipFile(archive, "w") as target:
                target.writestr("identity.json", "{}")
            with self.assertRaises(builder.CompositionError):
                builder.read_archive(archive)
        finally:
            self.assertTrue(path.is_relative_to((ROOT / "tmp").resolve()))
            directory.cleanup()


if __name__ == "__main__":
    unittest.main()
