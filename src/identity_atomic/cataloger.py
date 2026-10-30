from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable
import hashlib
import json
import os
import re
import stat
import tempfile
import zipfile

NON_SEMANTIC_PREFIXES = ("schemas/", "tests/", "harness/")
NON_SEMANTIC_DIR_NAMES = {"schemas", "tests", "harness"}
KNOWN_SOURCE_KINDS = {"identity", "personality", "core", "integration", "backup", "attestation", "source", "provenance", "schemas", "tests", "harness"}
COMPLETENESS_STATES = {
    "COMPLETE_SOURCE_PRESENT",
    "PARTIAL_SOURCE_PRESENT",
    "REFERENCE_ONLY",
    "UNKNOWN_SOURCE_COMPLETENESS",
}

class CatalogError(ValueError):
    pass

class UnsafeArchiveError(CatalogError):
    pass

class UnsafeSourceTreeError(CatalogError):
    pass

@dataclass(frozen=True)
class ZipSecurityPolicy:
    max_members: int = 10_000
    max_total_uncompressed: int = 512 * 1024 * 1024
    max_member_uncompressed: int = 64 * 1024 * 1024
    max_compression_ratio: float = 200.0
    reject_encrypted: bool = True
    reject_symlinks: bool = True
    reject_special_files: bool = True

DEFAULT_ZIP_POLICY = ZipSecurityPolicy()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _esc(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def iter_leaves(value: Any, pointer: str = ""):
    """Yield (RFC 6901 JSON pointer, leaf value). Arrays become one atom per leaf."""
    if isinstance(value, dict):
        if not value:
            yield pointer or "/", {}
        for key, child in value.items():
            p = (pointer + "/" + _esc(str(key))) if pointer else "/" + _esc(str(key))
            yield from iter_leaves(child, p)
    elif isinstance(value, list):
        if not value:
            yield pointer or "/", []
        for idx, child in enumerate(value):
            p = (pointer + "/" + str(idx)) if pointer else "/" + str(idx)
            yield from iter_leaves(child, p)
    else:
        yield pointer or "/", value


def value_type(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, int) and not isinstance(v, bool):
        return "integer"
    if isinstance(v, float):
        return "number"
    if isinstance(v, str):
        return "string"
    if isinstance(v, list):
        return "array"
    if isinstance(v, dict):
        return "object"
    raise TypeError(f"unsupported JSON value type: {type(v).__name__}")


def normalize(v: Any) -> str:
    """Human-search normalization only. Never use this value to establish exact identity."""
    if isinstance(v, str):
        return " ".join(v.strip().split())
    return canonical_json(v)


def _lexical_tokens(text: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", text.lower()) if t}

def classify(path: str, pointer: str, value: Any) -> tuple[str, str, bool]:
    """Return derived (atom_type, reuse_class, portable). Source path/value remain authoritative."""
    s = (path + " " + pointer).lower()
    key = pointer.rsplit("/", 1)[-1].lower() if pointer else ""
    tokens = _lexical_tokens(path + " " + pointer)
    key_tokens = _lexical_tokens(key)
    if any(x in s for x in ["sha256", "checksum", "fingerprint"]):
        return "provenance.digest", "evidence_metadata", False
    if any(x in s for x in ["/date", "/version", "schema_version", "packet_version"]) or key in {"date", "version"}:
        return "metadata.version_or_date", "artifact_metadata", False
    if "schema" in s and path.startswith("schemas/"):
        return "schema.structure", "structural_template", True
    if any(x in s for x in ["provenance", "source_artifact", "source_fingerprints", "source_basis"]):
        return "provenance.source", "evidence_metadata", False
    if "attestation" in s:
        return "attestation.fact", "evidence_metadata", False
    if "production" in tokens or "gate" in tokens:
        return "lifecycle.gate", "lifecycle_reusable", True
    if key in {"canonical_name", "call_name", "visible_name", "machine_id", "short_id", "namespace", "identity"}:
        return "identity.anchor", "identity_specific", False
    if "identity_class" in s:
        return "identity.class", "identity_structure", True
    if any(x in s for x in ["human_identity_claim", "biological_identity_claim", "legal_personhood_claim", "sentience_claim", "autonomy_claim", "shared_state_claim", "identity_fusion", "parent_identity_fusion", "replaces_parents", "visible_identity_replacement"]):
        return "identity.boundary", "boundary_reusable", True
    if any(x in s for x in ["authority", "authorized", "authorization", "permission", "scope"]):
        return "authority.rule", "authority_reusable", True
    if "role" in key_tokens or "roles" in key_tokens:
        return "identity.role", "role_reusable", True
    if any(x in s for x in ["lineage", "derived_from", "relationship", "relation", "peer", "parent_identity", "return_target"]):
        return "relationship.fact", "relationship_specific", False
    if "temperament" in s:
        return "behavior.temperament", "behavioral_reusable", True
    if "interaction_style" in s:
        return "behavior.interaction_rule", "behavioral_reusable", True
    if "operating_preferences" in s:
        return "behavior.operating_preference", "behavioral_reusable", True
    if any(x in s for x in ["core_doctrine", "defining_trait", "synthesized_properties", "inherited_from_"]):
        return "behavior.trait_or_doctrine", "behavioral_reusable", True
    if "anti_patterns" in s or "forbidden_" in s or "must_not_" in s:
        return "behavior.prohibition", "behavioral_reusable", True
    if "must_preserve" in s:
        return "behavior.invariant", "boundary_reusable", True
    if any(x in s for x in ["/states/", "default_state", "/status", "state_machine", "from_state", "to_state", "state_transitions"]):
        return "control.state", "control_reusable", True
    if any(x in s for x in ["trigger", "activation", "deactivation", "return_conditions"]):
        return "control.trigger_or_condition", "control_reusable", True
    if any(x in s for x in ["execution_grammar", "phase_rules", "/phases/"]):
        return "control.phase", "control_reusable", True
    if any(x in s for x in ["/rules/", "/requires/", "sufficient_when", "reopening_condition", "principle"]):
        return "control.rule", "control_reusable", True
    if any(x in s for x in ["validation", "verified", "unverified", "evidence", "inferred", "unknown", "confidence"]):
        return "epistemic.validation", "epistemic_reusable", True
    if any(x in s for x in ["error", "failure", "recover", "rollback", "reversib"]):
        return "recovery.rule", "control_reusable", True
    if key == "purpose" or "/purpose/" in s or key == "goal":
        return "purpose.goal", "purpose_reusable", True
    return "generic.scalar", "generic", False


def file_kind(rel: str) -> str:
    p = PurePosixPath(rel)
    parts = [part.lower() for part in p.parts]
    for part in parts[:-1]:
        if part in KNOWN_SOURCE_KINDS:
            return part
    name = p.name.lower()
    if name == "provenance.json":
        return "provenance"
    if name.endswith("release.json") or name == "production_release.json":
        return "release"
    if name == "manifest.json":
        return "manifest"
    return "other"


def is_semantic_json(rel: str) -> bool:
    p = PurePosixPath(rel)
    if p.suffix.lower() != ".json":
        return False
    parent_parts = {part.lower() for part in p.parts[:-1]}
    if parent_parts & NON_SEMANTIC_DIR_NAMES:
        return False
    return True


def _validate_identity_inputs(artifact: str, subject: str, completeness: str) -> None:
    if not isinstance(artifact, str) or not artifact.strip():
        raise CatalogError("artifact must be a non-empty string")
    if not isinstance(subject, str) or not subject.strip():
        raise CatalogError("subject must be a non-empty string")
    if completeness not in COMPLETENESS_STATES:
        raise CatalogError(f"unsupported completeness state: {completeness}")


def _zip_member_mode(info: zipfile.ZipInfo) -> int:
    return (info.external_attr >> 16) & 0xFFFF


def _validate_zip_name(name: str) -> PurePosixPath:
    if not name or "\x00" in name:
        raise UnsafeArchiveError(f"invalid zip member name: {name!r}")
    if "\\" in name:
        raise UnsafeArchiveError(f"backslash zip path rejected: {name!r}")
    if name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        raise UnsafeArchiveError(f"absolute/drive zip path rejected: {name!r}")
    raw = name[:-1] if name.endswith("/") else name
    if not raw:
        raise UnsafeArchiveError(f"invalid zip member name: {name!r}")
    raw_parts = raw.split("/")
    if any(part in {"", ".", ".."} for part in raw_parts):
        raise UnsafeArchiveError(f"non-canonical zip path rejected: {name!r}")
    p = PurePosixPath(raw)
    return p


def inspect_zip(zip_path: Path, policy: ZipSecurityPolicy = DEFAULT_ZIP_POLICY) -> dict:
    zip_path = Path(zip_path)
    if not zip_path.is_file():
        raise FileNotFoundError(zip_path)
    with zipfile.ZipFile(zip_path) as z:
        infos = z.infolist()
        if len(infos) > policy.max_members:
            raise UnsafeArchiveError(f"archive has {len(infos)} members; max is {policy.max_members}")
        seen = set()
        file_paths = set()
        total = 0
        max_ratio = 0.0
        for info in infos:
            p = _validate_zip_name(info.filename)
            canonical = p.as_posix().rstrip("/")
            if canonical in seen:
                raise UnsafeArchiveError(f"duplicate zip member: {canonical}")
            seen.add(canonical)
            mode = _zip_member_mode(info)
            ftype = stat.S_IFMT(mode) if mode else 0
            is_dir = info.is_dir() or info.filename.endswith("/")
            if policy.reject_encrypted and (info.flag_bits & 0x1):
                raise UnsafeArchiveError(f"encrypted zip member rejected: {info.filename}")
            if policy.reject_symlinks and ftype == stat.S_IFLNK:
                raise UnsafeArchiveError(f"symlink zip member rejected: {info.filename}")
            if policy.reject_special_files and ftype not in {0, stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK}:
                raise UnsafeArchiveError(f"special zip member rejected: {info.filename}")
            if not is_dir:
                file_paths.add(canonical)
                if info.file_size > policy.max_member_uncompressed:
                    raise UnsafeArchiveError(f"member too large: {info.filename}")
                total += info.file_size
                if total > policy.max_total_uncompressed:
                    raise UnsafeArchiveError("archive uncompressed size exceeds policy")
                if info.file_size:
                    ratio = info.file_size / max(info.compress_size, 1)
                    max_ratio = max(max_ratio, ratio)
                    if ratio > policy.max_compression_ratio:
                        raise UnsafeArchiveError(f"compression ratio exceeds policy: {info.filename}")
        # Prevent a file from being a parent of another member: a/b file plus a/b/c.
        for path in seen:
            parts = PurePosixPath(path).parts
            for i in range(1, len(parts)):
                prefix = "/".join(parts[:i])
                if prefix in file_paths:
                    raise UnsafeArchiveError(f"file/directory collision in archive: {prefix}")
        return {
            "members": len(infos),
            "total_uncompressed": total,
            "max_compression_ratio": max_ratio,
            "sha256": sha256_file(zip_path),
        }


def _safe_extract_zip(zip_path: Path, dest: Path, policy: ZipSecurityPolicy) -> None:
    inspect_zip(zip_path, policy)
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    with zipfile.ZipFile(zip_path) as z:
        for info in z.infolist():
            rel = _validate_zip_name(info.filename)
            target = dest.joinpath(*rel.parts)
            resolved_parent = target.parent.resolve()
            if root != resolved_parent and root not in resolved_parent.parents:
                raise UnsafeArchiveError(f"zip member escapes extraction root: {info.filename}")
            if info.is_dir() or info.filename.endswith("/"):
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            # xb prevents silent overwrite even if a platform-specific collision slipped through.
            remaining = info.file_size
            with z.open(info, "r") as src, target.open("xb") as dst:
                while True:
                    chunk = src.read(min(1024 * 1024, remaining + 1))
                    if not chunk:
                        break
                    remaining -= len(chunk)
                    if remaining < 0:
                        raise UnsafeArchiveError(f"member exceeds declared size: {info.filename}")
                    dst.write(chunk)
            if remaining != 0:
                raise UnsafeArchiveError(f"member shorter than declared size: {info.filename}")


def _walk_safe_files(root: Path):
    root = Path(root)
    if not root.exists() or not root.is_dir():
        raise NotADirectoryError(root)
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        cur = Path(current)
        for name in list(dirs):
            p = cur / name
            if p.is_symlink():
                raise UnsafeSourceTreeError(f"directory symlink rejected: {p.relative_to(root)}")
        for name in files:
            p = cur / name
            if p.is_symlink():
                raise UnsafeSourceTreeError(f"file symlink rejected: {p.relative_to(root)}")
            if not p.is_file():
                raise UnsafeSourceTreeError(f"special source file rejected: {p.relative_to(root)}")
            yield p


def canonical_tree_sha256(root: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(_walk_safe_files(root), key=lambda x: x.relative_to(root).as_posix()):
        rel = p.relative_to(root).as_posix()
        fsha = sha256_file(p)
        record = canonical_json({"path": rel, "bytes": p.stat().st_size, "sha256": fsha}).encode("utf-8")
        h.update(len(record).to_bytes(8, "big"))
        h.update(record)
    return h.hexdigest()


def _atom_seed(artifact_sha256: str | None, rel: str, pointer: str, value: Any) -> str:
    return "|".join([artifact_sha256 or "", rel, pointer, canonical_json(value)])


class SemanticJSONError(ValueError):
    pass

def _reject_duplicate_pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise SemanticJSONError(f"duplicate JSON object key: {key!r}")
        out[key] = value
    return out

def _reject_nonstandard_constant(token: str):
    raise SemanticJSONError(f"non-standard JSON numeric constant: {token}")

def _validate_json_scalars(value: Any, pointer: str = "") -> None:
    if isinstance(value, float) and not __import__("math").isfinite(value):
        raise SemanticJSONError(f"non-finite JSON number at {pointer or '/'}")
    if isinstance(value, str):
        if any(0xD800 <= ord(ch) <= 0xDFFF for ch in value):
            raise SemanticJSONError(f"unpaired Unicode surrogate at {pointer or '/'}")
    elif isinstance(value, dict):
        for key, child in value.items():
            if any(0xD800 <= ord(ch) <= 0xDFFF for ch in key):
                raise SemanticJSONError(f"unpaired Unicode surrogate in key at {pointer or '/'}")
            child_ptr = (pointer + "/" + _esc(key)) if pointer else "/" + _esc(key)
            _validate_json_scalars(child, child_ptr)
    elif isinstance(value, list):
        for idx, child in enumerate(value):
            child_ptr = (pointer + "/" + str(idx)) if pointer else "/" + str(idx)
            _validate_json_scalars(child, child_ptr)

def parse_semantic_json(data: bytes) -> Any:
    text = data.decode("utf-8-sig")
    obj = json.loads(
        text,
        object_pairs_hook=_reject_duplicate_pairs,
        parse_constant=_reject_nonstandard_constant,
    )
    _validate_json_scalars(obj)
    return obj

def build_atom(*, artifact: str, artifact_version: str | None, artifact_sha256: str | None, rel: str, file_sha256: str, pointer: str, value: Any, subject: str, completeness: str) -> dict:
    atype, reuse_class, portable = classify(rel, pointer, value)
    canonical = canonical_json(value)
    seed = _atom_seed(artifact_sha256, rel, pointer, value)
    return {
        "atom_id": "atom:" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:24],
        "subject": subject,
        "atom_type": atype,
        "reuse_class": reuse_class,
        "portable": portable,
        "value_type": value_type(value),
        "value": value,
        "normalized_value": normalize(value),
        "canonical_value_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "source": {
            "artifact": artifact,
            "artifact_version": artifact_version,
            "artifact_sha256": artifact_sha256,
            "file": rel,
            "file_sha256": file_sha256,
            "json_pointer": pointer,
            "source_kind": file_kind(rel),
            "completeness": completeness,
        },
        "activation_semantics": "CATALOG_ONLY",
    }


def catalog_directory(root: Path, *, artifact: str, artifact_version: str | None = None, artifact_sha256: str | None = None, subject: str, completeness: str = "COMPLETE_SOURCE_PRESENT", strict_json: bool = True) -> dict:
    _validate_identity_inputs(artifact, subject, completeness)
    root = Path(root)
    files = sorted(_walk_safe_files(root), key=lambda p: p.relative_to(root).as_posix())
    digest_kind = "PROVIDED_ARTIFACT_SHA256" if artifact_sha256 else "CANONICAL_TREE_SHA256"
    effective_digest = artifact_sha256 or canonical_tree_sha256(root)
    if not re.fullmatch(r"[0-9a-f]{64}", effective_digest or ""):
        raise CatalogError("artifact_sha256 must be a lowercase 64-hex SHA-256 digest")
    atoms, inventory, errors = [], [], []
    for p in files:
        rel = p.relative_to(root).as_posix()
        data = p.read_bytes()
        fsha = sha256_bytes(data)
        rec = {"path": rel, "bytes": len(data), "sha256": fsha, "kind": file_kind(rel)}
        if is_semantic_json(rel):
            try:
                obj = parse_semantic_json(data)
                rec["cataloged"] = True
                n0 = len(atoms)
                for ptr, val in iter_leaves(obj):
                    atoms.append(build_atom(artifact=artifact, artifact_version=artifact_version, artifact_sha256=effective_digest, rel=rel, file_sha256=fsha, pointer=ptr, value=val, subject=subject, completeness=completeness))
                rec["atom_count"] = len(atoms) - n0
            except (UnicodeDecodeError, json.JSONDecodeError, SemanticJSONError, RecursionError) as exc:
                rec["cataloged"] = False
                rec["reason"] = "json_parse_error"
                errors.append({"file": rel, "error_type": type(exc).__name__, "error": str(exc)})
                if strict_json:
                    raise CatalogError(f"semantic JSON parse failed for {rel}: {exc}") from exc
        else:
            rec["cataloged"] = False
            if rel.startswith("schemas/"):
                rec["reason"] = "schema_inventory_only"
            elif rel.startswith(("tests/", "harness/")):
                rec["reason"] = "test_mechanism_excluded_from_identity_atoms"
            elif rel.endswith((".md", ".txt")):
                rec["reason"] = "prose_or_startup_context_omitted"
            else:
                rec["reason"] = "non_json_or_nonsemantic"
        inventory.append(rec)
    catalog = {
        "schema": "atomic_identity_catalog",
        "schema_version": "0.2",
        "catalog_mode": "NON_ACTIVATING_ATOMIC_DECOMPOSITION",
        "subject": subject,
        "source_artifact": artifact,
        "source_version": artifact_version,
        "source_artifact_sha256": effective_digest,
        "source_digest_kind": digest_kind,
        "source_completeness": completeness,
        "rules": {
            "assembled_personality_included": False,
            "startup_context_included": False,
            "prose_personality_included": False,
            "atomic_source_values_preserved": True,
            "source_paths_preserved": True,
            "classification_is_derived_metadata": True,
            "normalized_value_is_non_authoritative": True,
            "exact_value_hash_used_for_reuse_identity": True,
        },
        "inventory": inventory,
        "atoms": atoms,
        "errors": errors,
        "summary": {
            "files_seen": len(inventory),
            "json_files_cataloged": sum(1 for r in inventory if r.get("cataloged")),
            "atoms": len(atoms),
            "portable_atoms": sum(1 for a in atoms if a["portable"]),
            "errors": len(errors),
        },
    }
    issues = validate_catalog_internal(catalog)
    if issues:
        raise CatalogError("internal catalog invariant failure: " + "; ".join(issues[:5]))
    return catalog


def catalog_zip(zip_path: Path, *, zip_policy: ZipSecurityPolicy = DEFAULT_ZIP_POLICY, **kwargs) -> dict:
    zip_path = Path(zip_path)
    audit = inspect_zip(zip_path, zip_policy)
    with tempfile.TemporaryDirectory() as td:
        _safe_extract_zip(zip_path, Path(td), zip_policy)
        root = Path(td)
        entries = [p for p in root.iterdir()]
        if len(entries) == 1 and entries[0].is_dir() and entries[0].name.lower() not in KNOWN_SOURCE_KINDS:
            root = entries[0]
        if kwargs.get("artifact_sha256") is None:
            kwargs["artifact_sha256"] = audit["sha256"]
        return catalog_directory(root, **kwargs)


def merge_reusable(catalogs: Iterable[dict]) -> dict:
    """Merge only exact portable values. normalized_value is never a deduplication key."""
    groups = {}
    for cat in catalogs:
        issues = validate_catalog_internal(cat)
        if issues:
            raise CatalogError("cannot merge invalid catalog: " + "; ".join(issues[:5]))
        for atom in cat.get("atoms", []):
            if not atom.get("portable"):
                continue
            canonical = canonical_json(atom["value"])
            exact_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            key = (atom["atom_type"], atom["value_type"], exact_hash)
            reuse_seed = "|".join(key)
            group = groups.setdefault(key, {
                "reusable_atom_id": "reuse:" + hashlib.sha256(reuse_seed.encode("utf-8")).hexdigest()[:24],
                "atom_type": atom["atom_type"],
                "value_type": atom["value_type"],
                "value": atom["value"],
                "normalized_value": atom["normalized_value"],
                "canonical_value_sha256": exact_hash,
                "reuse_class": atom["reuse_class"],
                "portable": True,
                "activation_semantics": "CATALOG_ONLY",
                "occurrences": [],
            })
            group["occurrences"].append({
                "subject": atom["subject"],
                "source_artifact": atom["source"]["artifact"],
                "file": atom["source"]["file"],
                "json_pointer": atom["source"]["json_pointer"],
                "atom_id": atom["atom_id"],
            })
    atoms = sorted(groups.values(), key=lambda x: (x["atom_type"], x["canonical_value_sha256"]))
    result = {
        "schema": "reusable_identity_atom_dictionary",
        "schema_version": "0.2",
        "activation_semantics": "CATALOG_ONLY",
        "selection_rule": "Reuse requires explicit selection; presence in this dictionary is not activation or recommendation.",
        "deduplication_rule": "Exact canonical JSON value + atom_type + value_type. normalized_value is search metadata only.",
        "atoms": atoms,
        "summary": {"unique_portable_atoms": len(atoms), "occurrences": sum(len(a["occurrences"]) for a in atoms)},
    }
    issues = validate_reusable_internal(result)
    if issues:
        raise CatalogError("internal reusable dictionary invariant failure: " + "; ".join(issues[:5]))
    return result


def validate_catalog_internal(cat: dict) -> list[str]:
    issues: list[str] = []
    if cat.get("schema") != "atomic_identity_catalog": issues.append("schema identifier invalid")
    if cat.get("catalog_mode") != "NON_ACTIVATING_ATOMIC_DECOMPOSITION": issues.append("catalog mode invalid")
    if cat.get("source_completeness") not in COMPLETENESS_STATES: issues.append("completeness state invalid")
    atoms = cat.get("atoms")
    if not isinstance(atoms, list): return issues + ["atoms is not a list"]
    seen = set()
    portable = 0
    for i, atom in enumerate(atoms):
        prefix = f"atoms[{i}]"
        if atom.get("activation_semantics") != "CATALOG_ONLY": issues.append(prefix + " activation semantics invalid")
        if atom.get("atom_id") in seen: issues.append(prefix + " duplicate atom_id")
        seen.add(atom.get("atom_id"))
        if atom.get("portable") is True: portable += 1
        try:
            expected_type = value_type(atom.get("value"))
            if atom.get("value_type") != expected_type: issues.append(prefix + " value_type mismatch")
            canonical = canonical_json(atom.get("value"))
            expected_vhash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            if atom.get("canonical_value_sha256") != expected_vhash: issues.append(prefix + " canonical value hash mismatch")
            src = atom.get("source", {})
            expected_id = "atom:" + hashlib.sha256(_atom_seed(src.get("artifact_sha256"), src.get("file", ""), src.get("json_pointer", ""), atom.get("value")).encode("utf-8")).hexdigest()[:24]
            if atom.get("atom_id") != expected_id: issues.append(prefix + " atom_id mismatch")
            if not re.fullmatch(r"[0-9a-f]{64}", src.get("file_sha256", "")): issues.append(prefix + " file_sha256 invalid")
            if not re.fullmatch(r"[0-9a-f]{64}", src.get("artifact_sha256", "")): issues.append(prefix + " artifact_sha256 invalid")
            if not isinstance(src.get("json_pointer"), str) or not src.get("json_pointer", "").startswith("/"): issues.append(prefix + " JSON pointer invalid")
        except Exception as exc:
            issues.append(prefix + f" validation error: {type(exc).__name__}")
    summary = cat.get("summary", {})
    if summary.get("atoms") != len(atoms): issues.append("summary atom count mismatch")
    if summary.get("portable_atoms") != portable: issues.append("summary portable count mismatch")
    if summary.get("errors") != len(cat.get("errors", [])): issues.append("summary error count mismatch")
    if summary.get("files_seen") != len(cat.get("inventory", [])): issues.append("summary file count mismatch")
    return issues


def validate_reusable_internal(obj: dict) -> list[str]:
    issues: list[str] = []
    if obj.get("schema") != "reusable_identity_atom_dictionary": issues.append("schema identifier invalid")
    if obj.get("activation_semantics") != "CATALOG_ONLY": issues.append("dictionary activation semantics invalid")
    atoms = obj.get("atoms")
    if not isinstance(atoms, list): return issues + ["atoms is not a list"]
    seen = set(); occurrences = 0
    for i, atom in enumerate(atoms):
        prefix = f"atoms[{i}]"
        if atom.get("portable") is not True: issues.append(prefix + " non-portable atom present")
        if atom.get("activation_semantics") != "CATALOG_ONLY": issues.append(prefix + " activation semantics invalid")
        canonical = canonical_json(atom.get("value"))
        h = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if atom.get("canonical_value_sha256") != h: issues.append(prefix + " canonical value hash mismatch")
        key = (atom.get("atom_type", ""), atom.get("value_type", ""), h)
        expected = "reuse:" + hashlib.sha256("|".join(key).encode("utf-8")).hexdigest()[:24]
        if atom.get("reusable_atom_id") != expected: issues.append(prefix + " reusable_atom_id mismatch")
        if expected in seen: issues.append(prefix + " duplicate reusable_atom_id")
        seen.add(expected)
        occurrences += len(atom.get("occurrences", []))
    summary = obj.get("summary", {})
    if summary.get("unique_portable_atoms") != len(atoms): issues.append("summary unique count mismatch")
    if summary.get("occurrences") != occurrences: issues.append("summary occurrence count mismatch")
    return issues
