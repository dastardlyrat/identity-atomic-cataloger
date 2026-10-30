from pathlib import Path
import argparse
import json
from .cataloger import catalog_directory, catalog_zip, merge_reusable, validate_catalog_internal, validate_reusable_internal


def _write(obj, path):
    text = json.dumps(obj, indent=2, ensure_ascii=False) + "\n"
    if path:
        Path(path).write_text(text, encoding="utf-8")
    else:
        print(text, end="")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="identity-atomic", description="Hardened non-activating identity/personality atomic cataloger")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("catalog")
    p.add_argument("source")
    p.add_argument("--artifact", required=True)
    p.add_argument("--version")
    p.add_argument("--subject", required=True)
    p.add_argument("--completeness", default="COMPLETE_SOURCE_PRESENT")
    p.add_argument("--allow-json-errors", action="store_true", help="Return an incomplete catalog with parse errors instead of failing closed")
    p.add_argument("-o", "--output")
    m = sub.add_parser("merge")
    m.add_argument("catalogs", nargs="+")
    m.add_argument("-o", "--output")
    v = sub.add_parser("verify")
    v.add_argument("document")
    args = ap.parse_args(argv)
    if args.cmd == "catalog":
        src = Path(args.source)
        kw = dict(artifact=args.artifact, artifact_version=args.version, subject=args.subject, completeness=args.completeness, strict_json=not args.allow_json_errors)
        obj = catalog_zip(src, **kw) if src.suffix.lower() == ".zip" else catalog_directory(src, artifact_sha256=None, **kw)
        _write(obj, args.output)
    elif args.cmd == "merge":
        cats = [json.loads(Path(p).read_text(encoding="utf-8")) for p in args.catalogs]
        _write(merge_reusable(cats), args.output)
    else:
        obj = json.loads(Path(args.document).read_text(encoding="utf-8"))
        if obj.get("schema") == "atomic_identity_catalog": issues = validate_catalog_internal(obj)
        elif obj.get("schema") == "reusable_identity_atom_dictionary": issues = validate_reusable_internal(obj)
        else: issues = ["unsupported document schema"]
        if issues:
            for issue in issues: print("FAIL", issue)
            raise SystemExit(1)
        print("PASS internal invariants")

if __name__ == "__main__":
    main()
