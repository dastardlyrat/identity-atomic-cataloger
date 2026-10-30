from __future__ import annotations
from pathlib import Path
import argparse
import json
import random
import shutil
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from identity_atomic.cataloger import (
    CatalogError, UnsafeArchiveError, canonical_json, catalog_directory, catalog_zip,
    classify, inspect_zip, iter_leaves, validate_catalog_internal,
)

class FuzzyHarness:
    def __init__(self): self.results=[]
    def check(self, name, fn, *, advisory=False):
        try:
            ok=fn()
            if ok is False: raise AssertionError("returned false")
            self.results.append((name,"PASS",""))
        except Exception as exc:
            self.results.append((name,"WARN" if advisory else "FAIL",f"{type(exc).__name__}: {exc}"))
    def finish(self, seed, iterations):
        counts={"PASS":0,"WARN":0,"FAIL":0}
        print(f"FUZZ seed={seed} iterations={iterations}")
        for name,status,detail in self.results:
            counts[status]+=1
            print(status,name,("- "+detail if detail else ""))
        print(f"RESULT {counts['PASS']} PASS / {counts['WARN']} WARN / {counts['FAIL']} FAIL")
        if counts['FAIL']:
            raise SystemExit(1)


def semantic_signature(cat):
    """Compare meaning while deliberately ignoring provenance hashes/atom IDs."""
    return sorted((
        a["source"]["json_pointer"], a["atom_type"], a["reuse_class"], a["portable"],
        a["value_type"], canonical_json(a["value"])
    ) for a in cat["atoms"])


def write_source(base: Path, obj=None, *, data: bytes|None=None, rel="identity/identity.json") -> Path:
    p=base/rel; p.parent.mkdir(parents=True,exist_ok=True)
    if data is None: data=json.dumps(obj,ensure_ascii=False).encode("utf-8")
    p.write_bytes(data)
    return base


def make_zip(path: Path, members, *, reverse=False):
    seq=list(members)
    if reverse: seq.reverse()
    with zipfile.ZipFile(path,"w",zipfile.ZIP_DEFLATED) as z:
        for name,data in seq: z.writestr(name,data)


def expect_catalog_error(fn):
    try: fn()
    except CatalogError: return True
    return False


def expect_archive_error(fn):
    try: fn()
    except UnsafeArchiveError: return True
    return False


def random_scalar(r):
    return r.choice([
        None, True, False, r.randint(-10**9,10**9), round(r.uniform(-1e6,1e6),6),
        "", " alpha   beta ", "雪", "é", "e\u0301", "~/", "line\nbreak", "🙂"
    ])


def random_value(r, depth=0):
    if depth >= 4 or r.random() < .42:
        return random_scalar(r)
    if r.random() < .55:
        out={}
        for i in range(r.randint(0,5)):
            base=r.choice(["name","role","authority","x/y","~key","κλειδί","field","status","rule"])
            out[f"{base}_{i}"]=random_value(r,depth+1)
        return out
    return [random_value(r,depth+1) for _ in range(r.randint(0,5))]


def main(argv=None):
    ap=argparse.ArgumentParser(description="Loose/fuzzy/metamorphic robustness suite")
    ap.add_argument("--seed",type=int,default=260929)
    ap.add_argument("--iterations",type=int,default=256)
    args=ap.parse_args(argv)
    r=random.Random(args.seed); h=FuzzyHarness()

    with tempfile.TemporaryDirectory() as td0:
        td=Path(td0)
        fixture={
            "canonical_name":"Fixture",
            "primary_role":"Integrator",
            "rules":["one","two"],
            "nested":{"a/b":"~x","unicode":"雪","authority":"operator"},
        }
        base=write_source(td/"base",fixture)
        baseline=catalog_directory(base,artifact="fixture",subject="Fixture")
        baseline_sig=semantic_signature(baseline)

        # Metamorphic: bytes may vary while identity semantics do not.
        serializations=[
            json.dumps(fixture,ensure_ascii=False,separators=(",",":")).encode(),
            json.dumps(fixture,ensure_ascii=False,indent=4,sort_keys=True).encode(),
            json.dumps(fixture,ensure_ascii=False,indent=2).replace("\n","\r\n").encode(),
            b"\xef\xbb\xbf"+json.dumps(fixture,ensure_ascii=False).encode(),
        ]
        h.check("serialization/whitespace/BOM semantic equivalence", lambda: all(
            semantic_signature(catalog_directory(write_source(td/f"ser{i}",fixture,data=data),artifact="fixture",subject="Fixture"))==baseline_sig
            for i,data in enumerate(serializations)
        ))

        h.check("object key-order fuzz preserves semantics", lambda: all(
            semantic_signature(catalog_directory(
                write_source(td/f"order{i}",dict(r.sample(list(fixture.items()),len(fixture)))),
                artifact="fixture",subject="Fixture"))==baseline_sig
            for i in range(min(args.iterations,128))
        ))

        def random_tree_campaign():
            for i in range(args.iterations):
                obj=random_value(r)
                root=write_source(td/f"random{i}",obj)
                cat=catalog_directory(root,artifact=f"random-{i}",subject="Fixture")
                if len(cat["atoms"]) != len(list(iter_leaves(obj))): return False
                if validate_catalog_internal(cat): return False
            return True
        h.check("random JSON tree campaign",random_tree_campaign)

        # Harmless packaging variation.
        prose=td/"prose"; shutil.copytree(base,prose)
        (prose/"README.md").write_text("noise",encoding="utf-8")
        (prose/"notes.txt").write_text("more noise",encoding="utf-8")
        h.check("benign prose files do not alter atoms",lambda: semantic_signature(catalog_directory(prose,artifact="fixture",subject="Fixture"))==baseline_sig)

        upper=write_source(td/"upper",fixture,rel="Identity/IDENTITY.JSON")
        h.check("case/extension variation remains semantic",lambda: semantic_signature(catalog_directory(upper,artifact="fixture",subject="Fixture"))==baseline_sig)

        wrapped=td/"wrapped.zip"
        make_zip(wrapped,[
            ("wrapper/identity/identity.json",json.dumps(fixture)),
            ("wrapper/schemas/schema.json",'{"title":"NOISE_SCHEMA"}'),
            ("wrapper/tests/test.json",'{"x":"NOISE_TEST"}'),
            ("wrapper/harness/h.json",'{"x":"NOISE_HARNESS"}'),
            ("README.txt","packaging noise"),
        ])
        wrapped_cat=catalog_zip(wrapped,artifact="wrapped",subject="Fixture")
        h.check("nested mechanism JSON excluded under noisy wrapper",lambda: not any(str(a["value"]).startswith("NOISE_") for a in wrapped_cat["atoms"]))
        h.check("noisy wrapper preserves identity semantics",lambda: semantic_signature(wrapped_cat)==baseline_sig)

        identity_only=td/"identity-only.zip"
        make_zip(identity_only,[("identity/identity.json",json.dumps(fixture))])
        identity_cat=catalog_zip(identity_only,artifact="identity-only",subject="Fixture")
        h.check("single semantic top-level directory is not stripped",lambda: all(a["source"]["source_kind"]=="identity" for a in identity_cat["atoms"]))

        mixed_case=td/"mixed-case.zip"
        make_zip(mixed_case,[
            ("Identity/identity.JSON",json.dumps(fixture)),
            ("Schemas/noise.JSON",'{"x":"NOISE_CASE"}'),
        ])
        mc=catalog_zip(mixed_case,artifact="case",subject="Fixture")
        h.check("mechanism directory exclusion is case-insensitive",lambda: not any(a["value"]=="NOISE_CASE" for a in mc["atoms"]))

        # Member order should not alter meaning, though ZIP hash/provenance will differ.
        members=[("wrapper/identity/a.json",'{"role":"A"}'),("wrapper/core/b.json",'{"rules":["x","y"]}')]
        za=td/"za.zip"; zb=td/"zb.zip"; make_zip(za,members); make_zip(zb,members,reverse=True)
        h.check("ZIP member-order variation preserves semantic atoms",lambda: semantic_signature(catalog_zip(za,artifact="za",subject="F"))==semantic_signature(catalog_zip(zb,artifact="zb",subject="F")))

        # Partial/permissive behavior remains explicit, never silent.
        partial=write_source(td/"partial",{"x":1})
        q=partial/"core/bad.json"; q.parent.mkdir(); q.write_text("{bad",encoding="utf-8")
        h.check("permissive parse records error and preserves valid atoms",lambda: (lambda c: c["summary"]["errors"]==1 and any(a["value"]==1 for a in c["atoms"]))(
            catalog_directory(partial,artifact="partial",subject="Fixture",strict_json=False)))
        h.check("strict parse still fails malformed semantic JSON",lambda: expect_catalog_error(lambda: catalog_directory(partial,artifact="partial",subject="Fixture")))

        # Ambiguous/non-standard JSON must not be fuzz-normalized into a valid identity.
        ambiguous=[
            ("duplicate object keys",b'{"x":1,"x":2}'),
            ("NaN",b'{"x":NaN}'),
            ("Infinity",b'{"x":Infinity}'),
            ("negative Infinity",b'{"x":-Infinity}'),
            ("overflow to non-finite",b'{"x":1e9999}'),
            ("invalid UTF-8",b'{"x":"\xff"}'),
            ("unpaired Unicode surrogate",b'{"x":"\\ud800"}'),
        ]
        for i,(name,data) in enumerate(ambiguous):
            src=write_source(td/f"amb{i}",{},data=data)
            h.check("reject "+name,lambda src=src: expect_catalog_error(lambda: catalog_directory(src,artifact="amb",subject="Fixture")))

        # Edge shapes.
        empty=write_source(td/"empty",{"object":{},"array":[]})
        h.check("empty arrays/objects remain explicit atoms",lambda: len(catalog_directory(empty,artifact="empty",subject="Fixture")["atoms"])==2)
        scalar=write_source(td/"scalar",None,data=b"42")
        h.check("top-level scalar remains representable",lambda: (lambda c: len(c["atoms"])==1 and c["atoms"][0]["value"]==42 and c["atoms"][0]["source"]["json_pointer"]=="/")(
            catalog_directory(scalar,artifact="scalar",subject="Fixture")))

        # Fuzziness must not erase meaningful differences.
        a=write_source(td/"arr-a",{"rules":["a","b"]}); b=write_source(td/"arr-b",{"rules":["b","a"]})
        h.check("array order remains meaning-visible",lambda: semantic_signature(catalog_directory(a,artifact="a",subject="F")) != semantic_signature(catalog_directory(b,artifact="b",subject="F")))
        u1=write_source(td/"u1",{"rules":["é"]}); u2=write_source(td/"u2",{"rules":["e\u0301"]})
        h.check("Unicode normalization is not silently conflated",lambda: catalog_directory(u1,artifact="u1",subject="F")["atoms"][0]["canonical_value_sha256"] != catalog_directory(u2,artifact="u2",subject="F")["atoms"][0]["canonical_value_sha256"])
        w1=write_source(td/"w1",{"rules":["a  b"]}); w2=write_source(td/"w2",{"rules":["a b"]})
        h.check("search normalization does not erase exact string difference",lambda: (lambda x,y: x["normalized_value"]==y["normalized_value"] and x["canonical_value_sha256"]!=y["canonical_value_sha256"])(
            catalog_directory(w1,artifact="w1",subject="F")["atoms"][0],catalog_directory(w2,artifact="w2",subject="F")["atoms"][0]))

        # Non-canonical spellings should be rejected instead of normalized opportunistically.
        for i,(label,name) in enumerate([
            ("dot segment","root/./identity.json"),
            ("double slash","root//identity.json"),
        ]):
            zp=td/f"noncanonical{i}.zip"; make_zip(zp,[(name,"{}")])
            h.check("reject non-canonical ZIP "+label,lambda zp=zp: expect_archive_error(lambda: inspect_zip(zp)))

        # Heuristic near misses: classifier must not make obvious substring mistakes.
        h.check("near-miss 'parole' is not classified as identity.role",lambda: classify("identity/x.json","/parole","x")[0] != "identity.role")
        h.check("near-miss 'reproduction' is not classified as lifecycle.gate",lambda: classify("identity/x.json","/reproduction_mode","x")[0] != "lifecycle.gate")

        # Unknown semantic JSON is still catalogable rather than requiring a known personality schema.
        unknown=write_source(td/"unknown",{"novel_domain":{"x":1,"y":"z"}},rel="custom/novel.JSON")
        h.check("unknown semantic JSON degrades to generic atoms without crashing",lambda: (lambda c: len(c["atoms"])==2 and all(a["atom_type"]=="generic.scalar" for a in c["atoms"]))(
            catalog_directory(unknown,artifact="unknown",subject="Fixture")))

    h.finish(args.seed,args.iterations)

if __name__=="__main__": main()
