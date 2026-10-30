from __future__ import annotations
from pathlib import Path
import copy
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from identity_atomic.cataloger import (
    CatalogError, UnsafeArchiveError, UnsafeSourceTreeError, ZipSecurityPolicy,
    catalog_directory, catalog_zip, inspect_zip, merge_reusable,
    sha256_file, validate_catalog_internal, validate_reusable_internal,
)

class Harness:
    def __init__(self): self.results=[]
    def check(self, name, fn):
        try:
            ok = fn()
            if ok is False: raise AssertionError("returned false")
            self.results.append((name, True, ""))
        except Exception as exc:
            self.results.append((name, False, f"{type(exc).__name__}: {exc}"))
    def expect_raises(self, name, exc_type, fn):
        def wrapped():
            try: fn()
            except exc_type: return True
            except Exception as exc: raise AssertionError(f"wrong exception {type(exc).__name__}: {exc}")
            raise AssertionError(f"expected {exc_type.__name__}")
        self.check(name, wrapped)
    def finish(self):
        for name, ok, detail in self.results:
            print(("PASS" if ok else "FAIL"), name, ("- " + detail if detail else ""))
        failed=[r for r in self.results if not r[1]]
        print(f"RESULT {len(self.results)-len(failed)}/{len(self.results)} PASS")
        if failed: raise SystemExit(1)


def load(rel): return json.loads((ROOT/rel).read_text(encoding="utf-8"))

def write_zip(path, members):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in members:
            z.writestr(name, data)

def make_symlink_zip(path):
    with zipfile.ZipFile(path, "w") as z:
        zi=zipfile.ZipInfo("root/link")
        zi.create_system=3
        zi.external_attr=(stat.S_IFLNK | 0o777) << 16
        z.writestr(zi, "../../escape")

def verify_checksums(root):
    lines=(root/'CHECKSUMS.sha256').read_text().splitlines()
    for line in lines:
        if not line.strip(): continue
        digest, rel=line.split('  ',1)
        p=root/rel
        if not p.is_file() or sha256_file(p)!=digest: return False
    return True

def schema_validate_docs(root):
    try:
        from jsonschema import Draft202012Validator
        from referencing import Registry, Resource
    except Exception as exc:
        raise AssertionError("jsonschema + referencing are required for hardening harness") from exc
    schema_dir=root/'schemas'
    atom=json.loads((schema_dir/'identity_atom.schema.json').read_text())
    cat=json.loads((schema_dir/'atomic_identity_catalog.schema.json').read_text())
    reuse=json.loads((schema_dir/'reusable_identity_atom_dictionary.schema.json').read_text())
    for s in [atom,cat,reuse]: Draft202012Validator.check_schema(s)
    registry=Registry().with_resources([(s['$id'], Resource.from_contents(s)) for s in [atom,cat,reuse]])
    Draft202012Validator(cat, registry=registry).validate(load('catalogs/vesper_atomic_catalog.json'))
    Draft202012Validator(cat, registry=registry).validate(load('catalogs/corda_atomic_catalog.json'))
    Draft202012Validator(reuse, registry=registry).validate(load('catalogs/reusable_atom_dictionary.json'))
    return True

def main():
    h=Harness()
    v=load('catalogs/vesper_atomic_catalog.json'); c=load('catalogs/corda_atomic_catalog.json'); r=load('catalogs/reusable_atom_dictionary.json'); idx=load('catalogs/source_index.json')
    # Baseline invariants
    h.check('Vesper catalog internal invariants', lambda: not validate_catalog_internal(v))
    h.check('Corda catalog internal invariants', lambda: not validate_catalog_internal(c))
    h.check('Reusable dictionary internal invariants', lambda: not validate_reusable_internal(r))
    h.check('JSON Schema documents and catalogs validate', lambda: schema_validate_docs(ROOT))
    h.check('Package checksum manifest validates', lambda: verify_checksums(ROOT))
    h.check('No complete claim for reference-only identities', lambda: all(x.get('complete_identity_claim') is False for x in idx['subjects'] if x['source_status']=='REFERENCE_ONLY'))
    h.check('No embedded startup context', lambda: not any(p.name.lower()=='startup_context.txt' for p in ROOT.rglob('*') if p.is_file()))
    h.check('No assembled personality directory', lambda: not (ROOT/'personality').exists())
    h.check('All catalog atoms are CATALOG_ONLY', lambda: all(a['activation_semantics']=='CATALOG_ONLY' for a in v['atoms']+c['atoms']))
    h.check('Reusable atoms are portable and CATALOG_ONLY', lambda: all(a['portable'] is True and a['activation_semantics']=='CATALOG_ONLY' for a in r['atoms']))

    with tempfile.TemporaryDirectory() as td:
        td=Path(td)
        # deterministic directory catalog and provenance
        src=td/'src'; src.mkdir(); (src/'identity').mkdir(); (src/'identity'/'x.json').write_text('{"a":"x", "b": [1, true]}', encoding='utf-8')
        a=catalog_directory(src, artifact='fixture', subject='Fixture')
        b=catalog_directory(src, artifact='fixture', subject='Fixture')
        h.check('Directory catalog deterministic', lambda: a==b)
        h.check('Directory catalog gets canonical tree digest', lambda: a['source_digest_kind']=='CANONICAL_TREE_SHA256' and len(a['source_artifact_sha256'])==64)
        h.check('Source file hash provenance exact', lambda: a['atoms'][0]['source']['file_sha256']==hashlib.sha256((src/'identity'/'x.json').read_bytes()).hexdigest())
        # malformed semantic JSON fails closed
        bad=td/'bad'; bad.mkdir(); (bad/'identity').mkdir(); (bad/'identity'/'bad.json').write_text('{nope',encoding='utf-8')
        h.expect_raises('Malformed semantic JSON fails closed', CatalogError, lambda: catalog_directory(bad, artifact='bad', subject='Bad'))
        # directory symlink escape
        sy=td/'sy'; sy.mkdir(); (sy/'identity').mkdir(); outside=td/'outside.json'; outside.write_text('{}'); os.symlink(outside, sy/'identity'/'link.json')
        h.expect_raises('Directory symlink rejected', UnsafeSourceTreeError, lambda: catalog_directory(sy, artifact='sy', subject='Sy'))
        # zip path attacks
        for label, name in [('parent traversal','../evil.json'),('backslash traversal','..\\evil.json'),('absolute path','/evil.json'),('drive path','C:/evil.json')]:
            zp=td/(label.replace(' ','_')+'.zip'); write_zip(zp, [(name,'{}')]); h.expect_raises('ZIP rejects '+label, UnsafeArchiveError, lambda p=zp: inspect_zip(p))
        # duplicate member
        dup=td/'dup.zip'
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            with zipfile.ZipFile(dup,'w') as z:
                z.writestr('root/a.json','{}'); z.writestr('root/a.json','{}')
        h.expect_raises('ZIP duplicate member rejected', UnsafeArchiveError, lambda: inspect_zip(dup))
        # symlink zip
        sl=td/'symlink.zip'; make_symlink_zip(sl); h.expect_raises('ZIP symlink member rejected', UnsafeArchiveError, lambda: inspect_zip(sl))
        # file/directory collision
        col=td/'collision.zip'; write_zip(col,[('root/a','x'),('root/a/b.json','{}')]); h.expect_raises('ZIP file-directory collision rejected', UnsafeArchiveError, lambda: inspect_zip(col))
        # archive limits using deliberately tiny policy
        lim=td/'limit.zip'; write_zip(lim,[('root/a.json','x'*1000)])
        pol=ZipSecurityPolicy(max_member_uncompressed=100,max_total_uncompressed=1000,max_compression_ratio=10000)
        h.expect_raises('ZIP member size policy enforced', UnsafeArchiveError, lambda: inspect_zip(lim, pol))
        pol2=ZipSecurityPolicy(max_member_uncompressed=10000,max_total_uncompressed=10000,max_compression_ratio=2)
        h.expect_raises('ZIP compression ratio policy enforced', UnsafeArchiveError, lambda: inspect_zip(lim, pol2))
        # valid zip catalogs
        good=td/'good.zip'; write_zip(good,[('root/identity/x.json','{"a":1}')])
        h.check('Valid ZIP catalogs successfully', lambda: catalog_zip(good, artifact='good.zip', subject='Good')['summary']['atoms']==1)
        # exact-value merge: normalized strings collide but must remain distinct
        s1=td/'s1'; s1.mkdir(); (s1/'identity').mkdir(); (s1/'identity'/'x.json').write_text('{"rules":["a  b"]}')
        s2=td/'s2'; s2.mkdir(); (s2/'identity').mkdir(); (s2/'identity'/'x.json').write_text('{"rules":["a b"]}')
        c1=catalog_directory(s1,artifact='s1',subject='S1'); c2=catalog_directory(s2,artifact='s2',subject='S2')
        # force these fixture atoms portable via a path classified control.rule
        merged=merge_reusable([c1,c2])
        vals=[x['value'] for x in merged['atoms'] if x['atom_type']=='control.rule']
        h.check('Reusable merge never conflates normalized-but-distinct values', lambda: 'a  b' in vals and 'a b' in vals and len(vals)==2)

    # Meta-tests: prove the validator catches deliberately injected failures.
    mv=copy.deepcopy(v); mv['atoms'][0]['activation_semantics']='ACTIVE'
    h.check('META validator catches activation mutation', lambda: any('activation semantics' in x for x in validate_catalog_internal(mv)))
    mv=copy.deepcopy(v); mv['atoms'][0]['atom_id']='atom:'+'0'*24
    h.check('META validator catches atom-ID mutation', lambda: any('atom_id mismatch' in x for x in validate_catalog_internal(mv)))
    mv=copy.deepcopy(v); mv['summary']['atoms']+=1
    h.check('META validator catches summary mutation', lambda: any('summary atom count mismatch' in x for x in validate_catalog_internal(mv)))
    mr=copy.deepcopy(r); mr['atoms'][0]['portable']=False
    h.check('META validator catches nonportable reuse mutation', lambda: any('non-portable' in x for x in validate_reusable_internal(mr)))
    mr=copy.deepcopy(r); mr['atoms'][0]['value']=str(mr['atoms'][0]['value'])+'tamper'
    h.check('META validator catches reusable value mutation', lambda: any('canonical value hash mismatch' in x for x in validate_reusable_internal(mr)))
    # schema mutation must be caught
    def schema_mutation():
        from jsonschema import Draft202012Validator, ValidationError
        from referencing import Registry, Resource
        cat_schema=json.loads((ROOT/'schemas/atomic_identity_catalog.schema.json').read_text()); atom_schema=json.loads((ROOT/'schemas/identity_atom.schema.json').read_text())
        bad=copy.deepcopy(v); del bad['atoms'][0]['canonical_value_sha256']
        registry=Registry().with_resources([(atom_schema['$id'],Resource.from_contents(atom_schema)),(cat_schema['$id'],Resource.from_contents(cat_schema))])
        try: Draft202012Validator(cat_schema,registry=registry).validate(bad)
        except ValidationError: return True
        return False
    h.check('META schema validator catches required-field deletion', schema_mutation)
    h.finish()

if __name__=='__main__': main()
