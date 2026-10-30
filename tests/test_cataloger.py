from pathlib import Path
import json, sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from identity_atomic.cataloger import iter_leaves, normalize, value_type, validate_catalog_internal, validate_reusable_internal

def main():
    checks=[]
    def ck(name,cond): checks.append((name,bool(cond)))
    ck('JSON pointer escaping', list(iter_leaves({'a/b':{'~x':1}}))==[('/a~1b/~0x',1)])
    ck('Boolean type not integer', value_type(True)=='boolean')
    ck('Integer type', value_type(1)=='integer')
    ck('Search normalization collapses whitespace', normalize(' a   b ' )=='a b')
    v=json.loads((ROOT/'catalogs/vesper_atomic_catalog.json').read_text()); c=json.loads((ROOT/'catalogs/corda_atomic_catalog.json').read_text()); r=json.loads((ROOT/'catalogs/reusable_atom_dictionary.json').read_text())
    ck('Vesper invariants', not validate_catalog_internal(v)); ck('Corda invariants',not validate_catalog_internal(c)); ck('Reusable invariants',not validate_reusable_internal(r))
    failed=[n for n,v in checks if not v]
    for n,v in checks: print(('PASS' if v else 'FAIL'),n)
    print(f'RESULT {len(checks)-len(failed)}/{len(checks)} PASS')
    if failed: raise SystemExit(1)
if __name__=='__main__': main()
