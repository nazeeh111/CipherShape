"""Verify the portable synthetic record, not cryptographic correctness of a server."""
from pathlib import Path
import json,hashlib,math
P=Path(__file__).resolve().parent
def load(n): return json.loads((P/n).read_text())
m=load('bundle-manifest.json')
for f in m['files']:
 b=(P/f['path']).read_bytes(); assert len(b)==f['bytes'] and hashlib.sha256(b).hexdigest()==f['sha256'],f['path']
r=load('analytics-report.json'); d=load('error-points.json'); fixtures=load('synthetic-inputs.json')['requests']; assert r['accepted'] and len(r['runs'])==2
for i,(run,xy) in enumerate(zip(r['runs'],fixtures)):
 x,y=xy['x'],xy['y'];n=len(x);mx,my=sum(x)/n,sum(y)/n
 refs={'mean_x':mx,'mean_y':my,'variance_x':sum((v-mx)**2 for v in x)/n,'variance_y':sum((v-my)**2 for v in y)/n,'covariance':sum((a-mx)*(b-my) for a,b in zip(x,y))/n,'score_x':sum(v*(j+1)/(n*n) for j,v in enumerate(x)),'score_y':sum(v*(j+1)/(n*n) for j,v in enumerate(y))}
 assert all(math.isclose(refs[k],run['original_float'][k],abs_tol=1e-15,rel_tol=0) for k in refs)
 errors=[abs(run['decrypted'][k]-run['approximated_plaintext'][k]) for k in d['names']];assert errors==d['errors'][i] and max(errors)==run['encryption_error']
 assert run['accepted'] and run['approximation_error']+max(errors)<=d['tolerance'] and run['max_nonresult_slot']<=d['tolerance']
c=load('controls.json');assert c['client_range_refused_before_publication'] and c['response_request_binding_refused'] and c['existing_client_report_preserved'] and all(t['different'] for t in c['same_input_fresh_encryption'])
print(json.dumps({'bundle_members_verified':len(m['files']),'requests':2,'outputs_checked':14,'independent_float_references':True,'client_checks_recomputed':True,'scope':'Synthetic recorded-data verification; no fresh encryption or malicious-server proof'},indent=2))
