"""Offline allowlisted Pages construction. No writes to source/Git/settings/network."""
from pathlib import Path, PurePosixPath
import argparse,hashlib,json,os,re,stat,subprocess,sys

DOMAIN='media.bgzona.win'
LEGACY={f'kolaji/full/bgzona-p-{n:05d}.jpg' for n in range(1,47)}
LEGACY.update('slideshow/'+n for n in ('gallery.json','slideshow.json','slideshow-exclude.json'))
COMPAT={'index.html','assets/css/style.css'}
PUBLIC=LEGACY|COMPAT
class Reject(RuntimeError):pass
def need(ok,msg):
    if not ok:raise Reject(msg)
def digest(b):return hashlib.sha256(b).hexdigest()
def data(v):return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode('utf-8')
def parse(b):
    try:return json.loads(b.decode('utf-8-sig','strict'))
    except (UnicodeError,ValueError) as e:raise Reject('INVALID_UTF8_JSON') from e
def relative(rel):
    need(isinstance(rel,str) and bool(re.fullmatch(r'[A-Za-z0-9._/-]+',rel)),'UNSAFE_PATH')
    p=PurePosixPath(rel)
    need(not p.is_absolute() and bool(p.parts) and str(p)==rel and all(not x.startswith('.') and not x.endswith('.') for x in p.parts),'UNSAFE_PATH')
    return p
def unlinked(path):
    p=Path(path).absolute()
    for x in (p,*p.parents):need(not x.is_symlink() and not (hasattr(x,'is_junction') and x.is_junction()),'LINK_PATH')
    return p
def external(path):
    p=unlinked(path)
    need(not any((x/'.git').exists() for x in (p,*p.parents)),'EXTERNAL_OUTPUT_REQUIRED')
    return p
def safe_file(base,rel):
    p=unlinked(Path(base).joinpath(*relative(rel).parts));need(p.is_relative_to(Path(base).absolute()),'UNSAFE_PATH')
    need(p.is_file(),'MISSING_REQUIRED_FILE:'+rel);s=p.stat()
    need(stat.S_ISREG(s.st_mode) and s.st_nlink==1,'NONREGULAR_OR_HARDLINK:'+rel)
    need(s.st_size<=50_000_000,'FILE_SIZE_LIMIT');return p
def policy(path):
    p=parse(Path(path).read_bytes())
    need(set(p)=={'schema','domain','files'} and p['schema']==1 and p['domain']==DOMAIN and isinstance(p['files'],list),'POLICY_SCHEMA')
    seen=set();rows=[]
    for e in p['files']:
        need(isinstance(e,dict) and set(e)=={'path','source'},'POLICY_ENTRY')
        rel=e['path'];relative(rel);fold=rel.casefold();need(fold not in seen,'DUPLICATE_OUTPUT_PATH');seen.add(fold)
        need(rel in PUBLIC,'PATH_NOT_ALLOWLISTED:'+rel)
        need(e['source']==('repository' if rel in LEGACY else 'compat'),'SOURCE_MAPPING_NOT_ALLOWED')
        rows.append(e)
    need({r['path'] for r in rows}==PUBLIC,'REQUIRED_ALLOWLIST_INCOMPLETE')
    return sorted(rows,key=lambda r:r['path'])

class Source:
    def __init__(self,root,commit=None):
        self.root=unlinked(root);need(self.root.is_dir(),'SOURCE_DIRECTORY_REQUIRED');self.commit=commit
        if commit:
            need(bool(re.fullmatch('[0-9a-f]{40}',commit)),'EXACT_COMMIT_REQUIRED')
            need(self.git('rev-parse','--verify',commit+'^{commit}').decode().strip()==commit,'COMMIT_RESOLUTION')
    def git(self,*args):
        env=dict(os.environ);env['GIT_NO_LAZY_FETCH']='1'
        q=subprocess.run(['git','--no-optional-locks','-C',str(self.root),*args],capture_output=True,env=env,timeout=30)
        need(q.returncode==0,'READONLY_GIT_FAILED');return q.stdout
    def read(self,rel):
        relative(rel)
        if not self.commit:return safe_file(self.root,rel).read_bytes()
        tree=self.git('ls-tree','-z',self.commit,'--',rel).split(b'\0')
        need(len(tree)==2 and tree[-1]==b'' and b'\t' in tree[0],'MISSING_REQUIRED_FILE:'+rel)
        header,name=tree[0].split(b'\t',1);parts=header.split()
        need(name==rel.encode('ascii') and parts[0]==b'100644' and parts[1]==b'blob','GIT_PUBLIC_FILE_TYPE')
        b=self.git('cat-file','blob',parts[2].decode('ascii'));need(len(b)<=50_000_000,'FILE_SIZE_LIMIT');return b

def compatibility(root,manifest):
    root=unlinked(root);rows=parse(Path(manifest).read_bytes());need(isinstance(rows,list),'COMPAT_SCHEMA')
    need(len(rows)==2 and {r['path'] for r in rows}==COMPAT,'COMPAT_EXACT_SET')
    buffers={}
    for r in rows:
        need(set(r)=={'path','bytes','sha256'},'COMPAT_SCHEMA');b=safe_file(root,r['path']).read_bytes()
        need(len(b)==r['bytes'] and digest(b)==r['sha256'],'COMPAT_SHA_OR_SIZE');buffers[r['path']]=b
    return buffers
def inventory(root):
    rows=[];dirs=set();root=unlinked(root)
    need(root.is_dir(),'OUTPUT_DIRECTORY_REQUIRED')
    for folder,children,files in os.walk(root,followlinks=False):
        for name in children:
            p=unlinked(Path(folder)/name);rel=p.relative_to(root).as_posix();relative(rel);dirs.add(rel)
        for name in files:
            p=Path(folder)/name;rel=p.relative_to(root).as_posix();b=safe_file(root,rel).read_bytes()
            rows.append({'path':rel,'bytes':len(b),'sha256':digest(b)})
    allowed_dirs={str(p) for rel in PUBLIC for p in PurePosixPath(rel).parents if str(p)!='.'}
    need(dirs==allowed_dirs,'UNEXPECTED_OUTPUT_DIRECTORY')
    return sorted(rows,key=lambda r:r['path'])
def verify(output,manifest,expected_tree):
    m=parse(Path(manifest).read_bytes());need(m.get('schema')==1 and m.get('domain')==DOMAIN,'MANIFEST_SCHEMA')
    rows=m.get('files');need(isinstance(rows,list) and len(rows)==51 and {r['path'] for r in rows}==PUBLIC,'MANIFEST_EXACT_SET')
    for r in rows:
        relative(r['path']);need(set(r)=={'path','bytes','sha256'} and type(r['bytes'])==int and bool(re.fullmatch('[0-9a-f]{64}',r['sha256'])),'MANIFEST_ENTRY')
    need(rows==sorted(rows,key=lambda r:r['path']) and len({r['path'].casefold() for r in rows})==51,'MANIFEST_ORDER_OR_DUPLICATE')
    actual=digest(data(rows));need(actual==m.get('tree_sha256')==expected_tree,'TRUSTED_TREE_DIGEST_MISMATCH')
    need(inventory(output)==rows,'OUTPUT_EXACT_SET_OR_HASH')
    return {'status':'VERIFIED_LOCALLY','files':51,'tree_sha256':actual}
def build(source,compat,allowlist,compat_manifest,output,manifest,commit=None):
    source=Source(source,commit);rows=policy(allowlist);compat_root=unlinked(compat)
    output=external(output);manifest=external(manifest)
    need(not output.exists() and not manifest.exists(),'NEW_OUTPUT_AND_MANIFEST_REQUIRED')
    need(not manifest.is_relative_to(output),'MANIFEST_MUST_STAY_OUTSIDE_PUBLIC')
    for protected in (source.root,compat_root):
        need(not output.is_relative_to(protected) and not protected.is_relative_to(output),'OUTPUT_SOURCE_OVERLAP')
        need(not manifest.is_relative_to(protected),'MANIFEST_SOURCE_OVERLAP')
    cname=source.read('CNAME');need(cname.decode('ascii','strict').strip()==DOMAIN,'CNAME_DOMAIN_MISMATCH')
    comp=compatibility(compat_root,compat_manifest)
    buffers={e['path']:(source.read(e['path']) if e['source']=='repository' else comp[e['path']]) for e in rows}
    need(sum(map(len,buffers.values()))<=500_000_000,'OUTPUT_SIZE_LIMIT')
    # JSON is checked, not re-serialized: its exact source bytes enter the output.
    arrays={}
    for name in ('gallery.json','slideshow.json','slideshow-exclude.json'):
        a=parse(buffers['slideshow/'+name]);need(isinstance(a,list) and all(isinstance(x,str) for x in a),'LEGACY_JSON_SCHEMA')
        need(len(set(a))==len(a),'LEGACY_JSON_DUPLICATE')
        for rel in a:need(rel.startswith('/') and rel[1:] in LEGACY and rel.startswith('/kolaji/full/'),'LEGACY_JSON_PATH')
        arrays[name]=a
    need(arrays['slideshow.json']==[x for x in arrays['gallery.json'] if x not in arrays['slideshow-exclude.json']],'LEGACY_SLIDESHOW_RELATION')
    need('/assets/css/style.css' in buffers['index.html'].decode('utf-8'),'COMPAT_CSS_REFERENCE')
    records=[{'path':rel,'bytes':len(b),'sha256':digest(b)} for rel,b in sorted(buffers.items())]
    tree=digest(data(records))
    # All required reads/validation succeed before any output is created.
    output.mkdir(parents=True)
    for rel,b in buffers.items():
        p=output.joinpath(*relative(rel).parts);p.parent.mkdir(parents=True,exist_ok=True)
        with p.open('xb') as f:f.write(b)
    result={'schema':1,'domain':DOMAIN,'source':{'mode':'git' if commit else 'working-tree','commit':commit},
            'CNAME_source_control':{'bytes':len(cname),'sha256':digest(cname),'published':False},'files':records,'tree_sha256':tree}
    manifest.parent.mkdir(parents=True,exist_ok=True)
    with manifest.open('xb') as f:f.write(data(result)+b'\n')
    verify(output,manifest,tree)
    return {'status':'PROVEN_LOCALLY_NOT_DEPLOYED','files':51,'bytes':sum(r['bytes'] for r in records),'tree_sha256':tree,'manifest':str(manifest)}
def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='operation',required=True)
    b=sub.add_parser('build')
    for name in ('source','compat','allowlist','compat-manifest','output','manifest'):b.add_argument('--'+name,type=Path,required=True)
    b.add_argument('--git-commit')
    v=sub.add_parser('verify');v.add_argument('--output',type=Path,required=True);v.add_argument('--manifest',type=Path,required=True);v.add_argument('--expected-tree',required=True)
    a=p.parse_args()
    if a.operation=='verify':result=verify(a.output,a.manifest,a.expected_tree)
    else:result=build(a.source,a.compat,a.allowlist,a.compat_manifest,a.output,a.manifest,a.git_commit)
    print(json.dumps(result,sort_keys=True))
if __name__=='__main__':
    try:main()
    except (Reject,OSError,ValueError,KeyError,TypeError) as e:raise SystemExit('PUBLIC_BUILD_REJECT: '+str(e))
