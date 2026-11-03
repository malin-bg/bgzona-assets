"""D1 local-only Git transport. No GitHub URLs, credentials or live activation.

All writes require an explicitly created disposable Lab. C1 runs only in a
separate non-Git transaction directory. A reservation is durable/assigned only
when an atomic, non-forced push accepts main AND the metadata witness ref.
"""
from pathlib import Path, PurePosixPath
import json, os, re, subprocess, uuid
from importer import Store, Reject, Crash, external, data, digest, parse
from history_guard import check_history

MAIN='refs/heads/main'
WITNESS='refs/bgzona/witness'
MANAGED=('automation-state/','objects/','library/','incoming/')
PROTECTED=('automation-state/','objects/')

class Conflict(Reject):pass
class Uncertain(Reject):pass

def require(ok,message):
    if not ok:raise Reject(message)

def relative(name):
    p=PurePosixPath(name)
    require(not p.is_absolute() and str(p)==name and '..' not in p.parts and
            not any(c in name for c in ('\\',':','\0')) and
            not any(ord(c)<32 for c in name),'UNSAFE_GIT_PATH')
    require(all(part.casefold()!='.git' for part in p.parts),'UNSAFE_GIT_PATH')
    return p

def git(repo,*args,stdin=None,env_extra=None,allow=False):
    # No user/system config, credential helpers, signing or network transports.
    env=dict(os.environ)
    for key in list(env):
        if key.startswith('GIT_'):del env[key]
    env.update(GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL=os.devnull,
               GIT_TERMINAL_PROMPT='0',GIT_NO_LAZY_FETCH='1',
               GIT_AUTHOR_NAME='BGZONA disposable test',GIT_AUTHOR_EMAIL='fixture@invalid',
               GIT_COMMITTER_NAME='BGZONA disposable test',GIT_COMMITTER_EMAIL='fixture@invalid')
    if env_extra:env.update(env_extra)
    try:
        q=subprocess.run(['git','--no-optional-locks','-c','core.autocrlf=false',
                          '-c','protocol.allow=never','-c','protocol.file.allow=always',
                          '-C',str(repo),*args],input=stdin,capture_output=True,env=env,timeout=45)
    except subprocess.TimeoutExpired as e:raise Uncertain('GIT_OUTCOME_UNCERTAIN_RECLONE_NO_NEW_IDS') from e
    if not allow:require(q.returncode==0,'GIT_FAILED:'+q.stderr.decode('utf8','replace'))
    return q

def value(repo,*args,**kw):return git(repo,*args,**kw).stdout.decode('utf8').strip()

class Lab:
    """Only a NEW external fixture root can enable this implementation's writes."""
    @classmethod
    def create(cls,path):
        root=external(path);require(not root.exists(),'NEW_DISPOSABLE_LAB_REQUIRED')
        root.mkdir(parents=True)
        (root/'.bgzona-disposable.json').write_bytes(data({'schema':1,'purpose':'D1-disposable-only','nonce':uuid.uuid4().hex}))
        return cls(root)
    def __init__(self,path):
        self.root=external(path)
        require(parse((self.root/'.bgzona-disposable.json').read_bytes()).get('purpose')=='D1-disposable-only','DISPOSABLE_LAB_REQUIRED')
    def path(self,path):
        p=Path(path).absolute();require(p!=self.root and p.is_relative_to(self.root),'OUTSIDE_DISPOSABLE_LAB')
        for x in (p,*p.parents):
            if x==self.root:break
            require(not x.is_symlink() and not (hasattr(x,'is_junction') and x.is_junction()),'LINK_PATH')
        return p
    def remote(self,path):
        p=self.path(path)
        require(p.is_dir() and value(p,'rev-parse','--is-bare-repository')=='true','LOCAL_BARE_TEST_REMOTE_REQUIRED')
        return p

def files(repo,commit,prefixes=MANAGED):
    result={};folded=set();entries=[]
    for row in git(repo,'ls-tree','-r','-z',commit).stdout.split(b'\0'):
        if not row:continue
        header,name=row.split(b'\t',1);name=name.decode('utf8','strict')
        if not name.startswith(prefixes):continue
        relative(name);mode,kind,oid=header.split()
        require(mode==b'100644' and kind==b'blob','MANAGED_GIT_TYPE')
        require(name.casefold() not in folded,'CASE_COLLISION');folded.add(name.casefold())
        require(not name.endswith('.tmp') and name!='automation-state/.lock','EPHEMERAL_STATE_COMMITTED')
        entries.append((name,oid))
    if entries:
        raw=git(repo,'cat-file','--batch',stdin=b''.join(oid+b'\n' for _,oid in entries)).stdout
        offset=0
        for name,oid in entries:
            end=raw.index(b'\n',offset);header=raw[offset:end].split()
            require(len(header)==3 and header[:2]==[oid,b'blob'],'BATCH_OBJECT_MISMATCH')
            size=int(header[2]);require(0<=size<=50_000_000,'OBJECT_SIZE_LIMIT')
            start=end+1;result[name]=raw[start:start+size];offset=start+size
            require(len(result[name])==size and raw[offset:offset+1]==b'\n','BATCH_OBJECT_TRUNCATED');offset+=1
        require(offset==len(raw),'BATCH_OBJECT_EXTRA_DATA')
    return result

def snapshot(root):
    result={}
    for folder in ('automation-state','objects','library','incoming'):
        base=root/folder
        if not base.exists():continue
        for p in base.rglob('*'):
            require(not p.is_symlink() and not (hasattr(p,'is_junction') and p.is_junction()),'LINK_PATH')
            if p.is_dir():continue
            name=p.relative_to(root).as_posix();relative(name)
            if name=='automation-state/.lock' or name.endswith('.tmp'):continue
            require(p.is_file() and p.stat().st_nlink==1,'NONREGULAR_STATE')
            result[name]=p.read_bytes()
    return result

def state_commit(repo,base,buffers,index,message=None):
    """Private index: preserve every unrelated source/legacy object unchanged."""
    env={'GIT_INDEX_FILE':str(index)}
    git(repo,'read-tree',base,env_extra=env)
    old=files(repo,base)
    updates=[]
    for p in sorted(set(old)-set(buffers)):updates.append(b'0 '+b'0'*40+b'\t'+p.encode('utf8')+b'\0')
    changed=[(p,b) for p,b in sorted(buffers.items()) if old.get(p)!=b]
    if changed:
        blobdir=index.with_suffix('.blobs');require(not blobdir.exists(),'NEW_BLOB_STAGING_REQUIRED');blobdir.mkdir()
        paths=[]
        for n,(p,b) in enumerate(changed):
            require(p.startswith(MANAGED),'STATE_SCOPE_ESCAPE');relative(p)
            path=blobdir/str(n);path.write_bytes(b);paths.append(path)
        quoted=''.join(json.dumps(p.as_posix(),ensure_ascii=False)+'\n' for p in paths).encode('utf8')
        oids=git(repo,'hash-object','-w','--no-filters','--stdin-paths',stdin=quoted).stdout.splitlines()
        require(len(oids)==len(changed) and all(re.fullmatch(b'[0-9a-f]{40}',x) for x in oids),'HASH_BATCH_MISMATCH')
        for (p,_),oid in zip(changed,oids):updates.append(b'100644 '+oid+b'\t'+p.encode('utf8')+b'\0')
    if updates:git(repo,'update-index','-z','--index-info',stdin=b''.join(updates),env_extra=env)
    tree=value(repo,'write-tree',env_extra=env)
    if message is None:message='MEDIA: durable state transaction '+uuid.uuid4().hex
    require(isinstance(message,str) and 0<len(message)<=16384 and '\0' not in message,'INVALID_STATE_BINDING')
    return value(repo,'commit-tree',tree,'-p',base,'-m',message)

def witness_commit(repo,authority,registry,previous=None):
    metadata={'schema':1,'authority':authority,'library_id':registry['library_id'],
              'seq':registry['seq'],'counters':registry['counters'],
              'registry_sha256':digest(data(registry)),'previous':previous}
    oid=value(repo,'hash-object','-w','--stdin',stdin=data(metadata))
    tree=value(repo,'mktree',stdin=('100644 blob '+oid+'\twitness.json\n').encode())
    args=['commit-tree',tree,'-m','MEDIA: append-only state witness']
    if previous:args+=['-p',previous]
    return value(repo,*args)

class Session:
    def __init__(self,lab,remote,trusted_genesis):
        require(isinstance(lab,Lab),'DISPOSABLE_LAB_REQUIRED')
        self.lab=lab;self.remote=lab.remote(remote)
        require(bool(re.fullmatch('[0-9a-f]{40}',trusted_genesis)),'PINNED_WITNESS_GENESIS_REQUIRED')
        self.genesis=trusted_genesis;self.job=lab.path(lab.root/'runners'/uuid.uuid4().hex)
        self.job.mkdir(parents=True);self.repo=self.job/'checkout'
        git(self.job,'clone','--no-local','--no-checkout','--branch','main','--',str(self.remote),str(self.repo))
        git(self.repo,'fetch','--no-tags','origin',WITNESS+':refs/bgzona/observed-witness')
        self.base=value(self.repo,'rev-parse',MAIN);self.witness=value(self.repo,'rev-parse','refs/bgzona/observed-witness')
        self._validate_chain()
        buffers=files(self.repo,self.base)
        protected={p:b for p,b in buffers.items() if p.startswith(PROTECTED)}
        require(protected==files(self.repo,self.anchor['authority'],PROTECTED),'UNWITNESSED_AUTHORITY_EDIT_OR_ROLLBACK')
        self.root=self.job/'transaction';self.root.mkdir()
        for p,b in buffers.items():
            dest=self.root.joinpath(*relative(p).parts);dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(b)
        self.external_witness=self.job/'rehydrated-witness.json'
        self.external_witness.write_bytes(data({k:self.anchor[k] for k in ('library_id','seq')}|{'sha256':self.anchor['registry_sha256']}))
        self.store=Store(self.root,self.external_witness,history_repo=self.repo)
        self.candidate=None
    def _validate_chain(self):
        current=self.witness;newer=None;seen=set();self.anchor=None
        while True:
            require(current not in seen,'WITNESS_CYCLE');seen.add(current)
            tree=git(self.repo,'ls-tree','--name-only',current).stdout
            require(tree==b'witness.json\n','WITNESS_IS_METADATA_ONLY')
            w=parse(git(self.repo,'show',current+':witness.json').stdout)
            require(set(w)=={'schema','authority','library_id','seq','counters','registry_sha256','previous'} and w['schema']==1,'WITNESS_SCHEMA')
            raw=git(self.repo,'show',w['authority']+':automation-state/registry.json').stdout;r=parse(raw)
            require(digest(raw)==w['registry_sha256'] and data(r)==raw and all(r[k]==w[k] for k in ('library_id','seq','counters')),'WITNESS_STATE_MISMATCH')
            require(isinstance(r.get('bootstrap'),dict) and r['bootstrap'].get('archive_sha256')==StoreBootstrap,'UNTRUSTED_FROZEN_BASELINE')
            require(git(self.repo,'merge-base','--is-ancestor',w['authority'],self.base,allow=True).returncode==0,'MAIN_BEHIND_WITNESS')
            if newer:
                require(newer['library_id']==w['library_id'] and newer['seq']>w['seq'] and all(newer['counters'][c]>=n for c,n in w['counters'].items()),'WITNESS_COUNTER_ROLLBACK')
                require(git(self.repo,'merge-base','--is-ancestor',w['authority'],newer['authority'],allow=True).returncode==0,'WITNESS_AUTHORITY_FORK')
                check_history(parse(git(self.repo,'show',newer['authority']+':automation-state/registry.json').stdout),[r])
            if self.anchor is None:self.anchor=w
            parents=value(self.repo,'show','-s','--format=%P',current).split()
            if current==self.genesis:
                require(w['previous'] is None and not parents,'INVALID_PINNED_GENESIS');break
            require(w['previous'] and parents==[w['previous']],'WITNESS_CHAIN_OR_GENESIS_MISSING')
            newer=w;current=w['previous']
    def prepare(self,operation=None):
        require(self.candidate is None,'SESSION_ALREADY_PREPARED')
        if operation is None:
            bound=git(self.repo,'show','-s','--format=%B',self.anchor['authority']).stdout
            require(not bound.startswith(b'BGZONA-E4G '),'REQUEST_EXECUTOR_REQUIRED')
        before=(self.root/'automation-state/registry.json').read_bytes()
        # show performs exact C1 journal roll-forward before any new admission.
        self.store.show()
        recovered=(self.root/'automation-state/registry.json').read_bytes()!=before
        if recovered:phase='recovery-final'
        else:
            try:
                if operation is None:self.store.add(fault='after-reserve')
                else:operation.apply(self)
                phase='metadata-final'
            except Crash as e:
                require(str(e)=='AFTER_RESERVATION','UNEXPECTED_CORE_CRASH');phase='reservation'
        raw=(self.root/'automation-state/registry.json').read_bytes()
        if raw==before:return None
        reg=parse(raw)
        message=operation.message(self) if operation is not None else None
        authority=state_commit(self.repo,self.base,snapshot(self.root),self.job/'state.index',message=message)
        witness=witness_commit(self.repo,authority,reg,self.witness)
        self.candidate={'authority':authority,'witness':witness,'base':self.base,'previous_witness':self.witness,'phase':phase,'registry_sha256':digest(raw),'seq':reg['seq'],'counters':reg['counters']}
        (self.job/'candidate.json').write_bytes(data(self.candidate))
        return dict(self.candidate)
    def publish(self):
        require(self.candidate is not None,'NO_VALIDATED_CANDIDATE')
        require(self.lab.remote(self.remote)==self.remote,'REMOTE_BOUNDARY_CHANGED')
        c=self.candidate
        q=git(self.repo,'push','--atomic',str(self.remote),c['authority']+':'+MAIN,c['witness']+':'+WITNESS,allow=True)
        (self.job/'push-result.json').write_bytes(data({'exit':q.returncode,'out':q.stdout.decode('utf8','replace'),'err':q.stderr.decode('utf8','replace')}))
        if q.returncode:raise Conflict('ATOMIC_UPDATE_REJECTED_RECLONE_VALIDATE_RETRY; candidate retained at '+str(self.job))
        # A concurrent later update is allowed; the accepted candidate remains an ancestor.
        return {'status':'DURABLE_IN_LOCAL_TEST_REMOTE','phase':c['phase'],'authority':c['authority'],'witness':c['witness'],'seq':c['seq'],'counters':c['counters']}

from importer import BOOTSTRAP_SHA as StoreBootstrap
