"""D3 INACTIVE, disposable local storage ONLY. No CLI, GitHub or live activation.

LocalWitness ports the D2 Domain protocol/record format. Coordinator adds
explicit stages and fail-closed outcomes; optional trusted operations keep the
existing D2 record format, local backend and inactive default.
"""
from pathlib import Path
import os,re,uuid
from importer import atomic
from git_transport import Lab,Session,MAIN,WITNESS,MANAGED,PROTECTED,git,value,files,state_commit,witness_commit,Reject,Conflict,relative
from importer import data,parse,digest,Store,external
from history_guard import check_history

def need(ok,msg):
 if not ok:raise Reject(msg)
def raw(repo,oid):return git(repo,'show',oid+':automation-state/registry.json').stdout
def ancestor(repo,a,b):return git(repo,'merge-base','--is-ancestor',a,b,allow=True).returncode==0

class LocalWitness:
 """Independent fixture storage, outside the primary rollback domain only.

 This is logical isolation on one machine. Exclusive creates/hash checks are
 NOT a demonstration of GitHub immutable Releases or physical WORM storage.
 """
 def __init__(self,lab,anchor,archives,genesis,library_id,primary_genesis,hit=lambda point:None):
  need(isinstance(lab,Lab),'DISPOSABLE_LAB_REQUIRED')
  self.library_id=library_id;self.primary_genesis=primary_genesis;self.hit=hit
  need(bool(re.fullmatch('[0-9a-f]{64}',genesis)),'PINNED_GENESIS_REQUIRED')
  self.lab=lab;self.anchor=lab.remote(anchor);self.archives=lab.path(archives);self.genesis=genesis
  need(self.archives.is_dir(),'INDEPENDENT_ARCHIVE_UNAVAILABLE')
 def job(self,name):
  p=self.lab.path(self.lab.root/'d2-runners'/(name+'-'+uuid.uuid4().hex));p.mkdir(parents=True);return p
 def read(self):
  need(self.archives.is_dir(),'INDEPENDENT_ARCHIVE_UNAVAILABLE')
  job=self.job('anchor-read');repo=job/'ledger'
  git(job,'clone','--no-local','--no-checkout',str(self.anchor),str(repo))
  tip=value(repo,'rev-parse',MAIN)
  names=git(repo,'ls-tree','-r','--name-only',tip).stdout.decode().splitlines()
  entries=sorted(n for n in names if n.startswith('records/'))
  need(entries and set(names)=={'anchor.json',*entries},'MISSING_OR_UNEXPECTED_ANCHOR_RECORD')
  records=[];previous=None
  for n,path in enumerate(entries):
   need(path==f'records/{n:08d}.json','ANCHOR_GAP')
   b=git(repo,'show',tip+':'+path).stdout;r=parse(b);self.validate_record(r)
   need(data(r)==b and r['index']==n and r['previous']==previous,'ANCHOR_CHAIN')
   if n==0:need(digest(b)==self.genesis,'INDEPENDENT_GENESIS_MISMATCH')
   else:
    old=records[-1]
    need(r['library_id']==old['library_id'] and r['registry_seq']>old['registry_seq'] and all(r['counters'][c]>=v for c,v in old['counters'].items()),'INDEPENDENT_HIGH_WATER_REGRESSION')
   records.append(r);previous=digest(b)
  need(git(repo,'show',tip+':anchor.json').stdout==data(records[-1]),'STALE_ANCHOR_POINTER')
  need(int(value(repo,'rev-list','--count',MAIN))==len(records),'ANCHOR_HISTORY_NOT_APPEND_ONLY')
  # Each commit must add precisely its next record; no rewritten/deleted prefix.
  commits=value(repo,'rev-list','--reverse',MAIN).splitlines()
  for i,commit in enumerate(commits):
   parents=value(repo,'show','-s','--format=%P',commit).split()
   need(parents==([] if i==0 else [commits[i-1]]),'ANCHOR_HISTORY_NOT_LINEAR')
   need(git(repo,'show',commit+':anchor.json').stdout==data(records[i]),'ANCHOR_HISTORY_CHANGED')
   need(git(repo,'show',commit+':'+f'records/{i:08d}.json').stdout==data(records[i]),'ANCHOR_HISTORY_CHANGED')
  recovered=job/'recovered.git';recovered.mkdir();git(recovered,'init','--bare','--initial-branch=main')
  full=max(i for i,r in enumerate(records) if r['backup']['full'])
  for r in records[full:]:self.import_backup(recovered,r)
  current=records[-1];reg=parse(raw(recovered,current['primary_main']))
  need(digest(raw(recovered,current['primary_main']))==current['registry_sha256'] and reg['seq']==current['registry_seq'] and reg['counters']==current['counters'] and reg['library_id']==current['library_id'],'RECOVERY_STATE_MISMATCH')
  # The last complete C1 history includes earlier records even across checkpoints.
  protected=files(recovered,current['primary_main'],PROTECTED)
  history=sorted((p,b) for p,b in protected.items() if p.startswith('automation-state/history/'))
  need(history and history[-1][1]==raw(recovered,current['primary_main']),'MISSING_RECOVERY_HISTORY')
  for a,b in zip(history,history[1:]):check_history(parse(b[1]),[parse(a[1])])
  for item in reg['items'].values():
   for obj in item['revisions']+([item['og']] if item['og'] else []):need(digest(protected[obj['blob']])==obj['sha256'],'RECOVERY_OBJECT_CORRUPT')
  for receipt in reg['receipts'].values():
   for p,h in receipt['input'].get('files',{}).items():need(digest(protected[receipt['input']['blobs'][p]])==h,'RECOVERY_RECEIPT_OBJECT_CORRUPT')
  self.verify_state(recovered,current)
  return {'job':job,'repo':repo,'tip':tip,'records':records,'latest':current,'recovered':recovered,'chain':records[full:]}
 def import_backup(self,repo,record):
  d=record['backup'];name=d['file'];need(name==d['sha256']+'.bundle','BACKUP_LOCATOR')
  p=self.lab.path(self.archives/name);need(p.is_file(),'LATEST_BACKUP_MISSING')
  b=p.read_bytes();need(len(b)==d['bytes'] and digest(b)==d['sha256'],'BACKUP_HASH_MISMATCH')
  # Consume exactly the verified bytes, not a second read of shared storage.
  verified=self.job('verified-bytes')/'backup.bundle'
  with verified.open('xb') as f:f.write(b);f.flush();os.fsync(f.fileno())
  git(repo,'bundle','verify',str(verified));git(repo,'bundle','unbundle',str(verified))
  need(value(repo,'rev-parse',record['primary_main']+'^{commit}')==record['primary_main'],'BACKUP_AUTHORITY_OBJECT_MISSING')
  need(value(repo,'rev-parse',record['primary_witness']+'^{commit}')==record['primary_witness'],'BACKUP_PRIMARY_WITNESS_MISSING')
 def record(self,repo,authority,witness,base,prior,index):
  reg=parse(raw(repo,authority))
  if prior:
   need(reg['seq']>prior['registry_seq'] and reg['library_id']==prior['library_id'] and all(reg['counters'][c]>=n for c,n in prior['counters'].items()),'PROPOSED_HIGH_WATER_REGRESSION')
   old=parse(raw(repo,prior['primary_main']));check_history(reg,[old])
  git(repo,'update-ref','refs/bgzona/backup-main',authority);git(repo,'update-ref','refs/bgzona/backup-witness',witness)
  target=self.job('backup')/'candidate.bundle';full=index%3==0
  args=['bundle','create',str(target),'refs/bgzona/backup-main','refs/bgzona/backup-witness']
  if prior and not full:args+=['^'+prior['primary_main'],'^'+prior['primary_witness']]
  git(repo,*args);git(repo,'bundle','verify',str(target));b=target.read_bytes();name=digest(b)+'.bundle';dest=self.lab.path(self.archives/name)
  self.hit('before-backup-complete')
  if dest.exists():need(dest.read_bytes()==b,'EXCLUSIVE_BACKUP_CONFLICT')
  else:
   with dest.open('xb') as f:
    half=len(b)//2;f.write(b[:half]);f.flush();os.fsync(f.fileno());self.hit('during-backup-write')
    f.write(b[half:]);f.flush();os.fsync(f.fileno())
  need(dest.read_bytes()==b,'BACKUP_READBACK')
  return {'schema':1,'index':index,'previous':digest(data(prior)) if prior else None,'library_id':reg['library_id'],'registry_seq':reg['seq'],'counters':reg['counters'],'registry_sha256':digest(raw(repo,authority)),
          'primary_main':authority,'primary_witness':witness,'primary_base':base,'phase':reg.get('transaction_status'),'operation':digest(data({'library':reg['library_id'],'seq':reg['seq'],'registry':digest(raw(repo,authority))})),
          'backup':{'file':name,'sha256':digest(b),'bytes':len(b),'full':full}}
 def _append_record(self,context,record):
  repo=context['repo'];index=context['job']/'ledger.index';env={'GIT_INDEX_FILE':str(index)}
  git(repo,'read-tree',context['tip'],env_extra=env)
  for p in ('anchor.json',f'records/{record["index"]:08d}.json'):
   oid=value(repo,'hash-object','-w','--stdin',stdin=data(record));git(repo,'update-index','--add','--cacheinfo','100644',oid,p,env_extra=env)
  tree=value(repo,'write-tree',env_extra=env);oid=value(repo,'commit-tree',tree,'-p',context['tip'],'-m','Append independent acceptance '+record['operation'])
  self.hit('during-independent-write')
  q=git(repo,'push',str(self.anchor),oid+':'+MAIN,allow=True)
  (context['job']/'anchor-push.json').write_bytes(data({'exit':q.returncode,'out':q.stdout.decode('utf8','replace'),'err':q.stderr.decode('utf8','replace')}))
  if q.returncode:raise Conflict('INDEPENDENT_ANCHOR_CAS_REJECTED')
  self.hit('independent-outcome-unknown')
  return record
 def reconcile(self,primary,*,publisher=None):
  if publisher is not None:
   need(type(publisher) is LocalD3Ports and publisher._issuer is _PORT_ISSUER,
        'UNTRUSTED_NATIVE_PUBLISHER')
   publisher.validate(*publisher.scope_args())
   need(publisher.mode=='LOCAL_NATIVE_TEST' and primary==publisher.scope[1],
        'D3_PORT_SCOPE_MISMATCH')
  context=self.read();r=context['latest'];job=self.job('reconcile');repo=job/'primary'
  git(job,'clone','--no-local','--no-checkout','--branch','main',str(self.lab.remote(primary)),str(repo))
  git(repo,'fetch',str(primary),WITNESS+':refs/bgzona/current-witness')
  current=value(repo,'rev-parse',MAIN);current_w=value(repo,'rev-parse','refs/bgzona/current-witness')
  for entry in context['chain']:self.import_backup(repo,entry)
  desired=files(repo,r['primary_main']);present=files(repo,current)
  if ancestor(repo,r['primary_main'],current) and {p:b for p,b in present.items() if p.startswith(PROTECTED)}=={p:b for p,b in desired.items() if p.startswith(PROTECTED)}:
   if current_w==r['primary_witness']:return {'aligned':True,'anchor_index':r['index'],'main':current}
   need(ancestor(repo,current_w,r['primary_witness']),'PRIMARY_WITNESS_DISAGREEMENT')
   self.hit('during-primary-write')
   if publisher is None:
    git(repo,'push','--atomic',str(primary),current+':'+MAIN,r['primary_witness']+':'+WITNESS)
   else:
    publisher.publish_pair(self,context,repo,(current,current_w),(current,r['primary_witness']),_issuer=_PORT_ISSUER)
   return {'aligned':True,'anchor_index':r['index'],'main':current,'restored':True,'witness_completed':True}
  preg=parse(present['automation-state/registry.json'])
  need(preg['library_id']==self.library_id,'PRIMARY_IDENTITY_MISMATCH')
  need(preg['seq']<=r['registry_seq'] and all(preg['counters'][c]<=n for c,n in r['counters'].items()),'MAIN_AHEAD_REQUIRES_ADOPTION')
  need(ancestor(repo,current_w,r['primary_witness']),'DIVERGENT_PRIMARY_WITNESS')
  common=value(repo,'merge-base',current,r['primary_main']);before=files(repo,common);merged=dict(present)
  for p in list(merged):
   if p.startswith(PROTECTED):del merged[p]
  merged.update({p:b for p,b in desired.items() if p.startswith(PROTECTED)})
  for p in set(before)|set(present)|set(desired):
   if not p.startswith(('incoming/','library/')):continue
   old=before.get(p);mine=present.get(p);accepted=desired.get(p)
   if mine!=old and accepted!=old and mine!=accepted:raise Reject('SOURCE_MERGE_CONFLICT_NO_DROP:'+p)
   chosen=accepted if accepted!=old else mine
   if chosen is None:merged.pop(p,None)
   else:merged[p]=chosen
  candidate=state_commit(repo,current,merged,job/'repair.index')
  if not ancestor(repo,r['primary_main'],current):
   candidate=value(repo,'commit-tree',value(repo,'rev-parse',candidate+'^{tree}'),'-p',current,'-p',r['primary_main'],'-m','Forward recovery from independent acceptance')
  self.hit('during-primary-write')
  if publisher is None:
   q=git(repo,'push','--atomic',str(primary),candidate+':'+MAIN,r['primary_witness']+':'+WITNESS,allow=True)
   if q.returncode:raise Conflict('PRIMARY_FORWARD_REPAIR_CONFLICT')
  else:
   publisher.publish_pair(self,context,repo,(current,current_w),(candidate,r['primary_witness']),_issuer=_PORT_ISSUER)
  return {'aligned':True,'anchor_index':r['index'],'main':candidate,'restored':True,'force':False}

 def validate_record(self,r):
  keys={'schema','index','previous','library_id','registry_seq','counters','registry_sha256','primary_main','primary_witness','primary_base','phase','operation','backup'}
  need(isinstance(r,dict) and set(r)==keys and type(r['schema'])==int and r['schema']==1,'ANCHOR_SCHEMA')
  need(type(r['index'])==int and r['index']>=0 and type(r['registry_seq'])==int and r['registry_seq']>=0,'ANCHOR_SEQUENCE')
  need(r['library_id']==self.library_id,'AUTHORITY_IDENTITY_MISMATCH')
  need(isinstance(r['counters'],dict) and set(r['counters'])=={'kolaji','poslaniya'} and all(type(n)==int and 0<=n<=99999 for n in r['counters'].values()),'ANCHOR_COUNTERS')
  for k in ('registry_sha256','operation'):
   need(isinstance(r[k],str) and re.fullmatch('[0-9a-f]{64}',r[k]),'ANCHOR_DIGEST')
  need(r['previous'] is None if r['index']==0 else isinstance(r['previous'],str) and re.fullmatch('[0-9a-f]{64}',r['previous']),'ANCHOR_PREVIOUS')
  for k in ('primary_main','primary_witness','primary_base'):
   need(isinstance(r[k],str) and re.fullmatch('[0-9a-f]{40}',r[k]),'ANCHOR_GIT_OID')
  need(r['phase'] in ('accepted','staged'),'AMBIGUOUS_TRANSACTION_STATE')
  need(r['operation']==digest(data({'library':r['library_id'],'seq':r['registry_seq'],'registry':r['registry_sha256']})),'OPERATION_DIGEST_MISMATCH')
  b=r['backup'];need(isinstance(b,dict) and set(b)=={'file','sha256','bytes','full'},'BACKUP_SCHEMA')
  need(isinstance(b['sha256'],str) and re.fullmatch('[0-9a-f]{64}',b['sha256']) and b['file']==b['sha256']+'.bundle' and type(b['bytes'])==int and b['bytes']>0 and type(b['full'])==bool,'BACKUP_IDENTITY')
  need(r['index']!=0 or b['full'],'INITIAL_FULL_BACKUP_REQUIRED')
 def verify_state(self,repo,r):
  self.validate_record(r);b=raw(repo,r['primary_main']);reg=parse(b)
  need(digest(b)==r['registry_sha256'] and reg['library_id']==r['library_id'] and reg['seq']==r['registry_seq'] and reg['counters']==r['counters'] and reg.get('transaction_status')==r['phase'],'RECOVERY_STATE_MISMATCH')
  need(ancestor(repo,r['primary_base'],r['primary_main']),'RECOVERY_BASE_NOT_ANCESTOR')
  # Only the private reconstructed bare repository receives these refs.
  git(repo,'update-ref',MAIN,r['primary_main']);git(repo,'update-ref',WITNESS,r['primary_witness'])
  validation=Session(self.lab,repo,self.primary_genesis)
  need(validation.anchor['authority']==r['primary_main'],'RECOVERY_WITNESS_AUTHORITY_MISMATCH')
  final=validation.store.show()  # rolls pending forward ONLY in a new external copy
  need(final['counters']==r['counters'],'RECOVERY_COUNTER_MISMATCH')
  if r['phase']=='accepted':need(final['seq']>r['registry_seq'],'PENDING_NOT_RECOVERABLE')
  else:need(data(final)==b,'FINAL_STATE_NOT_STABLE')
  return {'recoverable':True,'registry_sha256':digest(b),'phase':r['phase']}
 def verify_backup(self,context,record):
  self.validate_record(record)
  prior=context['latest'];need(record['index']==prior['index']+1 and record['previous']==digest(data(prior)),'CANDIDATE_CONTINUITY')
  need(record['registry_seq']>prior['registry_seq'] and all(record['counters'][c]>=n for c,n in prior['counters'].items()),'PROPOSED_HIGH_WATER_REGRESSION')
  self.import_backup(context['recovered'],record)
  check_history(parse(raw(context['recovered'],record['primary_main'])),[parse(raw(context['recovered'],prior['primary_main']))])
  return self.verify_state(context['recovered'],record)
 def append_verified(self,context,record):
  # Verification is repeated at the acceptance boundary; no caller boolean bypass.
  evidence=self.verify_backup(context,record)
  return self._append_record(context,record),evidence


class Interrupted(RuntimeError):pass



# E4I: in-process policy objects, NOT a registry/receipt/ledger schema.
# Issuance belongs to independently trusted setup code, never request JSON.
# Same-process hostile Python is not an authentication/isolation boundary.
from dataclasses import dataclass, asdict, field

_PORT_ISSUER = object()


class PortStop(Reject):
 def __init__(self,status,code):
  self.status=status if status in ('UNSUPPORTED','UNRESOLVED','SUSPENDED_FREE_QUOTA','REJECTED_AUTHORITY') else 'UNRESOLVED'
  self.code=code if isinstance(code,str) and re.fullmatch('[A-Z0-9_]{1,80}',code) else 'PROVIDER_UNAVAILABLE'
  super().__init__(self.code)


@dataclass(frozen=True,repr=False)
class DerivedFile:
 path:str
 private_path:str
 raw:object
 output:object
 role:str
 proof_sha256:str|None=None


@dataclass(frozen=True,repr=False)
class SourceBinding:
 owner_request_sha256:str
 raw_source:str
 raw_parent:str
 derived_repo:Path
 derived_source:str
 derived_parent:str
 derived_request_sha256:str
 files:tuple


@dataclass(frozen=True,repr=False)
class NativeIntent:
 """PRIVATE in-process capability, issued only by genuine D3 reconciliation.

 Not a durable queue or a permission against hostile code in this process.
 The original tuple is retained even if a later preparation produces another OID.
 """
 before:tuple
 after:tuple
 ledger_tip:str
 record_sha256:str
 request_sha256:str
 repo:Path
 _binding:object=field(repr=False)
 _domain:object=field(repr=False)
 _issuer:object=field(repr=False)
 recovered:bool=False
 checkpoint_sha:str|None=None


def native_intent_binding(intent,backend):
 """Authenticate the sealed binding before invoking any intent callback."""
 need(type(intent) is NativeIntent and intent._issuer is _PORT_ISSUER,'UNTRUSTED_NATIVE_INTENT')
 p=intent._binding
 need(type(p) is LocalD3Ports and p._issuer is _PORT_ISSUER and p.backend is backend and
      any(intent is old for old in p._intents),'UNTRUSTED_NATIVE_INTENT')
 return p


def verify_native_intent(intent,backend):
 """Reuse full D3 read/restore validation; never accept a verified flag."""
 p=native_intent_binding(intent,backend)
 p.validate(*p.scope_args())
 need(p.mode=='LOCAL_NATIVE_TEST' and backend.native is p._native_config,'NATIVE_MODE_REQUIRED')
 domain=intent._domain
 need(type(domain) is LocalWitness and domain.lab.root==p.scope[0] and
      domain.anchor==p.scope[2] and domain.archives==p.scope[3] and
      domain.genesis==p.scope[4] and domain.library_id==p.scope[5] and
      domain.primary_genesis==p.scope[6],'D3_PORT_SCOPE_MISMATCH')
 context=domain.read()  # Full existing history, backup, genesis and witness checks.
 r=context['latest']
 need(context['tip']==intent.ledger_tip and digest(data(r))==intent.record_sha256,
      'STALE_INDEPENDENT_ACCEPTANCE')
 need(intent.request_sha256==p.binding.owner_request_sha256,'REQUEST_SOURCE_BINDING_MISMATCH')
 repo=domain.lab.path(intent.repo)
 need(repo.is_dir() and intent.after[1]==r['primary_witness'],'NATIVE_TARGET_WITNESS')
 need(ancestor(repo,r['primary_main'],intent.after[0]) and
      files(repo,intent.after[0],PROTECTED)==files(context['recovered'],r['primary_main'],PROTECTED),
      'NATIVE_TARGET_AUTHORITY')
 need(all(ancestor(repo,a,b) for a,b in zip(intent.before,intent.after)), 'NATIVE_NON_FAST_FORWARD')
 if p._checkpoint_root is not None:p.checkpoint_verify(intent)
 return intent


@dataclass(frozen=True,repr=False)
class LocalD3Ports:
 """Sealed LOCAL factories + E4H read/admission gate. No remote transport.

 Backend decisions never grant writes: only genuine D3 under a marked Lab can
 mutate. PROVIDER_REQUIRED is explicit unsupported, with NO local fallback.
 """
 scope:tuple
 backend:object
 binding:SourceBinding
 demand:tuple
 mode:str
 domain_factory:object=field(repr=False)
 session_factory:object=field(repr=False)
 _policy_sha:str=field(repr=False)
 _backend_ports:object=field(repr=False)
 _issuer:object=field(repr=False)
 _native_config:object=field(default=None,repr=False)
 _intents:list=field(default_factory=list,repr=False,compare=False)
 _checkpoint_root:Path|None=field(default=None,repr=False)
 _fresh_records:set=field(default_factory=set,repr=False,compare=False)
 _private_recovery:object=field(default=None,repr=False,compare=False)

 def validate(self,lab,primary,anchor,archives,genesis,library_id,primary_genesis):
  import github_backend as gb
  need(type(self) is LocalD3Ports and self._issuer is _PORT_ISSUER,'UNTRUSTED_D3_PORTS')
  actual=(lab.root,lab.remote(primary),lab.remote(anchor),lab.path(archives),genesis,library_id,primary_genesis)
  need(actual==self.scope,'D3_PORT_SCOPE_MISMATCH')
  need(self.domain_factory is LocalWitness and self.session_factory is Session,'UNTRUSTED_D3_FACTORY')
  need(type(self.backend) is gb.Backend and type(self.backend.policy) is gb.Policy and
       self.backend.ports is self._backend_ports and
       digest(data(asdict(self.backend.policy)))==self._policy_sha,'TRUSTED_POLICY_CHANGED')
  need(self.backend.policy.library_id==library_id,'D3_PORT_LIBRARY_MISMATCH')
  if self.mode=='PROVIDER_REQUIRED':
   raise PortStop('UNSUPPORTED','NATIVE_ATOMIC_UNSUPPORTED')
  need(self.mode in ('LOCAL_LAB','LOCAL_NATIVE_TEST'),'D3_PORT_MODE')
  if self.mode=='LOCAL_NATIVE_TEST':
   need(self.backend.native is self._native_config and self._native_config is not None,'TRUSTED_POLICY_CHANGED')

 def domain(self,lab,primary,anchor,archives,genesis,library_id,primary_genesis,hit):
  self.validate(lab,primary,anchor,archives,genesis,library_id,primary_genesis)
  return self.domain_factory(lab,anchor,archives,genesis,library_id,primary_genesis,hit)

 def session(self,lab,primary,primary_genesis):
  need(self._issuer is _PORT_ISSUER and self.session_factory is Session,'UNTRUSTED_D3_FACTORY')
  need(lab.root==self.scope[0] and lab.remote(primary)==self.scope[1] and
       primary_genesis==self.scope[6],'D3_PORT_SCOPE_MISMATCH')
  return self.session_factory(lab,primary,primary_genesis)

 def checkpoint_identity(self):
  # PRIVATE source commitments only; no raw bytes, names, keys or public upload.
  b=self.binding;n=self.backend.native
  return {'schema':1,'scope':digest(data([str(v) for v in self.scope])),
      'policy':self._policy_sha,'repository':n.repository.numeric_id,'node':n.node_id,
      'actor':n.actor_id,'source':[b.owner_request_sha256,b.raw_source,b.raw_parent,
          b.derived_source,b.derived_parent,b.derived_request_sha256],
      'derivation':digest(data([asdict(f) for f in b.files]))}

 def checkpoint_read(self,path):
  try:
   self.scope_args()[0].path(path)
   need(path.is_file() and path.stat().st_nlink==1 and path.stat().st_size<=65536,
        'PRIVATE_CHECKPOINT_MISSING')
   b=path.read_bytes();e=parse(b)
   need(type(e) is dict and set(e)=={'sha256','checkpoint'} and
        e['sha256']==digest(data(e['checkpoint'])) and data(e)==b,'PRIVATE_CHECKPOINT_CORRUPT')
   return e['checkpoint'],e['sha256']
  except PortStop:raise
  except Exception:
   raise PortStop('UNRESOLVED','PRIVATE_CHECKPOINT_INVALID') from None

 def checkpoint_create(self,path,payload):
  # Existing D3 exclusive-write/fsync pattern. A torn file is retained and STOPs.
  b=data({'sha256':digest(data(payload)),'checkpoint':payload})
  with path.open('xb') as f:f.write(b);f.flush();os.fsync(f.fileno())
  need(path.read_bytes()==b,'PRIVATE_CHECKPOINT_READBACK')

 def checkpoint_open(self,initialize=False):
  if self._checkpoint_root is None:
   need(not initialize,'PRIVATE_CHECKPOINT_REQUIRED');return
  need(self.mode=='LOCAL_NATIVE_TEST','D3_PORT_MODE')
  root=external(self._checkpoint_root);self.scope_args()[0].path(root)
  for forbidden in (self.scope[1],self.scope[2],self.scope[3],self.binding.derived_repo):
   need(not root.is_relative_to(forbidden) and not forbidden.is_relative_to(root),
        'PRIVATE_CHECKPOINT_SCOPE')
  if initialize:
   need(not root.exists(),'PRIVATE_CHECKPOINT_ALREADY_EXISTS')
   domain=LocalWitness(self.scope_args()[0],self.scope[2],self.scope[3],self.scope[4],self.scope[5],self.scope[6])
   c=domain.read();r=c['latest']
   root.mkdir(parents=True)
   self.checkpoint_create(root/'identity.json',self.checkpoint_identity()|{
       'origin':{'tip':c['tip'],'index':r['index'],'record':digest(data(r))}})
  header,_=self.checkpoint_read(root/'identity.json')
  need(type(header) is dict and set(header)==set(self.checkpoint_identity())|{'origin'} and
       {k:header[k] for k in self.checkpoint_identity()}==self.checkpoint_identity() and
       type(header['schema']) is int and type(header['origin']) is dict and
       set(header['origin'])=={'tip','index','record'},
       'PRIVATE_CHECKPOINT_IDENTITY')

 def checkpoint_path(self,record_sha,suffix='intent'):
  need(bool(re.fullmatch('[0-9a-f]{64}',record_sha)) and suffix in ('intent','attempt','result'),
       'PRIVATE_CHECKPOINT_LOCATOR')
  return self._checkpoint_root/(record_sha+'.'+suffix+'.json')

 def checkpoint_load(self,context):
  self.checkpoint_open();header,_=self.checkpoint_read(self._checkpoint_root/'identity.json')
  origin=header['origin'];records=context['records']
  need(type(origin['index']) is int and 0<=origin['index']<len(records) and
       digest(data(records[origin['index']]))==origin['record'],'PRIVATE_CHECKPOINT_ORIGIN')
  commits=value(context['repo'],'rev-list','--reverse',MAIN).splitlines()
  need(commits[origin['index']]==origin['tip'],'PRIVATE_CHECKPOINT_ORIGIN')
  key=digest(data(context['latest']));path=self.checkpoint_path(key)
  if not path.exists():
   need(not any(x.record_sha256==key for x in self._intents),'PRIVATE_INTENT_MISSING')
   need(key in self._fresh_records or key==origin['record'],'PRIVATE_INTENT_MISSING')
   return None
  row,sha=self.checkpoint_read(path)
  keys={'schema','record','ledger','index','operation','phase','receipts','before','after','repo'}
  need(type(row) is dict and set(row)==keys and type(row['schema']) is int and row['schema']==1 and
       type(row['index']) is int and
       row['record']==key and row['ledger']==context['tip'] and
       row['index']==context['latest']['index'] and
       row['operation']==context['latest']['operation'] and row['phase']==context['latest']['phase'] and
       row['receipts']==digest(data(parse(raw(context['recovered'],context['latest']['primary_main']))['receipts'])) and
       type(row['before']) is list and type(row['after']) is list and
       len(row['before'])==len(row['after'])==2 and type(row['repo']) is str,
       'PRIVATE_INTENT_MISMATCH')
  for suffix in ('attempt','result'):
   p=self.checkpoint_path(key,suffix)
   if p.exists():
    event,_=self.checkpoint_read(p)
    if suffix=='attempt':
     need(event=={'intent':sha,'status':'MAY_HAVE_SENT'},'PRIVATE_ATTEMPT_MISMATCH')
    else:
     import github_backend as gb
     need(type(event) is dict and set(event)=={'intent','status','reason'} and event['intent']==sha and
          gb.Result(event['status'],event['reason']).status==event['status'] and
          gb.Result(event['status'],event['reason']).reason==event['reason'],'PRIVATE_RESULT_MISMATCH')
  return row,sha

 def checkpoint_restore(self,domain,context,loaded):
  row,sha=loaded;repo=self.scope_args()[0].path(self.scope[0].joinpath(*relative(row['repo']).parts))
  intent=NativeIntent(tuple(row['before']),tuple(row['after']),row['ledger'],row['record'],
      self.binding.owner_request_sha256,repo,self,domain,_PORT_ISSUER,True,sha)
  self._intents.append(intent)
  verify_native_intent(intent,self.backend)
  return intent

 def checkpoint_verify(self,intent):
  self.checkpoint_open();row,sha=self.checkpoint_read(self.checkpoint_path(intent.record_sha256))
  need(sha==intent.checkpoint_sha and row['record']==intent.record_sha256 and row['ledger']==intent.ledger_tip and
       tuple(row['before'])==intent.before and tuple(row['after'])==intent.after and
       self.scope[0]/row['repo']==intent.repo,'PRIVATE_INTENT_MISMATCH')

 def accepted(self,domain,record,*,_issuer):
  need(_issuer is _PORT_ISSUER,'UNTRUSTED_NATIVE_INTENT')
  if self._checkpoint_root is None:return
  self.validate(*self.scope_args());self.checkpoint_open()
  context=domain.read()
  need(context['latest']==record,'STALE_INDEPENDENT_ACCEPTANCE')
  self._fresh_records.add(digest(data(record)))

 def reserve_native_attempt(self,intent):
  if self._checkpoint_root is None:return
  verify_native_intent(intent,self.backend)
  need(not intent.recovered,'PRIVATE_INTENT_REPLAY_FORBIDDEN')
  self.checkpoint_create(self.checkpoint_path(intent.record_sha256,'attempt'),
                         {'intent':intent.checkpoint_sha,'status':'MAY_HAVE_SENT'})
  if self._private_recovery is not None:
   import github_backend as gb
   need(type(self._private_recovery) is gb.PrivateRecovery,'UNTRUSTED_PRIVATE_RECOVERY')
   packet,_=portable_native_export(intent,self.backend)
   r=self._private_recovery
   r.persist(intent.request_sha256,intent.record_sha256,packet)
   r.claim(intent.request_sha256,intent.record_sha256,digest(packet))
   r.verify_claim(intent.request_sha256,intent.record_sha256,digest(packet))
   # Remote persistence can take time: independently revalidate at the send boundary.
   verify_native_intent(intent,self.backend)
   r.verify_claim(intent.request_sha256,intent.record_sha256,digest(packet))
  intent._domain.hit('native-before-mutation')

 def complete_native_attempt(self,result):
  intent=result.pending
  if self._checkpoint_root is None or type(intent) is not NativeIntent:return
  need(intent._binding is self and any(intent is x for x in self._intents),'UNTRUSTED_NATIVE_INTENT')
  self.checkpoint_verify(intent)
  payload={'intent':intent.checkpoint_sha,'status':result.status,'reason':result.reason}
  atomic(self.checkpoint_path(intent.record_sha256,'result'),
         data({'sha256':digest(data(payload)),'checkpoint':payload}))
  intent._domain.hit('native-result-durable')

 def reconcile(self,domain,primary):
  self.validate(*self.scope_args())
  need(primary==self.scope[1],'D3_PORT_SCOPE_MISMATCH')
  if self._checkpoint_root is not None:
   try:
    context=domain.read();loaded=self.checkpoint_load(context)
    if loaded is not None:
     intent=self.checkpoint_restore(domain,context,loaded)
     result=self.backend.atomic_authority_update(intent,dict(self.demand))
     if result.status!='ATOMIC_OBSERVED_INACTIVE':raise PortStop('UNRESOLVED',result.reason)
     return {'aligned':True,'anchor_index':context['latest']['index'],'main':intent.after[0],
             'restored':True,'intent_recovered':True}
   except PortStop:raise
   except Exception:raise PortStop('UNRESOLVED','PRIVATE_INTENT_RECOVERY_STOP') from None
  return domain.reconcile(primary,publisher=self if self.mode=='LOCAL_NATIVE_TEST' else None)

 def publish_pair(self,domain,context,repo,before,after,*,_issuer):
  import github_backend as gb
  need(_issuer is _PORT_ISSUER and self.mode=='LOCAL_NATIVE_TEST','UNTRUSTED_NATIVE_INTENT')
  self.validate(*self.scope_args())
  r=context['latest']
  intent=NativeIntent(tuple(before),tuple(after),context['tip'],digest(data(r)),
       self.binding.owner_request_sha256,repo,self,domain,_PORT_ISSUER)
  if self._checkpoint_root is not None:
   loaded=self.checkpoint_load(context)
   if loaded is not None:
    intent=self.checkpoint_restore(domain,context,loaded)
   else:
    need(intent.record_sha256 in self._fresh_records,'PRIVATE_INTENT_MISSING')
    reg=parse(raw(context['recovered'],r['primary_main']))
    row={'schema':1,'record':intent.record_sha256,'ledger':intent.ledger_tip,'index':r['index'],
        'operation':r['operation'],'phase':r['phase'],'receipts':digest(data(reg['receipts'])),
        'before':list(intent.before),'after':list(intent.after),
        'repo':repo.relative_to(self.scope[0]).as_posix()}
    try:
     self.checkpoint_create(self.checkpoint_path(intent.record_sha256),row)
     intent=NativeIntent(intent.before,intent.after,intent.ledger_tip,intent.record_sha256,
          intent.request_sha256,repo,self,domain,_PORT_ISSUER,False,digest(data(row)))
    except FileExistsError:
     intent=self.checkpoint_restore(domain,context,self.checkpoint_load(context))
  self._intents.append(intent)
  verify_native_intent(intent,self.backend)
  if self._checkpoint_root is not None and not intent.recovered:domain.hit('native-intent-durable')
  result=self.backend.atomic_authority_update(intent,dict(self.demand))
  need(type(result) is gb.Result,'UNTRUSTED_PROVIDER_RESULT')
  if result.status not in ('ATOMIC_APPLIED_INACTIVE','ATOMIC_OBSERVED_INACTIVE'):
   status=result.status if result.status in ('UNSUPPORTED','SUSPENDED_FREE_QUOTA') else 'UNRESOLVED'
   raise PortStop(status,result.reason)

 def bind_operation(self,operation):
  # Fixed genuine E4G operation, not an arbitrary callback/verified flag.
  from request_executor import RequestOperation
  b=self.binding
  need(type(operation) is RequestOperation and type(b) is SourceBinding,'REQUEST_OPERATION_REQUIRED')
  need(operation.source==b.derived_repo and operation.change['commit']==b.derived_source and
       operation.before['commit']==b.derived_parent and operation.request==b.derived_request_sha256,
       'REQUEST_SOURCE_BINDING_MISMATCH')
  changed={p for p,raw_bytes in operation.new.items() if operation.old.get(p)!=raw_bytes}
  need(len(b.files)==len({f.path for f in b.files}) and {f.path for f in b.files}==changed,
       'DERIVED_MANIFEST_BINDING_MISMATCH')

 def gate(self,context,operation):
  """D3 context is read by the real LocalWitness, NEVER by owner documents."""
  import github_backend as gb
  def checked(result,expected):
   if type(result) is not gb.Result:
    raise PortStop('UNRESOLVED','UNTRUSTED_PROVIDER_RESULT')
   if result.status!=expected:
    status=result.status if result.status in ('UNSUPPORTED','UNRESOLVED','SUSPENDED_FREE_QUOTA') else 'REJECTED_AUTHORITY'
    raise PortStop(status,result.reason if result.reason!='OK' else 'PROVIDER_CAPABILITY_UNSUPPORTED')
   return result.payload
  try:
   self.validate(*self.scope_args())
   self.bind_operation(operation)
   r=context['latest'];reg=parse(raw(context['recovered'],r['primary_main']))
   # Dynamic authority pins come from genuine independently restored D3 state.
   # Raw and derived request/source identities are deliberately DISTINCT.
   b=self.binding
   pins=gb.StatePins(b.owner_request_sha256,b.raw_source,b.raw_parent,
       value(self.scope[1],'rev-parse',MAIN),r['primary_main'],r['primary_witness'],
       context['tip'],digest(data(r)),digest(data(reg['receipts'])))
   checked(self.backend.admit(pins,dict(self.demand)),'ADMITTED_SIMULATION')
   for f in b.files:
    private=checked(self.backend.read_source(pins,f.private_path,f.raw),'PRIVATE_BYTES_SIMULATED')
    if f.role=='txt':
     need(f.raw==f.output,'TXT_DERIVATION_CHANGED_BYTES')
     ready=checked(self.backend.intentional_txt(pins,private,f.private_path),'INTENTIONAL_TXT_SIMULATED')
    else:
     ready=checked(self.backend.verify_derivation(pins,private,f.output,f.proof_sha256,f.role),
                   'DERIVATION_BOUND_SIMULATED')
    output=checked(self.backend.public_preview(ready),'PUBLIC_BYTES_PREVIEW_ONLY')
    need(output==operation.new[f.path] and digest(output)==f.output.sha256 and
         len(output)==f.output.size,'DERIVED_BYTES_BINDING_MISMATCH')
  except PortStop:
   raise
  except Reject:
   raise  # Internal static rejection codes; never provider exception text.
  except Exception:
   raise PortStop('UNRESOLVED','PROVIDER_UNAVAILABLE') from None

 def scope_args(self):
  # Rehydrate only the already marked Lab; no widening of local-only guards.
  return (Lab(self.scope[0]),*self.scope[1:])


def trusted_local_ports(lab,primary,anchor,archives,genesis,library_id,primary_genesis,*,
                        backend,binding,demand,mode='LOCAL_LAB',
                        domain_factory=LocalWitness,session_factory=Session,durable=False,initialize_checkpoint=False,private_recovery=None):
 """Trusted configuration API, not owner request input or write authorization."""
 import github_backend as gb
 from intake_plan import _path
 need(isinstance(lab,Lab) and type(backend) is gb.Backend and
      type(backend.policy) is gb.Policy and type(backend.ports) is gb.OfflinePorts,'UNTRUSTED_D3_PORTS')
 need(type(binding) is SourceBinding and type(binding.files) is tuple and
      gb.sha(binding.owner_request_sha256) and gb.sha(binding.derived_request_sha256) and
      all(gb.oid(x) for x in (binding.raw_source,binding.raw_parent,binding.derived_source,binding.derived_parent)),
      'INVALID_SOURCE_BINDING')
 need(domain_factory is LocalWitness and session_factory is Session,'UNTRUSTED_D3_FACTORY')
 need(mode in ('LOCAL_LAB','LOCAL_NATIVE_TEST','PROVIDER_REQUIRED'),'D3_PORT_MODE')
 source=lab.remote(binding.derived_repo)
 need(source==binding.derived_repo,'D3_PORT_SCOPE_MISMATCH')
 for f in binding.files:
  need(type(f) is DerivedFile and type(f.raw) is gb.ObjectPin and type(f.output) is gb.ObjectPin and
       f.role in ('original','og','txt'),'INVALID_DERIVED_BINDING')
  _path(f.path);_path(f.private_path)
  need(f.role=='txt' or gb.sha(f.proof_sha256),'INVALID_DERIVED_BINDING')
 need(type(demand) is dict and demand and all(type(k) is str and type(v) is int and v>=0
      for k,v in demand.items()),'INVALID_RESOURCE_DEMAND')
 scope=(lab.root,lab.remote(primary),lab.remote(anchor),lab.path(archives),genesis,library_id,primary_genesis)
 need(scope[1]!=scope[2],'INDEPENDENT_REMOTE_REQUIRED')
 need(type(durable) is bool and type(initialize_checkpoint) is bool and
      (not durable or mode=='LOCAL_NATIVE_TEST'),'PRIVATE_CHECKPOINT_MODE')
 need(private_recovery is None or (type(private_recovery) is gb.PrivateRecovery and
      private_recovery.repository==backend.repos['intake'] and durable and mode=='LOCAL_NATIVE_TEST'),
      'UNTRUSTED_PRIVATE_RECOVERY')
 checkpoint=lab.path(lab.root/'private-native-intents'/binding.owner_request_sha256) if durable else None
 result=LocalD3Ports(scope,backend,binding,tuple(sorted(demand.items())),mode,
       domain_factory,session_factory,digest(data(asdict(backend.policy))),backend.ports,_PORT_ISSUER,
       backend.native if mode=='LOCAL_NATIVE_TEST' else None,[],checkpoint,set(),private_recovery)
 result.checkpoint_open(initialize_checkpoint)
 return result


class Coordinator:
 """One bounded event; durable truth is ALWAYS the independent record.

 Observer files are diagnostic; PRIVATE native checkpoints bound I/O replay,
 never allocation authority.
 Fault callbacks are for disposable tests. No operational GitHub backend exists.
 """
 def __init__(self,lab,primary,anchor,archives,genesis,library_id,primary_genesis,interrupt=None,*,operation=None,integration=None):
  need(isinstance(lab,Lab),'DISPOSABLE_LAB_REQUIRED');self.lab=lab
  self.primary=lab.remote(primary);self.primary_genesis=primary_genesis
  self.interrupt=interrupt or (lambda point:None)
  self.operation=operation  # Trusted in-process port; local backend/guards unchanged.
  self.integration=integration
  if integration is None:
   self.domain=LocalWitness(lab,anchor,archives,genesis,library_id,primary_genesis,self.interrupt)
  else:
   need(type(integration) is LocalD3Ports,'UNTRUSTED_D3_PORTS')
   self.domain=integration.domain(lab,primary,anchor,archives,genesis,library_id,primary_genesis,self.interrupt)
   integration.bind_operation(operation)
  need(self.primary!=self.domain.anchor,'INDEPENDENT_REMOTE_REQUIRED')
 def run(self,max_steps=6):
  job=self.domain.job('coordinator');trace=[];accepted=None;changed=False;where='evidence'
  def stage(state,**detail):
   trace.append({'state':state,**detail});atomic(job/'trace.json',data(trace))
  def result(status,reason=None,eligible=False):
   out={'status':status,'reason':reason,'stage':trace[-1]['state'] if trace else 'START','accepted':accepted,'trace':trace,'projection_eligible':eligible,'live_activation':False,'evidence_path':str(job)}
   atomic(job/'outcome.json',data(out));return out
  try:
   need(type(max_steps)==int and 1<=max_steps<=12,'BOUNDED_STEPS_REQUIRED')
   for attempt in range(max_steps):
    where='evidence';context=self.domain.read();accepted=context['latest'];stage('EVIDENCE_VERIFIED',index=accepted['index'])
    if self.operation is not None:self.operation.bind(context)
    where='primary';repair=(self.domain.reconcile(self.primary) if self.integration is None else
                          self.integration.reconcile(self.domain,self.primary))
    if repair.get('restored'):
     changed=True;stage('PRIMARY_RECONCILED',index=accepted['index']);self.interrupt('after-primary-before-observed')
    if self.integration is not None:self.integration.gate(context,self.operation)
    where='primary';s=(Session(self.lab,self.primary,self.primary_genesis) if self.integration is None else
                       self.integration.session(self.lab,self.primary,self.primary_genesis))
    where='candidate';candidate=s.prepare(self.operation)
    if candidate is None:
     latest=self.domain.read()['latest']
     if latest!=accepted:continue
     need(accepted['phase']=='staged','NOT_FINAL_NO_PUBLICATION')
     if self.operation is not None:
      self.interrupt('before-final-request-verification')
      if self.integration is not None:self.integration.gate(context,self.operation)
      self.operation.verify_final(s,context)
     stage('RECONCILED_FINAL',index=accepted['index'])
     return result('RECONCILED' if changed else 'ALREADY_PROCESSED',eligible=True)
    changed=True;stage('CANDIDATE_PREPARED',seq=candidate['seq']);self.interrupt('after-candidate')
    where='backup';record=self.domain.record(s.repo,candidate['authority'],candidate['witness'],candidate['base'],accepted,accepted['index']+1)
    self.domain.verify_backup(context,record);stage('BACKUP_VERIFIED',sha256=record['backup']['sha256']);self.interrupt('after-backup-before-acceptance')
    if self.integration is not None:self.integration.gate(context,self.operation)
    where='acceptance';self.domain.append_verified(context,record);accepted=record
    if self.integration is not None:self.integration.accepted(self.domain,record,_issuer=_PORT_ISSUER)
    stage('INDEPENDENT_ACCEPTED',index=record['index'])
    stage('PRIMARY_INCOMPLETE',index=record['index']);self.interrupt('after-independent-acceptance')
    where='primary'
    if self.integration is None:self.domain.reconcile(self.primary)
    else:self.integration.reconcile(self.domain,self.primary)
    stage('PRIMARY_RECONCILED',index=record['index']);self.interrupt('after-primary-before-observed')
   return result('UNRESOLVED','BOUNDED_RETRY_LIMIT')
  except PortStop as e:return result(e.status,e.code)
  except Interrupted as e:return result('UNRESOLVED' if str(e)=='independent-outcome-unknown' else 'RECOVERABLE_INTERRUPTION',str(e))
  except Exception as e:
   reason=str(e)
   if isinstance(e,(Conflict,)) or 'OUTCOME_UNCERTAIN' in reason:
    return result('UNRESOLVED',reason)
   if not isinstance(e,(Reject,ValueError,KeyError,TypeError,OSError)):
    raise  # programming errors must fail tests, not masquerade as guarded rejection
   if where=='backup' or any(x in reason for x in ('BACKUP_','ARCHIVE_CORRUPT','RECOVERY_OBJECT')):status='REJECTED_BACKUP'
   elif any(x in reason for x in ('UNAVAILABLE','MISSING_OR_UNEXPECTED_ANCHOR','LATEST_BACKUP_MISSING')) or (where=='evidence' and ('GIT_FAILED' in reason or isinstance(e,FileNotFoundError))):status='REJECTED_MISSING_EVIDENCE'
   elif where=='primary' and 'IDENTITY' not in reason:status='REJECTED_GIT_STATE'
   else:status='REJECTED_AUTHORITY'
   return result(status,reason)


def run_local(lab,primary,anchor,archives,genesis,library_id,primary_genesis,interrupt=None,max_steps=6):
 """Structured entry point, including unavailable/invalid initial configuration."""
 try:return Coordinator(lab,primary,anchor,archives,genesis,library_id,primary_genesis,interrupt).run(max_steps)
 except (Reject,OSError,ValueError) as e:
  reason=str(e);missing=any(x in reason for x in ('UNAVAILABLE','LOCAL_BARE_TEST_REMOTE_REQUIRED','No such file','cannot find'))
  return {'status':'REJECTED_MISSING_EVIDENCE' if missing else 'REJECTED_GIT_STATE','reason':reason,'stage':'CONFIGURATION','accepted':None,'trace':[],'projection_eligible':False,'live_activation':False,'evidence_path':None}



# PRIVATE transport envelope only; C1/D2/D3 authoritative records are unchanged.
def portable_native_trust(ports,record,ledger,*,before,after):
 h=ports.checkpoint_identity()
 return {k:h[k] for k in ('source','policy','repository','node','actor','derivation')}|{
     'genesis':ports.scope[4],'library_id':ports.scope[5],'primary_genesis':ports.scope[6],
     'record':record,'ledger':ledger,'before':list(before),'after':list(after)}


def portable_native_export(intent,backend):
 """Genuine D3 validation BEFORE export. No raw owner repository or credentials.

 The returned trust pins must be obtained independently on recovery, NEVER
 promoted to authority merely because they accompany this PRIVATE packet.
 """
 import base64
 verify_native_intent(intent,backend);p=native_intent_binding(intent,backend)
 need(p._checkpoint_root is not None and not intent.recovered,'PRIVATE_EXPORT_REQUIRES_ORIGINAL')
 d=intent._domain;c=d.read();row,sha=p.checkpoint_load(c)
 need(sha==intent.checkpoint_sha,'PRIVATE_INTENT_MISMATCH')
 trust=portable_native_trust(p,intent.record_sha256,intent.ledger_tip,before=intent.before,after=intent.after)
 enc=lambda b:base64.b64encode(b).decode('ascii')
 roles={
  'primary':(p.scope[1],{MAIN:value(p.scope[1],'rev-parse',MAIN),WITNESS:value(p.scope[1],'rev-parse',WITNESS)}),
  'anchor':(p.scope[2],{MAIN:intent.ledger_tip,'refs/heads/automation-control':p.backend.policy.code_oid,
                        'refs/heads/verification-code':p.backend.policy.verifier_code_oid}),
  'prepared':(intent.repo,{MAIN:intent.after[0],WITNESS:intent.after[1]}),
  'derived':(p.binding.derived_repo,{MAIN:p.binding.derived_source})}
 need(tuple(roles['primary'][1].values())==intent.before,'PRIVATE_EXPORT_STALE_PAIR')
 repos={}
 for name,(repo,refs) in roles.items():
  roots=list(refs.values())
  if name=='prepared':roots+=list(intent.before)+[p.scope[6]]
  if name=='derived':roots.append(p.binding.derived_parent)
  ids=sorted({line.split()[0] for line in value(repo,'rev-list','--objects',*roots).splitlines()})
  need(0<len(ids)<=4096 and all(re.fullmatch('[0-9a-f]{40}',v) for v in ids),'PORTABLE_OBJECT_LIMIT')
  pack=git(repo,'pack-objects','--stdout',stdin=('\n'.join(ids)+'\n').encode()).stdout
  need(len(pack)<=8_000_000,'PORTABLE_OBJECT_LIMIT')
  repos[name]={'refs':refs,'pack':enc(pack),'sha256':digest(pack),'objects':ids}
 backups={}
 for r in c['chain']:
  b=p.scope[3]/r['backup']['file'];raw_bytes=b.read_bytes()
  need(digest(raw_bytes)==r['backup']['sha256'],'BACKUP_HASH_MISMATCH')
  backups[b.name]=enc(raw_bytes)
 original={}
 for suffix in ('intent','attempt','result'):
  path=p.checkpoint_path(intent.record_sha256,suffix)
  if path.exists():original[suffix]=enc(path.read_bytes())
 original['identity']=enc((p._checkpoint_root/'identity.json').read_bytes())
 payload={'format':'bgzona-private-native-r1','trust':trust,'repos':repos,'backups':backups,'checkpoint':original}
 raw_bytes=data(payload);need(len(raw_bytes)<=12_000_000,'PORTABLE_OBJECT_LIMIT')
 return raw_bytes,trust


def portable_native_restore(packet,lab,*,expected,backend,binding,demand):
 """Restore into NEW disposable paths; verify against independently supplied pins.

 Never execute files/config/hooks from the packet, never import old .git/config,
 and never deserialize Python callbacks. Rebuilt intent is always recovered.
 """
 import base64
 from dataclasses import replace
 need(isinstance(lab,Lab) and type(packet) is bytes and len(packet)<=12_000_000,'PORTABLE_OBJECT_LIMIT')
 payload=parse(packet)
 need(type(payload) is dict and set(payload)=={'format','trust','repos','backups','checkpoint'} and
      payload['format']=='bgzona-private-native-r1' and data(payload)==packet and
      type(expected) is dict and payload['trust']==expected,'PRIVATE_PORTABLE_IDENTITY')
 need(set(expected)=={'source','policy','repository','node','actor','derivation','genesis','library_id',
                     'primary_genesis','record','ledger','before','after'},'PRIVATE_PORTABLE_IDENTITY')
 # Expected pins are caller's trusted source/D3 profile, not packet assertions.
 root=lab.path(lab.root/'private-portable');need(not root.exists(),'NEW_PORTABLE_WORKSPACE_REQUIRED');root.mkdir()
 decode=lambda s:base64.b64decode(s,validate=True)
 roles=payload['repos'];need(type(roles) is dict and set(roles)=={'primary','anchor','prepared','derived'},'PORTABLE_ROLES')
 for name,row in roles.items():
  need(type(row) is dict and set(row)=={'refs','pack','sha256','objects'},'PORTABLE_REPO')
  refs=row['refs'];allowed={MAIN,WITNESS} if name in ('primary','prepared') else (
      {MAIN,'refs/heads/automation-control','refs/heads/verification-code'} if name=='anchor' else {MAIN})
  need(type(refs) is dict and set(refs)==allowed and all(re.fullmatch('[0-9a-f]{40}',v) for v in refs.values()),'PORTABLE_REFS')
  pack=decode(row['pack']);need(len(pack)<=8_000_000 and digest(pack)==row['sha256'],'PORTABLE_PACK_HASH')
  ids=row['objects'];need(type(ids) is list and 0<len(ids)<=4096 and ids==sorted(set(ids)) and
                         all(type(v) is str and re.fullmatch('[0-9a-f]{40}',v) for v in ids),'PORTABLE_OBJECT_LIMIT')
  repo=root/(name+'.git');repo.mkdir();git(repo,'init','--bare','--initial-branch=main')
  git(repo,'unpack-objects','-r',stdin=pack)
  # Check every advertised object, not just the ref names or JSON checksum.
  actual=value(repo,'cat-file','--batch-all-objects','--batch-check=%(objectname)').splitlines()
  need(sorted(actual)==ids,'PORTABLE_OBJECT_SET')
  for ref,target in refs.items():
   need(value(repo,'rev-parse',target+'^{commit}')==target,'PORTABLE_COMMIT_IDENTITY')
   git(repo,'update-ref',ref,target)
  git(repo,'fsck','--strict','--no-reflogs')
 archives=root/'archives';archives.mkdir();backups=payload['backups']
 need(type(backups) is dict and 0<len(backups)<=64,'PORTABLE_BACKUP_LIMIT')
 for name,encoded in backups.items():
  need(type(name) is str and re.fullmatch(r'[0-9a-f]{64}\.bundle',name),'BACKUP_LOCATOR')
  raw_bytes=decode(encoded);need(len(raw_bytes)<=8_000_000 and digest(raw_bytes)==name[:-7],'BACKUP_HASH_MISMATCH')
  with (archives/name).open('xb') as f:f.write(raw_bytes);f.flush();os.fsync(f.fileno())
 binding=replace(binding,derived_repo=root/'derived.git')
 p=trusted_local_ports(lab,root/'primary.git',root/'anchor.git',archives,expected['genesis'],
      expected['library_id'],expected['primary_genesis'],backend=backend,binding=binding,demand=demand,
      mode='LOCAL_NATIVE_TEST')
 need(portable_native_trust(p,expected['record'],expected['ledger'],before=expected['before'],after=expected['after'])==expected,'PRIVATE_PORTABLE_IDENTITY')
 domain=p.domain(*p.scope_args(),lambda point:None);c=domain.read()
 need(c['tip']==expected['ledger'] and digest(data(c['latest']))==expected['record'],'STALE_INDEPENDENT_ACCEPTANCE')
 need(roles['anchor']['refs'][MAIN]==expected['ledger'] and
      roles['derived']['refs'][MAIN]==binding.derived_source,'PRIVATE_PORTABLE_IDENTITY')
 original=payload['checkpoint'];need(type(original) is dict and {'identity','intent'}<=set(original)<=
                                  {'identity','intent','attempt','result'},'PRIVATE_CHECKPOINT_MISSING')
 # Original R3 envelopes retain their exact bytes inside the packet. Only local
 # locator bindings are reissued after full D3 validation; OIDs never change.
 def envelope(name):
  b=decode(original[name]);e=parse(b)
  need(type(e) is dict and set(e)=={'sha256','checkpoint'} and data(e)==b and
       e['sha256']==digest(data(e['checkpoint'])),'PRIVATE_CHECKPOINT_CORRUPT')
  return e['checkpoint'],e['sha256']
 header,_=envelope('identity');row,old_sha=envelope('intent')
 need(type(header) is dict and set(header)==set(p.checkpoint_identity())|{'origin'},'PRIVATE_CHECKPOINT_IDENTITY')
 need({k:v for k,v in header.items() if k not in ('scope','origin')}==
      {k:v for k,v in p.checkpoint_identity().items() if k!='scope'},'PRIVATE_CHECKPOINT_IDENTITY')
 need(type(row) is dict and row.get('ledger')==expected['ledger'] and row.get('record')==expected['record'],
      'PRIVATE_INTENT_MISMATCH')
 # Pack's concrete before/after targets remain exactly those originally issued.
 need(row.get('after')==[roles['prepared']['refs'][MAIN],roles['prepared']['refs'][WITNESS]] and
      row.get('before')==[roles['primary']['refs'][MAIN],roles['primary']['refs'][WITNESS]] and
      row.get('before')==expected['before'] and row.get('after')==expected['after'],'PRIVATE_INTENT_MISMATCH')
 p=replace(p,_checkpoint_root=lab.path(lab.root/'private-native-intents'/binding.owner_request_sha256))
 need(not p._checkpoint_root.exists(),'NEW_PORTABLE_WORKSPACE_REQUIRED');p._checkpoint_root.mkdir(parents=True)
 p.checkpoint_create(p._checkpoint_root/'identity.json',p.checkpoint_identity()|{'origin':header['origin']})
 row=row|{'repo':(root/'prepared.git').relative_to(lab.root).as_posix()}
 p.checkpoint_create(p.checkpoint_path(expected['record']),row);new_sha=digest(data(row))
 for suffix in ('attempt','result'):
  if suffix in original:
   event,_=envelope(suffix);need(type(event) is dict and event.get('intent')==old_sha,'PRIVATE_ATTEMPT_MISMATCH')
   p.checkpoint_create(p.checkpoint_path(expected['record'],suffix),event|{'intent':new_sha})
 loaded=p.checkpoint_load(c);intent=p.checkpoint_restore(domain,c,loaded)
 return p,intent
