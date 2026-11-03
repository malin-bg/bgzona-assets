"""Offline shared importer adapted from BGZONA-003A3; no Git writes/publication."""
from pathlib import Path, PurePosixPath
from contextlib import contextmanager
from copy import deepcopy
from io import BytesIO
import argparse, base64, hashlib, json, os, time, uuid, re, sys, zipfile
from PIL import Image
from history_guard import check_history, read_git_history

COLS={'kolaji':'p','poslaniya':'m'}
STATES=('published','archived')  # Permanent removal remains unavailable.
EXTS={'.jpg':'JPEG','.jpeg':'JPEG','.png':'PNG','.webp':'WEBP','.gif':'GIF'}
BOOTSTRAP_SHA='35054cbed0f49ff6a9e656d46c7952bd3c903e6d2fc37dcbfd51d7987800b049'
class Reject(RuntimeError):pass
class Crash(RuntimeError):pass
def data(o):return json.dumps(o,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode('utf8')
def digest(b):return hashlib.sha256(b).hexdigest()
def fhash(p):return digest(p.read_bytes()) if p.is_file() else None
def parse(b):
    try:return json.loads(b.decode('utf-8-sig','strict'))
    except (ValueError,UnicodeError) as e:raise Reject('INVALID_JSON_UTF8') from e
def text(b):
    if len(b)>32768:raise Reject('TXT_TOO_LARGE')
    try:return b.decode('utf-8-sig','strict').strip()
    except UnicodeDecodeError as e:raise Reject('INVALID_UTF8') from e
def probe(b,ext,og=False):
    # A3/media_support validation: original bytes are never re-encoded.
    try:
        with Image.open(BytesIO(b)) as im:fmt=im.format;im.verify()
        with Image.open(BytesIO(b)) as im:
            w,h=im.size;frames=getattr(im,'n_frames',1);loop=im.info.get('loop');dur=[]
            if w*h>40_000_000 or frames>1000 or w*h*frames>300_000_000:raise Reject('IMAGE_LIMIT')
            for n in range(frames):im.seek(n);im.load();dur.append(im.info.get('duration'))
    except Reject:raise
    except Exception as e:raise Reject('CORRUPT_IMAGE:'+type(e).__name__) from e
    if EXTS.get(ext.lower())!=fmt:raise Reject('WRONG_EXTENSION')
    if og and fmt not in ('JPEG','PNG'):raise Reject('INVALID_OG_FORMAT')
    return {'sha256':digest(b),'format':fmt,'ext':'.jpg' if fmt=='JPEG' else '.'+fmt.lower(),
            'width':w,'height':h,'frames':frames,'durations_ms':dur,'loop':loop,'bytes':len(b)}
def atomic(p,b,tear=False):
    p.parent.mkdir(parents=True,exist_ok=True);tmp=p.with_name(p.name+'.'+uuid.uuid4().hex+'.tmp')
    with tmp.open('wb') as f:f.write(b[:max(1,len(b)//2)] if tear else b);f.flush();os.fsync(f.fileno())
    if tear:raise Crash('INTERRUPTED_TEMP_WRITE')
    os.replace(tmp,p)
def external(path):
    p=Path(path).absolute()
    if any(x.is_symlink() or (hasattr(x,'is_junction') and x.is_junction()) for x in (p,*p.parents)):
        raise Reject('LINK_PATH')
    p=p.resolve()
    if any((x/'.git').exists() for x in (p,*p.parents)):raise Reject('OFFLINE_EXTERNAL_ROOT_REQUIRED')
    return p
def locked(fn):
    def call(self,*a,**kw):
        with self.lock():
            self._recover();reg=self._load()
            return fn(self,reg,*a,**kw)
    return call

class Store:
    def __init__(self,root,witness,history_repo=None):
        self.root=external(root);self.witness=external(witness);self.history_repo=history_repo
        if self.witness.is_relative_to(self.root) or self.root.is_relative_to(self.witness):raise Reject('EXTERNAL_WITNESS_REQUIRED')
        self.state=self.root/'automation-state';self.reg=self.state/'registry.json';self.pending=self.state/'pending.json'
    @classmethod
    def create(cls,root,witness):
        s=cls(root,witness)
        if s.root.exists() or s.witness.exists():raise Reject('ALREADY_INITIALIZED_OR_NOT_EMPTY')
        s.state.mkdir(parents=True)
        r={'schema':1,'library_id':uuid.uuid4().hex,'seq':0,'previous':None,'counters':dict.fromkeys(COLS,0),
           'items':{},'receipts':{},'bootstrap':None,'state_events':[]}
        s._save(r,initial=True);return s
    @contextmanager
    def lock(self):
        if not self.reg.is_file():raise Reject('MISSING_LEDGER')
        if not self.witness.is_file():raise Reject('MISSING_WITNESS')
        p=self.path('automation-state/.lock');f=p.open('a+b');f.seek(0,2)
        if f.tell()==0:f.write(b'0');f.flush()
        end=time.monotonic()+8
        while True:
            try:
                f.seek(0)
                if os.name=='nt':
                    import msvcrt
                    msvcrt.locking(f.fileno(),msvcrt.LK_NBLCK,1)
                else:
                    import fcntl
                    fcntl.flock(f.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic()>end:f.close();raise Reject('LOCK_TIMEOUT')
                time.sleep(.02)
        try:yield
        finally:
            f.seek(0)
            if os.name=='nt':msvcrt.locking(f.fileno(),msvcrt.LK_UNLCK,1)
            else:fcntl.flock(f.fileno(),fcntl.LOCK_UN)
            f.close()
    def path(self,relative):
        if not isinstance(relative,str) or '\\' in relative or ':' in relative or any(ord(c)<32 for c in relative):raise Reject('UNSAFE_PATH')
        p=PurePosixPath(relative)
        if p.is_absolute() or not p.parts or '..' in p.parts or str(p)!=relative:raise Reject('UNSAFE_PATH')
        target=self.root.joinpath(*p.parts)
        if any(x.is_symlink() or (hasattr(x,'is_junction') and x.is_junction()) for x in (target,*target.parents) if x.is_relative_to(self.root)):raise Reject('LINK_PATH')
        if not target.resolve().is_relative_to(self.root):raise Reject('UNSAFE_PATH')
        return target
    def _validate(self,r):
        try:
            if r['schema']!=1 or type(r['seq'])!=int or r['seq']<0 or set(r['counters'])!=set(COLS):raise ValueError()
            for c,n in r['counters'].items():
                if type(n)!=int or not 0<=n<=99999:raise ValueError()
            for key,item in r['items'].items():
                c=item['collection'];n=item['number']
                if c not in COLS or type(n)!=int or n<1 or n>r['counters'][c] or key!=item['id'] or key!=f'bgzona-{COLS[c]}-{n:05d}':raise ValueError()
                if item['page_url']!=f'/{c}/'+('kolaj-' if c=='kolaji' else 'p-')+f'{n:05d}/' or item['state'] not in STATES:raise ValueError()
                revisions=item['revisions'];current=item['desired_revision']
                if type(current)!=int or current<1 or not isinstance(revisions,list) or len(revisions)!=current:raise Reject('INVALID_REVISION_SEQUENCE')
                for number,rev in enumerate(revisions,1):
                    sha=rev['sha256'];ext=rev['ext']
                    suffix='' if number==1 else f'-r{number:04d}-{sha[:12]}'
                    if rev['number']!=number or type(rev['number'])!=int or not re.fullmatch('[0-9a-f]{64}',sha) or ext not in ('.jpg','.png','.webp','.gif'):raise Reject('INVALID_REVISION_SEQUENCE')
                    if rev['blob']!=f'objects/{sha}{ext}' or rev['public_path']!=f'/{c}/full/{key}{suffix}{ext}':raise Reject('INVALID_REVISION_OBJECT')
            for k,v in r['receipts'].items():
                if k!=v['digest'] or digest(data(v['input']))!=k or v['item'] not in r['items']:raise ValueError()
                item=r['items'][v['item']]
                if type(v['revision'])!=int or not 1<=v['revision']<=item['desired_revision']:raise Reject('INVALID_RECEIPT_REVISION')
                if v['input']['op']=='replace' and (v['input']['id']!=item['id'] or v['input']['collection']!=item['collection'] or len(v['input']['files'])!=1):raise Reject('INVALID_REPLACEMENT_RECEIPT')
        except (KeyError,ValueError,TypeError) as e:raise Reject('INVALID_LEDGER') from e
    def _history(self,initial=False):
        rows=[];prev=None
        for p in sorted((self.state/'history').glob('*.json')):
            b=p.read_bytes();r=parse(b);self._validate(r)
            if p.name!=f'{len(rows):08d}-{digest(b)}.json' or r['seq']!=len(rows) or r['previous']!=prev:raise Reject('HISTORY_CORRUPTION')
            if rows and r['library_id']!=rows[0][0]['library_id']:raise Reject('HISTORY_IDENTITY')
            if rows:
                try:check_history(r,[rows[-1][0]])
                except ValueError as e:raise Reject(str(e)) from e
            rows.append((r,b));prev=digest(b)
        if not rows:
            if initial:return rows
            raise Reject('MISSING_HISTORY')
        if not initial:
            if not self.witness.is_file():raise Reject('MISSING_WITNESS')
            w=parse(self.witness.read_bytes());seq=w.get('seq',-1)
            if type(seq)!=int or seq<0 or seq>=len(rows) or w.get('library_id')!=rows[0][0]['library_id'] or w.get('sha256')!=digest(rows[seq][1]):raise Reject('WITNESS_ROLLBACK_OR_CONFLICT')
        return rows
    def _save(self,r,tear=False,initial=False):
        self._validate(r);rows=self._history(initial=initial);raw=data(r)
        if rows and rows[-1][1]!=raw:
            if r['seq']!=rows[-1][0]['seq']+1 or r['previous']!=digest(rows[-1][1]):raise Reject('HISTORY_APPEND_CONFLICT')
        elif not rows and (r['seq']!=0 or r['previous'] is not None):raise Reject('INVALID_INITIAL_STATE')
        p=self.path(f'automation-state/history/{r["seq"]:08d}-{digest(raw)}.json')
        if p.exists() and p.read_bytes()!=raw:raise Reject('HISTORY_MUTATION')
        if not p.exists():atomic(p,raw)
        atomic(self.reg,raw,tear)
        atomic(self.witness,data({'library_id':r['library_id'],'seq':r['seq'],'sha256':digest(raw)}))
    def _load(self):
        if not self.reg.is_file():raise Reject('MISSING_LEDGER')
        rows=self._history();raw=self.reg.read_bytes()
        if raw!=rows[-1][1]:raise Reject('LEDGER_ROLLBACK_OR_EDIT')
        r=rows[-1][0]
        if r.get('transaction_status')=='accepted':raise Reject('MISSING_TRANSACTION_JOURNAL')
        for item in r['items'].values():
            refs=item['revisions']+([item['og']] if item['og'] else [])
            for v in refs:
                if fhash(self.path(v['blob']))!=v['sha256']:raise Reject('ARCHIVE_CORRUPT')
        for rec in r['receipts'].values():
            for rel,h in rec['input'].get('files',{}).items():
                if fhash(self.path(rec['input']['blobs'][rel]))!=h:raise Reject('RECEIPT_ARCHIVE_CORRUPT')
        if self.history_repo:
            try:check_history(r,read_git_history(self.history_repo))
            except ValueError as e:raise Reject(str(e)) from e
        return r
    def _blob(self,b,ext):
        rel=f'objects/{digest(b)}{ext}';p=self.path(rel)
        if p.exists():
            if p.read_bytes()!=b:raise Reject('IMMUTABLE_BLOB_CHANGED')
        else:atomic(p,b)
        return rel
    def _effect(self,rel,after):
        return {'path':rel,'before':fhash(self.path(rel)),'after':base64.b64encode(after).decode(),'after_hash':digest(after)}
    def _check_effects(self,effects):
        for e in effects:
            if digest(base64.b64decode(e['after'],validate=True))!=e['after_hash']:raise Reject('JOURNAL_EFFECT_CORRUPT')
            if fhash(self.path(e['path'])) not in (e['before'],e['after_hash']):raise Reject('CONCURRENT_FILE_CHANGE:'+e['path'])
    def _apply(self,effects,fault=None):
        self._check_effects(effects)
        for n,e in enumerate(effects):
            p=self.path(e['path'])
            if fhash(p)==e['after_hash']:continue
            if fhash(p)!=e['before']:raise Reject('CONCURRENT_FILE_CHANGE:'+e['path'])
            atomic(p,base64.b64decode(e['after']))
            if fault=='mid-effects' and n==0:raise Crash('MID_EFFECTS')
    def _tx(self,before,after,effects=(),fault=None):
        if before==after and not effects:return before
        self._check_effects(effects);reserve=deepcopy(after);final=deepcopy(after)
        reserve.update(seq=before['seq']+1,previous=digest(data(before)),transaction_status='accepted')
        for v in reserve['receipts'].values():
            if v['status']=='staged':v['status']='accepted'
        final.update(seq=before['seq']+2,previous=digest(data(reserve)),transaction_status='staged')
        pending={'before':before,'reserve':reserve,'final':final,'effects':list(effects)}
        atomic(self.pending,data({'sha256':digest(data(pending)),'transaction':pending}))
        if fault=='before-reserve':raise Crash('BEFORE_RESERVATION')
        self._save(reserve,tear=fault=='temp-write')
        if fault=='after-reserve':raise Crash('AFTER_RESERVATION')
        if fault=='process-exit':os._exit(77)
        self._apply(effects,fault);self._save(final)
        if fault=='after-final':raise Crash('AFTER_FINAL')
        self.pending.unlink();return final
    def _recover(self):
        if not self.pending.exists():return
        # A missing registry never gets reconstructed silently from a journal.
        if not self.reg.is_file():raise Reject('MISSING_LEDGER')
        envelope=parse(self.pending.read_bytes());p=envelope.get('transaction')
        if digest(data(p))!=envelope.get('sha256'):raise Reject('JOURNAL_CORRUPT')
        rows=self._history();raw=parse(self.reg.read_bytes())
        before,reserve,final=(p[k] for k in ('before','reserve','final'))
        for r in (before,reserve,final):self._validate(r)
        if reserve['seq']!=before['seq']+1 or final['seq']!=reserve['seq']+1 or reserve['previous']!=digest(data(before)) or final['previous']!=digest(data(reserve)):raise Reject('JOURNAL_SEQUENCE')
        try:check_history(reserve,[before]);check_history(final,[reserve])
        except ValueError as e:raise Reject(str(e)) from e
        if raw not in (before,reserve,final) or rows[-1][0] not in (before,reserve,final):raise Reject('RECOVERY_LEDGER_CONFLICT')
        self._check_effects(p['effects'])
        if rows[-1][0]['seq']<reserve['seq'] or rows[-1][0]==reserve:self._save(reserve)
        self._apply(p['effects']);self._save(final);self.pending.unlink()
    def bundle(self,item,state=None):return f'library/{item["collection"]}/{state or item["state"]}/{item["id"]}'
    def _scan(self,reg,strict=False):
        found={};base=self.path('library')
        if base.exists():
            for c in base.iterdir():
                self.path(c.relative_to(self.root).as_posix())
                if c.name not in COLS or not c.is_dir():raise Reject('INVALID_LIBRARY_COLLECTION')
                if any(not p.is_dir() or p.name not in STATES for p in c.iterdir()):raise Reject('INVALID_LIBRARY_STATE')
        for col in COLS:
            for state in STATES:
                base=self.path(f'library/{col}/{state}')
                if not base.exists():continue
                for p in base.iterdir():
                    self.path(p.relative_to(self.root).as_posix());key=p.name
                    if not p.is_dir() or key not in reg['items']:raise Reject('UNKNOWN_LIBRARY_ID')
                    item=reg['items'][key]
                    if item['collection']!=col or key in found:raise Reject('CROSS_COLLECTION_OR_DUPLICATE_ID')
                    v=deepcopy(item);v['state']=state
                    allowed={key+'.txt','og.jpg','og.png'}
                    for rev in v['revisions']:
                        orig=self.path(self.bundle(v)+'/'+PurePosixPath(rev['public_path']).name)
                        if fhash(orig)!=rev['sha256']:raise Reject('MISSING_OR_CHANGED_MANAGED_ORIGINAL:'+key)
                        allowed.add(orig.name)
                    if any(not x.is_file() or x.name not in allowed for x in p.iterdir()):raise Reject('INVALID_PARTIAL_BUNDLE')
                    txt=self.path(self.bundle(v)+'/'+key+'.txt');b=txt.read_bytes() if txt.exists() else None
                    v['description']=text(b) if b is not None else '';v['description_hash']=digest(b) if b is not None else None
                    if strict and any(v[k]!=item[k] for k in ('state','description','description_hash')):raise Reject('REPLACEMENT_WITH_UNRELATED_MUTATION')
                    og=[self.path(self.bundle(v)+'/'+name) for name in ('og.jpg','og.png') if (p/name).exists()]
                    if len(og)>1:raise Reject('AMBIGUOUS_OG')
                    if og:
                        b=og[0].read_bytes();meta=probe(b,og[0].suffix,True)
                        if strict and (not item['og'] or meta['sha256']!=item['og']['sha256'] or meta['ext']!=item['og']['ext']):raise Reject('REPLACEMENT_WITH_UNRELATED_MUTATION')
                        v['og']={'sha256':digest(b),'blob':self._blob(b,meta['ext']),'ext':meta['ext']}
                    else:
                        if strict and item['og'] is not None:raise Reject('REPLACEMENT_WITH_UNRELATED_MUTATION')
                        v['og']=None
                    found[key]=v
        if set(found)!=set(reg['items']):raise Reject('MISSING_MANAGED_BUNDLE')
        return found
    def _sync(self,reg):
        items=self._scan(reg)
        if items==reg['items']:return reg
        now=time.time();events=reg['state_events'];fresh=[{'time':now,'id':k,'before':reg['items'][k]['state'],'after':v['state']} for k,v in items.items() if v['state']!=reg['items'][k]['state']]
        recent=[e for e in events if e['time']>=now-86400]+fresh;n=len({e['id'] for e in recent})
        published=sum(i['state']=='published' for i in reg['items'].values())
        if fresh and (n>=3 or (n>=2 and n/max(1,published)>=.10)):raise Reject('BULK_REVIEW_REQUIRED')
        # Metadata bulk edits also stop; no override/approval implementation in C1.
        changed=sum(v!=reg['items'][k] for k,v in items.items())
        if changed>=3:raise Reject('BULK_REVIEW_REQUIRED')
        after=deepcopy(reg);after['items']=items;after['state_events']=events+fresh
        return self._tx(reg,after)
    def _input(self):
        batches=[];incoming=self.path('incoming')
        if incoming.exists() and any(not p.is_dir() or p.name not in (*COLS,'replace') for p in incoming.iterdir()):raise Reject('INVALID_INPUT_COLLECTION')
        for col in COLS:
            folder=self.path('incoming/'+col)
            if not folder.exists():continue
            files={}
            for p in folder.iterdir():
                self.path(p.relative_to(self.root).as_posix());name=p.name.casefold()
                if not p.is_file() or name in files:raise Reject('AMBIGUOUS_OR_NESTED_INPUT')
                files[name]=p
            ordinary={};used=set()
            for name,p in files.items():
                if p.suffix.lower()=='.txt':continue
                if p.stem.casefold().endswith('.og'):
                    if p.suffix.lower() not in ('.jpg','.png'):raise Reject('INVALID_OG_SIDECAR')
                    continue
                if p.suffix.lower() not in EXTS:raise Reject('INVALID_INPUT_FORMAT')
                stem=p.stem.casefold()
                if stem in ordinary:raise Reject('AMBIGUOUS_PAIRING')
                ordinary[stem]=p
            for stem,p in sorted(ordinary.items()):
                txt=files.get(stem+'.txt');ogs=[files[n] for n in (stem+'.og.jpg',stem+'.og.png') if n in files]
                if len(ogs)>1:raise Reject('AMBIGUOUS_OG')
                group=[p]+([txt] if txt else [])+ogs;snapshot={q.relative_to(self.root).as_posix():q.read_bytes() for q in group}
                b=snapshot[p.relative_to(self.root).as_posix()];meta=probe(b,p.suffix)
                tb=snapshot[txt.relative_to(self.root).as_posix()] if txt else None
                if tb is not None:text(tb)
                ob=snapshot[ogs[0].relative_to(self.root).as_posix()] if ogs else None
                om=probe(ob,ogs[0].suffix,True) if ogs else None
                batches.append((col,b,meta,tb,ob,om,snapshot));used.update(q.name.casefold() for q in group)
            if used!=set(files):raise Reject('ORPHAN_SIDECAR')
        return batches
    def _request(self,snapshot,**identity):
        return dict(identity,files={p:digest(b) for p,b in snapshot.items()},
                    blobs={p:f'objects/{digest(b)}{Path(p).suffix.lower()}' for p,b in snapshot.items()})
    def _replacements(self,reg):
        root=self.path('incoming/replace');fresh=[];replayed=[]
        if not root.exists():return fresh,replayed
        if not root.is_dir():raise Reject('INVALID_REPLACEMENT_INPUT')
        for collection in sorted(root.iterdir()):
            self.path(collection.relative_to(self.root).as_posix())
            if not collection.is_dir() or collection.name not in COLS:raise Reject('INVALID_REPLACEMENT_COLLECTION')
            col=collection.name
            for target in sorted(collection.iterdir()):
                self.path(target.relative_to(self.root).as_posix())
                if not target.is_dir() or not re.fullmatch('[0-9]{5}',target.name):raise Reject('INVALID_REPLACEMENT_TARGET')
                key=f'bgzona-{COLS[col]}-{target.name}'
                if key not in reg['items'] or reg['items'][key]['collection']!=col:raise Reject('UNKNOWN_REPLACEMENT_ID')
                entries=list(target.iterdir())
                if not entries:continue  # Removing input cancels only that request.
                if len(entries)!=1:raise Reject('AMBIGUOUS_REPLACEMENT_REQUEST')
                p=entries[0];rel=p.relative_to(self.root).as_posix();self.path(rel)
                reserved=p.name.split('.')[0].upper()
                if (not p.is_file() or p.stat().st_nlink!=1 or p.name.endswith(('.', ' ')) or
                    any(c in p.name for c in '<>"|?*') or reserved in ('CON','PRN','AUX','NUL') or
                    re.fullmatch('(COM|LPT)[1-9]',reserved) or p.stem.casefold().endswith('.og')):raise Reject('UNSAFE_REPLACEMENT_FILE')
                if p.suffix.lower() not in EXTS:raise Reject('INVALID_REPLACEMENT_FORMAT')
                # Matches the inactive transport's maximum managed object size.
                with p.open('rb') as f:b=f.read(50_000_001)
                if len(b)>50_000_000:raise Reject('IMAGE_SIZE_LIMIT')
                meta=probe(b,p.suffix);snapshot={rel:b};inp=self._request(snapshot,op='replace',collection=col,id=key);req=digest(data(inp))
                for old in reg['receipts'].values():
                    for oldpath,h in old['input'].get('files',{}).items():
                        if oldpath.casefold()==rel.casefold() and h!=meta['sha256']:raise Reject('INPUT_PATH_CHANGED_AFTER_ACCEPTANCE')
                if req in reg['receipts']:
                    receipt=reg['receipts'][req];revision=reg['items'][key]['revisions'][receipt['revision']-1]
                    if receipt['item']!=key or revision['sha256']!=meta['sha256']:raise Reject('REPLACEMENT_RECEIPT_CONFLICT')
                    replayed.append(key);continue
                if any(v['sha256']==meta['sha256'] for v in reg['items'][key]['revisions']):raise Reject('REPLACEMENT_REVISION_REUSE')
                fresh.append((key,b,meta,inp,req))
        return fresh,replayed
    def _replace(self,reg,requests,replayed,fault=None):
        self._scan(reg,strict=True)  # No metadata/lifecycle admission in this operation.
        now=time.time();events=reg['state_events']
        fresh=[{'time':now,'id':key,'before':reg['items'][key]['state'],'after':reg['items'][key]['state'],'op':'replace'} for key,*_ in requests]
        recent=[e for e in events if e['time']>=now-86400]+fresh;n=len({e['id'] for e in recent})
        published=sum(i['state']=='published' for i in reg['items'].values())
        if len(fresh)>=3 or n>=3 or (n>=2 and n/max(1,published)>=.10):raise Reject('BULK_REVIEW_REQUIRED')
        after=deepcopy(reg);effects=[];out=list(replayed)
        for key,b,meta,inp,req in requests:
            item=after['items'][key];number=len(item['revisions'])+1;rev=deepcopy(meta)
            rev.update(number=number,blob=self._blob(b,meta['ext']),
                       public_path=f'/{item["collection"]}/full/{key}-r{number:04d}-{meta["sha256"][:12]}{meta["ext"]}')
            for rel in inp['files']:self._blob(b,Path(rel).suffix.lower())
            item['revisions'].append(rev);item['desired_revision']=number
            effects.append(self._effect(self.bundle(item)+'/'+PurePosixPath(rev['public_path']).name,b))
            after['receipts'][req]={'input':inp,'digest':req,'item':key,'revision':number,'status':'staged'};out.append(key)
        after['state_events']=events+fresh
        final=self._tx(reg,after,effects,fault)
        return {'items':out,'changed':final!=reg,'seq':final['seq']}
    def _make_item(self,col,n,b,meta,tb,ob,om,row=None):
        key=f'bgzona-{COLS[col]}-{n:05d}';meta=deepcopy(meta)
        meta.update(number=1,blob=self._blob(b,meta['ext']),public_path=f'/{col}/full/{key}{meta["ext"]}')
        own={'sha256':digest(ob),'blob':self._blob(ob,om['ext']),'ext':om['ext']} if ob is not None else None
        item={'id':key,'collection':col,'number':n,'page_url':f'/{col}/'+('kolaj-' if col=='kolaji' else 'p-')+f'{n:05d}/',
              'state':'published','slideshow':row['slideshow'] if row else col=='kolaji','description':row['description'] if row else text(tb) if tb is not None else '',
              'description_hash':digest(tb) if tb is not None else None,'og':own,'desired_revision':1,'revisions':[meta]}
        bundle=self.bundle(item);effects=[self._effect(bundle+'/'+key+meta['ext'],b)]
        if tb is not None:effects.append(self._effect(bundle+'/'+key+'.txt',tb))
        if own:effects.append(self._effect(bundle+'/og'+own['ext'],ob))
        return item,effects
    @locked
    def show(self,reg):return reg
    @locked
    def sync(self,reg):return self._sync(reg)
    @locked
    def add(self,reg,fault=None):
        batches=self._input()  # Validate the entire batch before allocating IDs.
        replacements,replayed=self._replacements(reg)
        if replacements:
            if any(digest(data(self._request(snapshot,op='add'))) not in reg['receipts'] for *_,snapshot in batches):raise Reject('MIXED_REPLACEMENT_AND_NEW_INTAKE')
            return self._replace(reg,replacements,replayed,fault)
        reg=self._sync(reg);after=deepcopy(reg);effects=[];out=list(replayed)
        for col,b,meta,tb,ob,om,snapshot in batches:
            inp=self._request(snapshot,op='add')
            for p,bits in snapshot.items():self._blob(bits,Path(p).suffix.lower())
            req=digest(data(inp))
            for old in after['receipts'].values():
                for p,h in inp['files'].items():
                    if p in old['input'].get('files',{}) and old['input']['files'][p]!=h:raise Reject('INPUT_PATH_CHANGED_AFTER_ACCEPTANCE')
            if req in after['receipts']:out.append(after['receipts'][req]['item']);continue
            matches=[v for v in after['items'].values() if v['collection']==col and any(rev['sha256']==meta['sha256'] for rev in v['revisions'])]
            if len(matches)>1:raise Reject('AMBIGUOUS_DUPLICATE_CONTENT')
            if matches:
                item=matches[0]
                if tb is not None and text(tb)!=item['description']:raise Reject('DUPLICATE_DESCRIPTION_CONFLICT')
                if ob is not None and (not item['og'] or digest(ob)!=item['og']['sha256']):raise Reject('DUPLICATE_OG_CONFLICT')
            else:
                n=after['counters'][col]+1
                if n>99999:raise Reject('COUNTER_EXHAUSTED')
                item,ef=self._make_item(col,n,b,meta,tb,ob,om);after['items'][item['id']]=item;effects+=ef;after['counters'][col]=n
            after['receipts'][req]={'input':inp,'digest':req,'item':item['id'],'revision':next(rev['number'] for rev in item['revisions'] if rev['sha256']==meta['sha256']),'status':'staged'};out.append(item['id'])
        final=self._tx(reg,after,effects,fault)
        return {'items':out,'changed':final!=reg,'seq':final['seq']}
    @locked
    def seed(self,reg,archive,fault=None):
        raw=Path(archive).read_bytes()
        if len(raw)!=9595193 or digest(raw)!=BOOTSTRAP_SHA:raise Reject('BOOTSTRAP_SHA_OR_SIZE')
        if reg['bootstrap']:
            self._scan(reg)
            if reg['bootstrap']['archive_sha256']!=BOOTSTRAP_SHA:raise Reject('BOOTSTRAP_CONFLICT')
            return {'changed':False,'items':sorted(reg['items'])}
        if reg['items'] or any(reg['counters'].values()):raise Reject('SEED_REQUIRES_EMPTY_REGISTRY')
        with zipfile.ZipFile(BytesIO(raw)) as z:
            if z.testzip() is not None:raise Reject('BOOTSTRAP_ZIP_CRC')
            infos=z.infolist();buffers={}
            for info in infos:
                name=info.filename
                if info.is_dir() or info.flag_bits&1 or name in buffers:raise Reject('BOOTSTRAP_MEMBER')
                self.path(name);buffers[name]=z.read(info)
        expected=parse(buffers['expected-files.json']);cat=parse(buffers['artifact/catalog.json'])
        actual={p.removeprefix('artifact/'):digest(b) for p,b in buffers.items() if p.startswith('artifact/')}
        if actual!=expected or set(cat)!= {'schema','items'} or cat['schema']!=1:raise Reject('BOOTSTRAP_EXPECTED_FILES')
        expected_ids={f'bgzona-{prefix}-{n:05d}' for col,prefix in COLS.items() for n in range(1,28 if col=='kolaji' else 19)}
        if len(cat['items'])!=45 or {r['id'] for r in cat['items']}!=expected_ids:raise Reject('BOOTSTRAP_MEMBERSHIP')
        if sum(r['slideshow'] for r in cat['items'])!=26:raise Reject('BOOTSTRAP_SLIDES')
        after=deepcopy(reg);effects=[];used={'catalog.json'}
        for r in cat['items']:
            col=r['collection'];n=int(r['id'][-5:]);b=buffers['artifact'+r['original']];meta=probe(b,Path(r['original']).suffix)
            if r['state']!='published' or r['revision']!=1 or meta['sha256']!=r['sha256']:raise Reject('BOOTSTRAP_MAPPING')
            ob=buffers['artifact'+r['og']] if r.get('og') else None;om=probe(ob,Path(r['og']).suffix,True) if ob is not None else None
            tb=r['description'].encode('utf8') if r['description'] else None
            item,ef=self._make_item(col,n,b,meta,tb,ob,om,r)
            if item['id']!=r['id'] or item['page_url']!=r['page_url'] or item['revisions'][0]['public_path']!=r['original']:raise Reject('BOOTSTRAP_IDENTITY')
            after['items'][item['id']]=item;after['counters'][col]=max(after['counters'][col],n);effects+=ef
            inp={'op':'seed','archive_sha256':BOOTSTRAP_SHA,'id':item['id'],'sha256':meta['sha256']};req=digest(data(inp))
            after['receipts'][req]={'input':inp,'digest':req,'item':item['id'],'revision':1,'status':'staged'}
            used.add(r['original'].lstrip('/'))
            if r.get('og'):used.add(r['og'].lstrip('/'))
        if used!=set(expected) or after['counters']!={'kolaji':27,'poslaniya':18}:raise Reject('BOOTSTRAP_EXACT_SET')
        after['bootstrap']={'archive_sha256':BOOTSTRAP_SHA,'catalog_sha256':digest(buffers['artifact/catalog.json']),'mapping_sha256':digest(data(cat))}
        self._tx(reg,after,effects,fault);return {'changed':True,'items':sorted(after['items'])}
    @locked
    def project(self,reg,destination):
        reg=self._sync(reg);dest=external(destination)
        if dest.exists() or dest.is_relative_to(self.root) or self.root.is_relative_to(dest):raise Reject('NEW_EXTERNAL_OUTPUT_REQUIRED')
        # Only the current original of published media enters the public artifact.
        public=[];payload={}
        for key,item in sorted(reg['items'].items()):
            r={k:item[k] for k in ('id','collection','page_url','state')}
            if item['state']=='published':
                rev=item['revisions'][-1];b=self.path(rev['blob']).read_bytes()
                if any(v!=rev[k] for k,v in probe(b,rev['ext']).items()):raise Reject('PROJECTION_SOURCE_CHANGED')
                payload[rev['public_path'].lstrip('/')]=b
                r.update(revision=item['desired_revision'],original=rev['public_path'],sha256=rev['sha256'],description=item['description'],slideshow=item['slideshow'])
                if item['og']:
                    og=item['og'];rel=f'{item["collection"]}/og/{key}-{og["sha256"][:12]}{og["ext"]}';b=self.path(og['blob']).read_bytes()
                    if digest(b)!=og['sha256']:raise Reject('PROJECTION_OG_CHANGED')
                    payload[rel]=b;r['og']='/'+rel
            public.append(r)
        payload['catalog.json']=data({'schema':1,'items':public})
        # A partial output has no completion manifest and cannot be accepted.
        for rel,b in payload.items():atomic(dest/'artifact'/rel,b)
        expected={p:digest(b) for p,b in payload.items()};atomic(dest/'expected-files.json',data(expected))
        return {'status':'LOCAL_PROJECTION_ONLY','registry_seq':reg['seq'],'catalog_sha256':expected['catalog.json'],'files':len(expected)}

def main():
    sys.stdout.reconfigure(encoding='utf-8')
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('operation',choices=('init','seed','add','sync','show','project'))
    p.add_argument('--root',type=Path,required=True);p.add_argument('--witness',type=Path,required=True);p.add_argument('--archive',type=Path);p.add_argument('--output',type=Path)
    a=p.parse_args()
    if a.operation=='init':Store.create(a.root,a.witness);result={'status':'INITIALIZED_OFFLINE_ONLY'}
    else:
        s=Store(a.root,a.witness)
        if a.operation=='seed':
            if not a.archive:p.error('--archive required')
            result=s.seed(a.archive)
        elif a.operation=='project':
            if not a.output:p.error('--output required')
            result=s.project(a.output)
        else:result=getattr(s,a.operation)()
    print(json.dumps(result,ensure_ascii=False,sort_keys=True))
if __name__=='__main__':
    try:main()
    except (Reject,OSError,ValueError,KeyError,TypeError,zipfile.BadZipFile) as e:raise SystemExit('IMPORT_REJECT: '+str(e))
