"""NEW focused E4G tests. Synthetic bytes, marked external bare repositories only.

The bootstrap marker below is explicitly FICTITIOUS fixture metadata, not proof
of the real frozen archive. No owner/archive image is read or copied. Actual
Store transactions/history and D3 bundles/independent acceptance are exercised.
"""
import argparse
from copy import deepcopy
from dataclasses import asdict, replace
from io import BytesIO
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import traceback
import unittest
import uuid
from PIL import Image

import intake_plan as planner
import request_executor as executor
from authority_coordinator import LocalWitness, Interrupted, run_local
from git_transport import (Lab, Session, MAIN, WITNESS, git, value, files,
                           snapshot, state_commit, witness_commit)
from importer import Store, BOOTSTRAP_SHA, data, parse, digest

WORK = None
LAB = None
BASE = None
ROWS = []
KEY = 'bgzona-p-00001'
ROOT = 'library/kolaji/published/' + KEY + '/'


def image(n):
    out = BytesIO()
    Image.new('RGB', (13, 11), ((n * 17) % 255, (n * 37) % 255,
                               (n * 73) % 255)).save(out, format='PNG')
    return out.getvalue()


def put_commit(repo, buffers, parent=None):
    index = repo.parent / ('index-' + uuid.uuid4().hex)
    env = {'GIT_INDEX_FILE': str(index)}
    git(repo, 'read-tree', '--empty', env_extra=env)
    for rel, b in sorted(buffers.items()):
        oid = value(repo, 'hash-object', '-w', '--stdin', stdin=b)
        git(repo, 'update-index', '--add', '--cacheinfo', '100644', oid, rel, env_extra=env)
    tree = value(repo, 'write-tree', env_extra=env)
    args = ['commit-tree', tree, '-m', 'SYNTHETIC E4G fixture only']
    if parent: args += ['-p', parent]
    commit = value(repo, *args)
    git(repo, 'update-ref', MAIN, commit)
    return commit


def initialize():
    global LAB, BASE
    LAB = Lab.create(WORK / 'lab')
    root = LAB.root / 'synthetic-baseline'
    store = Store.create(root, LAB.root / 'synthetic-witness.json')
    for n in range(1, 22):
        p = root / f'incoming/kolaji/base-{n:02d}.png'
        p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(image(n))
    (root / 'incoming/kolaji/base-01.txt').write_bytes(b'Original synthetic owner text')
    (root / 'incoming/kolaji/base-01.og.png').write_bytes(image(80))
    store.add()
    before = store.show(); after = deepcopy(before)
    after['bootstrap'] = {'archive_sha256': BOOTSTRAP_SHA,
                          'catalog_sha256': 'a' * 64, 'mapping_sha256': 'b' * 64}
    after['items']['bgzona-p-00004']['slideshow'] = False
    store._tx(before, after)  # FICTITIOUS trusted genesis; genuine C1 transaction.
    reg = store.show()
    primary = LAB.root / 'baseline.git'; primary.mkdir()
    git(primary, 'init', '--bare', '--initial-branch=main')
    commit = put_commit(primary, snapshot(root))
    witness = witness_commit(primary, commit, reg)
    git(primary, 'update-ref', WITNESS, witness)
    anchor = LAB.root / 'ledger0.git'; anchor.mkdir()
    git(anchor, 'init', '--bare', '--initial-branch=main')
    archives = LAB.root / 'initial-archives'; archives.mkdir()
    domain = LocalWitness(LAB, anchor, archives, '0' * 64, reg['library_id'], witness)
    record = domain.record(primary, commit, witness, commit, None, 0)
    put_commit(anchor, {'anchor.json': data(record), 'records/00000000.json': data(record)})
    BASE = dict(primary=primary, anchor=anchor, archives=archives,
                genesis=digest(data(record)), library_id=reg['library_id'],
                primary_genesis=witness)
    # Actual independent read/restore validates the fixture itself.
    LocalWitness(LAB, **{k: BASE[k] for k in ('anchor','archives','genesis','library_id','primary_genesis')}).read()
    (WORK / 'fixture.json').write_bytes(data({k: str(v) if isinstance(v, Path) else v
                                          for k, v in BASE.items()}))


def fixture(label):
    case = LAB.root / 'cases' / (label + '-' + uuid.uuid4().hex[:6]); case.mkdir(parents=True)
    c = dict(BASE)
    for key in ('primary', 'anchor'):
        target = case / (key + '.git')
        git(case, 'clone', '--bare', '--no-local', str(BASE[key]), str(target))
        if key == 'primary':git(target, 'fetch', str(BASE[key]), WITNESS + ':' + WITNESS)
        c[key] = target
    c['archives'] = case / 'archives'; shutil.copytree(BASE['archives'], c['archives'])
    return c


def domain(c):
    return LocalWitness(LAB, **{k: c[k] for k in ('anchor','archives','genesis','library_id','primary_genesis')})


def latest(c):
    return parse(git(c['anchor'], 'show', 'main:anchor.json').stdout)


def fingerprint(c):
    return (value(c['primary'], 'rev-parse', MAIN), value(c['primary'], 'rev-parse', WITNESS),
            value(c['anchor'], 'rev-parse', MAIN))


def state(c):
    return Session(LAB, c['primary'], c['primary_genesis']).store.show()


def request(c, transform):
    context = domain(c).read(); accepted = context['latest']
    old = {p: b for p, b in files(context['recovered'], accepted['primary_main']).items()
           if p.startswith(executor.EDITABLE)}
    new = dict(old); moves = transform(new) or []
    job = c['primary'].parent / ('source-' + uuid.uuid4().hex[:6]); job.mkdir()
    source = job / 'private-source.git'; source.mkdir()
    git(source, 'init', '--bare', '--initial-branch=main')
    parent = put_commit(source, old); commit = put_commit(source, new, parent)
    before = {'schema': 1, 'repository': {'id': 123, 'name': 'synthetic/private-intake'},
              'commit': parent, 'authority_commit': accepted['primary_main'],
              'witness_commit': accepted['primary_witness'],
              'ledger_record_sha256': digest(data(accepted)),
              'registry': parse(git(context['recovered'], 'show', accepted['primary_main'] + ':automation-state/registry.json').stdout),
              'files': {p: digest(b) for p, b in old.items()}}
    ops, consumed = [], set()
    for a, b in moves:
        ops.append(dict(op='move', path=a, to=b, before_sha256=digest(old[a]), after_sha256=digest(new[b])))
        consumed.update((a, b))
    for rel in sorted(set(old) | set(new)):
        if old.get(rel) == new.get(rel) or rel in consumed: continue
        a, b = old.get(rel), new.get(rel)
        ops.append(dict(op='add' if a is None else 'delete' if b is None else 'modify',
                        path=rel, before_sha256=digest(a) if a is not None else None,
                        after_sha256=digest(b) if b is not None else None))
    change = dict(schema=1, repository=dict(before['repository']), parent=parent, commit=commit,
                  before_state_sha256=digest(data(before)), files={p: digest(b) for p, b in new.items()}, operations=ops)
    evidence = planner.SourceEvidence(123, 'synthetic/private-intake', digest(data(before)),
                  planner.change_digest(change), digest(data(accepted)), int(time.time()), 'local-unpublished')
    return dict(source=source, before=before, change=change, evidence=evidence)


def execute(c, q, point=None, max_steps=12):
    def stop(hit):
        if hit == point:raise Interrupted(hit)
    q = dict(q); q['evidence'] = replace(q['evidence'], assessment_time=int(time.time()))
    return executor.run_local_request(LAB, **c, **q, interrupt=stop, max_steps=max_steps)


def replace_original(view, key=KEY, number=90):
    view[f'incoming/replace/kolaji/{key[-5:]}/replace-{number}.png'] = image(number)


def composition(txt='edited', og='replace', key=KEY):
    def change(view):
        replace_original(view, key)
        prefix = 'library/kolaji/published/' + key + '/'
        if txt == 'delete':view.pop(prefix + key + '.txt', None)
        elif txt == 'empty':view[prefix + key + '.txt'] = b''
        elif txt == 'edited':view[prefix + key + '.txt'] = b'Edited synthetic owner text'
        if og == 'remove':view.pop(prefix + 'og.png', None)
        elif og in ('add', 'replace'):view[prefix + 'og.png'] = image(91)
    return change


class Result(unittest.TextTestResult):
    def startTest(self, test):
        super().startTest(test);print("START "+test.id(),flush=True)
    def addSuccess(self, test):
        super().addSuccess(test);print('PASS '+test.id(),flush=True); ROWS.append({'test': test.id(), 'status': 'PASS'})
        self.save()
    def addFailure(self, test, err):
        super().addFailure(test, err); ROWS.append({'test': test.id(), 'status': 'FAIL', 'traceback': self._exc_info_to_string(err, test)});self.save()
    def addError(self, test, err):
        super().addError(test, err);ROWS.append({'test': test.id(), 'status': 'ERROR', 'traceback': self._exc_info_to_string(err, test)});self.save()
    def save(self):
        (WORK / 'results.json').write_bytes(data(ROWS))


class Tests(unittest.TestCase):
    def final(self, c, q):
        out = execute(c, q)
        self.assertEqual(out['status'], 'REQUEST_VERIFIED_FINAL', out)
        self.assertTrue(out['whole_request_verified']);self.assertTrue(out['projection_eligible'])
        self.assertFalse(out['publication_authorized']);self.assertFalse(out['live_activation'])
        self.assertEqual(out['steps_completed'], out['total_steps'])
        r = state(c);self.assertEqual(r['transaction_status'], 'staged')
        old = q['before']['registry']
        for key in old['items']:
            for field in ('id', 'page_url', 'number', 'slideshow'):
                self.assertEqual(r['items'][key][field], old['items'][key][field])
            self.assertEqual(r['items'][key]['revisions'][:len(old['items'][key]['revisions'])], old['items'][key]['revisions'])
        self.assertTrue(all(r['counters'][col] >= n for col, n in old['counters'].items()))
        # Genuine current-only Store projection ONLY AFTER full executor result.
        session = Session(LAB, c['primary'], c['primary_genesis'])
        dest = c['primary'].parent / ('final-projection-' + uuid.uuid4().hex[:6])
        session.store.project(dest)
        payload = parse((dest / 'expected-files.json').read_bytes())
        for item in r['items'].values():
            for rev in item['revisions']:
                self.assertEqual(rev['public_path'].lstrip('/') in payload,
                    item['state'] == 'published' and rev['number'] == item['desired_revision'])
        self.assertEqual(r['receipts'].keys() >= old['receipts'].keys(), True)
        return out, r

    def test_01_several_new_images(self):
        c = fixture('new')
        def change(v):
            for n in (90, 91, 92):v[f'incoming/kolaji/new-{n}.png'] = image(n)
        q = request(c, change);_, r = self.final(c, q)
        self.assertEqual(r['counters']['kolaji'], 24);self.assertEqual(len(r['items']), 24)

    def test_02_replacement_only(self):
        c = fixture('replace');q = request(c, lambda v: replace_original(v))
        _, r = self.final(c, q);self.assertEqual(r['items'][KEY]['desired_revision'], 2)
        self.assertEqual(r['counters']['kolaji'], 21)

    def test_10_independent_mixed_operations(self):
        c = fixture('mixed')
        def change(v):
            composition()(v);v['incoming/kolaji/new-independent.png'] = image(92)
            v['library/kolaji/published/bgzona-p-00002/bgzona-p-00002.txt'] = b'Other item'
        q = request(c, change);_, r = self.final(c, q)
        self.assertEqual(r['counters']['kolaji'], 22)
        self.assertEqual(r['items'][KEY]['desired_revision'], 2)

    def test_11_archive_restore(self):
        c = fixture('lifecycle')
        def move(target):
            def change(v):
                paths = [p for p in v if p.startswith('library/kolaji/') and '/'+KEY+'/' in p]
                pairs = []
                for old in paths:
                    new = f'library/kolaji/{target}/{KEY}/' + old.rsplit('/', 1)[1]
                    v[new] = v.pop(old);pairs.append((old, new))
                return pairs
            return change
        q = request(c, move('archived'));_, r = self.final(c, q)
        self.assertEqual(r['items'][KEY]['state'], 'archived')
        q = request(c, move('published'));_, r = self.final(c, q)
        self.assertEqual(r['items'][KEY]['state'], 'published')

    def rejected(self, c, q, reason):
        previous = fingerprint(c);out = execute(c, q)
        self.assertFalse(out['projection_eligible'], out);self.assertFalse(out['whole_request_verified'], out)
        self.assertIn(reason, out['reason']);self.assertEqual(previous, fingerprint(c))
        return out

    def test_12_conflicting_lifecycle_replacement(self):
        c = fixture('conflict')
        def change(v):
            replace_original(v)
            pairs=[]
            for a in list(v):
                if a.startswith(ROOT):
                    b=a.replace('/published/', '/archived/');v[b]=v.pop(a);pairs.append((a,b))
            return pairs
        self.rejected(c, request(c, change), 'AMBIGUOUS_SAME_ITEM_COMPOSITION')

    def test_13_multiple_originals(self):
        c=fixture('multiple')
        def change(v):replace_original(v, number=90);replace_original(v, number=91)
        self.rejected(c,request(c,change),'AMBIGUOUS_REPLACEMENT_REQUEST')

    def test_14_ambiguous_og(self):
        c=fixture('og-conflict')
        def change(v):composition()(v);v[ROOT+'og.jpg']=image(92)
        self.rejected(c,request(c,change),'AMBIGUOUS_OG')

    def test_15_aggregate_bulk_three_ids(self):
        c=fixture('bulk')
        def change(v):
            composition()(v)
            for n in (2,3):v[f'library/kolaji/published/bgzona-p-{n:05d}/bgzona-p-{n:05d}.txt']=b'x'
        self.rejected(c,request(c,change),'BULK_REVIEW_REQUIRED')

    def test_16_whole_preflight_invalid_new_sidecar(self):
        c=fixture('bad-txt')
        def change(v):composition()(v);v['incoming/kolaji/new.png']=image(92);v['incoming/kolaji/new.txt']=bytes([255])
        self.rejected(c,request(c,change),'INVALID_UTF8')

    def test_17_repeated_identical_and_recovery(self):
        c=fixture('idempotent');q=request(c,composition());self.final(c,q);before=fingerprint(c)
        a=execute(c,q);b=execute(c,q)
        self.assertEqual(a['status'], 'REQUEST_VERIFIED_FINAL',a);self.assertEqual(b['status'],a['status'])
        self.assertEqual(before,fingerprint(c));self.assertEqual(state(c)['items'][KEY]['desired_revision'],2)

    def test_18_new_request_blocked_while_incomplete(self):
        c=fixture('newer-conflict');q=request(c,composition())
        first=execute(c,q,'after-accepted-replacement');self.assertFalse(first['projection_eligible'])
        other=request(c,lambda v:v.__setitem__('incoming/kolaji/newer.png',image(92)))
        self.rejected(c,other,'ANOTHER_REQUEST_IN_PROGRESS');self.final(c,q)

    def test_19_old_valid_request_rejected_after_newer(self):
        c=fixture('stale');q=request(c,composition());self.final(c,q)
        newer=request(c,lambda v:v.__setitem__(ROOT+KEY+'.txt',b'Newer intentional text'))
        self.final(c,newer);self.rejected(c,q,'STALE_OR_CONFLICTING_REQUEST')

    def test_20_durable_pending_journal(self):
        c=fixture('pending');q=request(c,composition());before=latest(c)
        a=execute(c,q,'after-independent-acceptance');self.assertFalse(a['projection_eligible'])
        self.assertEqual(latest(c)['phase'],'accepted');self.assertEqual(latest(c)['index'],before['index']+1)
        self.final(c,q);self.assertEqual(state(c)['items'][KEY]['desired_revision'],2)

    def test_21_missing_accepted_backup(self):
        c=fixture('missing');q=request(c,composition());execute(c,q,'after-accepted-replacement')
        p=c['archives']/latest(c)['backup']['file'];p.rename(p.with_suffix('.quarantined'))
        self.rejected(c,q,'LATEST_BACKUP_MISSING')

    def test_22_corrupt_accepted_backup(self):
        c=fixture('corrupt');q=request(c,composition());execute(c,q,'after-accepted-replacement')
        (c['archives']/latest(c)['backup']['file']).write_bytes(b'SYNTHETIC corruption')
        self.rejected(c,q,'BACKUP_HASH_MISMATCH')

    def test_23_complete_input_digest_binding(self):
        c=fixture('source-binding');q=request(c,composition());q['change']['files'][ROOT+KEY+'.txt']='0'*64
        self.rejected(c,q,'COMMITTED_SOURCE_BYTES_MISMATCH')

    def test_24_no_network_or_owner_remote(self):
        for p in (Path('https://github.com/invalid/invalid'),Path(__file__).resolve().parents[2]):
            with self.assertRaises(Exception):LAB.remote(p)

    def test_25_default_d3_and_session_unchanged(self):
        c=fixture('old-port');job=c['primary'].parent/'owner';job.mkdir()
        repo=job/'r';git(job,'clone','--no-local','--no-checkout',str(c['primary']),str(repo))
        base=value(repo,'rev-parse',MAIN);f=files(repo,base);f['incoming/kolaji/legacy-default.png']=image(90)
        candidate=state_commit(repo,base,f,job/'i');git(repo,'push',str(c['primary']),candidate+':'+MAIN)
        a=run_local(LAB,**c);self.assertEqual(a['status'],'RECONCILED',a)
        self.assertEqual(state(c)['counters']['kolaji'],22)
        b=run_local(LAB,**c);self.assertEqual(b['status'],'ALREADY_PROCESSED',b)

    def test_26_deterministic_request_identity(self):
        c=fixture('identity');q=request(c,composition())
        a=executor.RequestOperation(LAB,**q,interrupt=lambda p:None)
        q2=dict(q);q2['change']=deepcopy(q['change']);q2['change']['operations'].reverse()
        q2['evidence']=replace(q['evidence'],assessment_time=int(time.time()))
        b=executor.RequestOperation(LAB,**q2,interrupt=lambda p:None)
        self.assertEqual(a.request,b.request);self.assertEqual(a.plan_sha,b.plan_sha)

    def test_27_bounded_partial_then_resume(self):
        c=fixture('bounded');q=request(c,composition());a=execute(c,q,max_steps=1)
        self.assertEqual(a['status'],'UNRESOLVED',a);self.assertFalse(a['projection_eligible'])
        self.final(c,q)

    def test_28_actual_process_death_and_fresh_resume(self):
        c=fixture('process');q=request(c,composition())
        config=c['primary'].parent/'child.json'
        config.write_bytes(data({'lab':str(LAB.root),'c':{k:str(v) if isinstance(v,Path) else v for k,v in c.items()},
            'q':{k:asdict(v) if k=='evidence' else str(v) if isinstance(v,Path) else v for k,v in q.items()}}))
        command=[sys.executable,'-B',str(Path(__file__).resolve()),'--child',str(config),'--point','after-accepted-replacement']
        r=subprocess.run(command,capture_output=True,timeout=300)
        config.with_suffix('.stdout').write_bytes(r.stdout);config.with_suffix('.stderr').write_bytes(r.stderr)
        config.with_suffix('.execution.json').write_bytes(data({'command':command,'exit':r.returncode}))
        self.assertEqual(r.returncode,77,r.stderr.decode('utf8','replace'));self.assertEqual(state(c)['items'][KEY]['desired_revision'],2)
        self.final(c,q);self.assertEqual(state(c)['items'][KEY]['desired_revision'],2)


    def test_35_rolling_guard_preserved(self):
        c=fixture('rolling');q=request(c,lambda v:replace_original(v,'bgzona-p-00002',93));self.final(c,q)
        def change(v):replace_original(v,KEY,90);replace_original(v,'bgzona-p-00003',91)
        self.rejected(c,request(c,change),'BULK_REVIEW_REQUIRED')

    def test_36_primary_missing_journal_recovers_from_independent(self):
        c=fixture('missing-primary-journal');q=request(c,composition())
        out=execute(c,q,'after-primary-before-observed');self.assertFalse(out['projection_eligible'])
        self.assertEqual(latest(c)['phase'],'accepted')
        job=c['primary'].parent/'damage';job.mkdir();repo=job/'r'
        git(job,'clone','--no-local','--no-checkout',str(c['primary']),str(repo))
        base=value(repo,'rev-parse',MAIN);buffers=files(repo,base)
        self.assertIn('automation-state/pending.json',buffers)
        buffers.pop('automation-state/pending.json')
        changed=state_commit(repo,base,buffers,job/'i');git(repo,'push',str(c['primary']),changed+':'+MAIN)
        self.final(c,q);self.assertEqual(state(c)['items'][KEY]['desired_revision'],2)

    def test_37_direct_managed_overwrite_rejects(self):
        c=fixture('managed-overwrite')
        q=request(c,lambda v:v.__setitem__(ROOT+KEY+'.png',image(91)))
        self.rejected(c,q,'MISSING_OR_CHANGED_MANAGED_ORIGINAL')

    def test_38_txt_is_intentional_and_byte_preserved(self):
        c=fixture('intentional-txt');raw=bytes([239,187,191])+b'Owner text: name@example.test, phone 123.\r\nSecond line.\r\n'
        def change(v):composition()(v);v[ROOT+KEY+'.txt']=raw
        q=request(c,change);_,r=self.final(c,q)
        session=Session(LAB,c['primary'],c['primary_genesis'])
        self.assertEqual((session.root/ROOT/(KEY+'.txt')).read_bytes(),raw)
        self.assertEqual(r['items'][KEY]['description'],raw.decode('utf-8-sig').strip())

    def test_39_excluded_slideshow_preserved(self):
        key='bgzona-p-00004';c=fixture('no-slides');q=request(c,composition('edited','add',key))
        _,r=self.final(c,q);self.assertFalse(r['items'][key]['slideshow'])

    def test_40_revision_three_and_explicit_old_input_removal(self):
        c=fixture('revision-three');q=request(c,composition());self.final(c,q)
        def change(v):
            v.pop('incoming/replace/kolaji/00001/replace-90.png')
            replace_original(v,number=94)
            v[ROOT+KEY+'.txt']=b'Third revision text'
        q=request(c,change);_,r=self.final(c,q)
        self.assertEqual(r['items'][KEY]['desired_revision'],3)
        self.assertEqual(r['counters']['kolaji'],21)
        self.assertEqual(len(r['items'][KEY]['revisions']),3)


    def test_41_default_entry_cannot_bypass_bound_request(self):
        c=fixture('default-bypass');q=request(c,composition())
        out=execute(c,q,'after-accepted-replacement')
        self.assertFalse(out['projection_eligible'])
        previous=fingerprint(c)
        with self.assertRaisesRegex(Exception,'REQUEST_EXECUTOR_REQUIRED'):
            Session(LAB,c['primary'],c['primary_genesis']).prepare()
        legacy=run_local(LAB,**c)
        self.assertFalse(legacy['projection_eligible'],legacy)
        self.assertIn('REQUEST_EXECUTOR_REQUIRED',legacy['reason'])
        self.assertEqual(previous,fingerprint(c))
        self.final(c,q)


def same_id(txt, og, key=KEY):
    def test(self):
        c=fixture('same-id');q=request(c,composition(txt,og,key));_,r=self.final(c,q)
        item=r['items'][key];self.assertEqual(item['desired_revision'],2)
        self.assertEqual(item['description'],'' if txt in ('delete','empty') else 'Edited synthetic owner text' if txt=='edited' else q['before']['registry']['items'][key]['description'])
        self.assertEqual(item['og'] is None,og=='remove' or og=='keep' and q['before']['registry']['items'][key]['og'] is None)
    return test


for name,txt,og,key in [
 ('03_replace_txt_edit','edited','keep',KEY),('04_replace_txt_delete','delete','keep',KEY),
 ('05_replace_txt_empty','empty','keep',KEY),('06_replace_og_add','keep','add','bgzona-p-00003'),
 ('07_replace_og_replace','keep','replace',KEY),('08_replace_og_remove','keep','remove',KEY),
 ('09_replace_txt_og','edited','replace',KEY),('29_replace_txt_add','edited','keep','bgzona-p-00003')]:
    setattr(Tests,'test_'+name,same_id(txt,og,key))


def interrupted_case(point):
    def test(self):
        c=fixture('interrupt');q=request(c,composition());out=execute(c,q,point)
        self.assertEqual(out['status'],'RECOVERABLE_INTERRUPTION',out)
        self.assertFalse(out['projection_eligible']);self.assertFalse(out['whole_request_verified'])
        self.final(c,q);before=fingerprint(c);again=execute(c,q)
        self.assertEqual(again['status'],'REQUEST_VERIFIED_FINAL',again);self.assertEqual(before,fingerprint(c))
    return test


for n,point in enumerate(('before-first-substep','after-accepted-replacement',
                         'before-metadata-application','after-metadata-acceptance',
                         'before-final-request-verification'),30):
    setattr(Tests,f'test_{n}_interrupt_'+point.replace('-','_'),interrupted_case(point))


def main():
    global WORK,LAB
    parser=argparse.ArgumentParser();parser.add_argument('--work',type=Path);parser.add_argument('--child',type=Path)
    parser.add_argument('--point');parser.add_argument('--only')
    args=parser.parse_args()
    if args.child:
        d=parse(args.child.read_bytes());LAB=Lab(Path(d['lab']))
        c={k:Path(v) if k in ('primary','anchor','archives') else v for k,v in d['c'].items()}
        q=dict(d['q']);q['source']=Path(q['source']);q['evidence']=planner.SourceEvidence(**q['evidence'])
        q['evidence']=replace(q['evidence'],assessment_time=int(time.time()))
        def die(point):
            if point==args.point:os._exit(77)
        out=executor.run_local_request(LAB,**c,**q,interrupt=die)
        print(json.dumps(out));raise RuntimeError('Expected process-death boundary not reached')
    require_work=args.work is not None and not args.work.exists()
    if not require_work:raise RuntimeError('NEW_EXTERNAL_TEST_WORK_REQUIRED')
    WORK=args.work.absolute();WORK.mkdir(parents=True)
    source_hashes={n:digest((Path(__file__).parent/n).read_bytes()) for n in ('intake_plan.py','git_transport.py','authority_coordinator.py','request_executor.py','test_request_executor.py')}
    started=time.perf_counter();initialize()
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(Tests)
    if args.only:
        names=args.only.split(',');suite=unittest.TestSuite(t for t in suite if any(n in t.id() for n in names))
    with (WORK/'tests.log').open('w',encoding='utf8') as stream:
        result=unittest.TextTestRunner(stream=stream,verbosity=2,resultclass=Result).run(suite)
    summary={'tests':result.testsRun,'pass':result.testsRun-len(result.failures)-len(result.errors),
             'fail':len(result.failures),'errors':len(result.errors),'seconds':time.perf_counter()-started,
             'synthetic_only':True,'network':False,'hosted_runs':0,'publication':False,
             'bootstrap_fixture':'FICTITIOUS marker; no frozen/owner originals read',
             'work':str(WORK),'source_sha256':source_hashes}
    (WORK/'summary.json').write_bytes(data(summary));print(json.dumps(summary),flush=True)
    return 0 if result.wasSuccessful() else 1


if __name__=='__main__':sys.exit(main())
