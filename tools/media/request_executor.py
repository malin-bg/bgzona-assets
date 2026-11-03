"""E4G inactive request -> actual Store/D3 adapter; marked LOCAL Labs only.

No network backend, CLI, publication or real-media authorization. Input Git
objects and independently accepted D2 records are reverified on every invocation.
Progress bindings live in accepted authority COMMIT METADATA, not a new C1
registry/history/receipt schema. Outcome files are diagnostics, never authority.
The trusted caller supplies SourceEvidence; local Git proofs replace no provider
identity/actor verification required by a future private GitHub backend.
"""
from copy import deepcopy
from pathlib import Path
import time
import uuid

import intake_plan as planner
from importer import Store, Crash, Reject, data, parse, digest, text
from git_transport import (Lab, Session, MAIN, MANAGED, git, value, files,
                           snapshot, relative, require)
from authority_coordinator import Coordinator, Interrupted, PortStop

PREFIX = 'BGZONA-E4G '
EDITABLE = ('incoming/', 'library/')


def binding(repo, commit):
    message = git(repo, 'show', '-s', '--format=%B', commit).stdout.decode('utf8').strip()
    if not message.startswith(PREFIX):
        return None
    row = parse(message[len(PREFIX):].encode('utf8'))
    require(type(row) is dict and set(row) == {
        'request', 'plan', 'base_record', 'step', 'steps', 'phase', 'state',
        'final', 'event_offset'}, 'REQUEST_BINDING_SCHEMA')
    require(type(row['step']) is int and type(row['steps']) is int and
            1 <= row['step'] <= row['steps'] <= planner.MAX_STEPS and
            type(row['event_offset']) is int and row['event_offset'] >= 0 and
            type(row['final']) is bool and row['phase'] in ('accepted', 'staged'),
            'REQUEST_BINDING_SCHEMA')
    for key in ('request', 'plan', 'base_record', 'state'):
        require(type(row[key]) is str and len(row[key]) == 64 and
                all(c in '0123456789abcdef' for c in row[key]), 'REQUEST_BINDING_DIGEST')
    return row


def signature(buffers, event_offset):
    """Exact payload + core semantics; only core-generated NEW event time varies.

    History/journal hashes and sequence are independently checked by D2/D3/C1.
    Their nondeterministic times are never used as an executor progress cursor.
    """
    reg = parse(buffers['automation-state/registry.json'])
    semantic = deepcopy(reg)
    semantic.pop('seq'); semantic.pop('previous')
    require(0 <= event_offset <= len(reg['state_events']), 'EVENT_PREFIX_MISSING')
    for event in semantic['state_events'][event_offset:]:
        event.pop('time', None)
    payload = {p: digest(b) for p, b in buffers.items()
               if p.startswith(('objects/', *EDITABLE))}
    return digest(data({'registry': semantic, 'payload': payload,
                        'pending': 'automation-state/pending.json' in buffers}))


def export(root, buffers):
    require(not root.exists(), 'NEW_EXECUTOR_SNAPSHOT_REQUIRED')
    root.mkdir(parents=True)
    for rel, raw in buffers.items():
        target = root.joinpath(*relative(rel).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as f:
            f.write(raw)


class RequestOperation:
    """Trusted in-process Session operation. All durable acceptance stays in D3."""
    def __init__(self, lab, source, before, change, evidence, interrupt):
        require(isinstance(lab, Lab), 'DISPOSABLE_LAB_REQUIRED')
        self.lab, self.source = lab, lab.remote(source)
        self.before, self.change = parse(data(before)), parse(data(change))
        self.evidence = evidence
        require(type(evidence) is planner.SourceEvidence, 'TRUSTED_SOURCE_EVIDENCE_REQUIRED')
        require(abs(time.time() - evidence.assessment_time) <= 300,
                'FRESH_ASSESSMENT_REQUIRED')
        self.hit = interrupt
        self.job = lab.path(lab.root / 'executor' / uuid.uuid4().hex)
        self.job.mkdir(parents=True)
        repo = self.job / 'source'
        git(self.job, 'clone', '--no-local', '--no-checkout', str(self.source), str(repo))
        old, new = self.before['commit'], self.change['commit']
        require(value(repo, 'show', '-s', '--format=%P', new).split() == [old],
                'SOURCE_PARENT_MISMATCH')
        changed = git(repo, 'diff-tree', '--no-commit-id', '--name-only', '-r', old, new).stdout.decode('utf8').splitlines()
        require(all(p.startswith(EDITABLE) for p in changed), 'SOURCE_SCOPE')
        self.old = files(repo, old, EDITABLE)
        self.new = files(repo, new, EDITABLE)
        require({p: digest(b) for p, b in self.old.items()} == self.before['files'] and
                {p: digest(b) for p, b in self.new.items()} == self.change['files'],
                'COMMITTED_SOURCE_BYTES_MISMATCH')
        export(self.job / 'before', self.old); export(self.job / 'after', self.new)
        plan = planner.plan(self.before, self.change, evidence,
                            self.job / 'before', self.job / 'after')
        require(plan['status'] == 'PLANNED', 'PLAN_' + str(plan['reason']))
        self.removals = [op for step in plan['steps'] if step['kind'] == 'input_remove'
                         for op in step['files']]
        self.plan = plan
        self.request = plan['request_sha256']
        self.steps = [s for s in plan['steps'] if s['kind'] not in ('replay', 'input_remove')]
        require(not self.removals or self.steps, 'INPUT_REMOVAL_ONLY_UNSUPPORTED')
        self.plan_sha = digest(data({'request': self.request, 'steps': self.steps}))
        self.expected = None
        self.done = 0
        self.pending = False
        self.seen = set()
        self.base_index = None

    def stage(self, root, step, first=False):
        """Change ONLY this substep's external view; accepted results carry on."""
        if first:
            # Explicit committed input deletions travel with the first core
            # transition. Receipts/immutable objects are never removed. Pure
            # housekeeping without a core transition is not accepted by R1.
            for op in self.removals:
                dest = root.joinpath(*relative(op['path']).parts)
                self.lab.path(dest)
                require(op['op'] == 'delete' and op['path'].startswith('incoming/') and
                        op['after_sha256'] is None and dest.is_file() and
                        digest(dest.read_bytes()) == op['before_sha256'],
                        'INPUT_REMOVAL_CONFLICT')
                dest.unlink()
        if step['kind'] in ('archive', 'restore'):
            item = self.before['registry']['items'][step['target_id']]
            col, key = item['collection'], item['id']
            start = root / f"library/{col}/{item['state']}/{key}"
            state = 'archived' if step['kind'] == 'archive' else 'published'
            end = root / f'library/{col}/{state}/{key}'
            self.lab.path(start); self.lab.path(end)
            require(start.is_dir() and not end.exists(), 'LIFECYCLE_VIEW_CONFLICT')
            end.parent.mkdir(parents=True, exist_ok=True)
            start.rename(end)  # Explicit synthetic bundle move, never cleanup.
            return
        for op in step['files']:
            require(op['op'] != 'move', 'UNSUPPORTED_SUBSTEP_MOVE')
            rel = op['path']; dest = root.joinpath(*relative(rel).parts)
            self.lab.path(dest)
            current = digest(dest.read_bytes()) if dest.is_file() else None
            require(current == op['before_sha256'], 'SUBSTEP_SOURCE_CONFLICT')
            if op['op'] == 'delete':
                require(dest.is_file(), 'SUBSTEP_SOURCE_MISSING')
                dest.unlink()  # Explicit TXT/OG delete in disposable transaction.
            else:
                raw = self.new[rel]
                require(digest(raw) == op['after_sha256'], 'SUBSTEP_BYTES_CHANGED')
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(raw)

    @staticmethod
    def invoke(store, step):
        if step['core_operation'] == 'add':
            return store.add(fault='after-reserve')
        require(step['core_operation'] == 'sync', 'UNSUPPORTED_CORE_OPERATION')
        return store.sync()

    def simulate(self, context, base):
        """Whole-batch admission through real core, before ANY D3 acceptance."""
        buffers = files(context['recovered'], base['primary_main'])
        require({p: b for p, b in buffers.items() if p.startswith(EDITABLE)} == self.old,
                'BEFORE_EDITABLE_AUTHORITY_MISMATCH')
        root = self.job / 'preflight-transaction'; export(root, buffers)
        witness = self.job / 'preflight-witness.json'
        witness.write_bytes(data({'library_id': base['library_id'],
                                  'seq': base['registry_seq'],
                                  'sha256': base['registry_sha256']}))
        # Historical base was independently restored/verified; no newer Git
        # history is presented as the base of this disposable simulation.
        store = Store(root, witness)
        require(data(store.show()) == data(self.before['registry']),
                'BEFORE_REGISTRY_AUTHORITY_MISMATCH')
        self.offset = len(self.before['registry']['state_events'])
        expected = [{'staged': signature(snapshot(root), self.offset)}]
        for number, step in enumerate(self.steps, 1):
            self.stage(root, step, first=number == 1)
            states = {}
            try:
                self.invoke(store, step)
            except Crash as exc:
                require(str(exc) == 'AFTER_RESERVATION', 'UNEXPECTED_CORE_CRASH')
                states['accepted'] = signature(snapshot(root), self.offset)
                store.show()  # Actual C1 journal roll-forward, no duplicate IDs.
            reg = store.show()
            store._scan(reg, strict=True)  # Validate the complete resulting view.
            require(not store.pending.exists() and reg['transaction_status'] == 'staged',
                    'PREFLIGHT_NOT_FINAL')
            states['staged'] = signature(snapshot(root), self.offset)
            require(states['staged'] != expected[-1]['staged'], 'NO_EFFECT_SUBSTEP')
            expected.append(states)
        self.expected = expected

    def bind(self, context):
        records = context['records']
        matches = [r for r in records if digest(data(r)) == self.before['ledger_record_sha256']]
        require(len(matches) == 1, 'REQUEST_BASE_EVIDENCE_MISSING')
        base = matches[0]
        require(base['phase'] == 'staged' and
                base['primary_main'] == self.before['authority_commit'] and
                base['primary_witness'] == self.before['witness_commit'] and
                base['registry_sha256'] == digest(data(self.before['registry'])) and
                self.evidence.authority_evidence_sha256 == digest(data(base)),
                'REQUEST_BASE_EVIDENCE_MISMATCH')
        self.base_index = base['index']
        suffix = records[self.base_index + 1:]
        if not suffix:
            prior = binding(context['recovered'], base['primary_main'])
            if prior is not None:
                require(prior['final'] and prior['phase'] == 'staged' and
                        prior['step'] == prior['steps'] and
                        prior['state'] == signature(files(context['recovered'], base['primary_main']),
                                                    prior['event_offset']),
                        'ANOTHER_REQUEST_IN_PROGRESS')
        if self.expected is None:
            self.simulate(context, base)
        done = 0; pending = False
        for record in suffix:
            row = binding(context['recovered'], record['primary_main'])
            require(row is not None, 'REQUEST_PROGRESS_BINDING_MISSING')
            require(row['request'] == self.request and row['plan'] == self.plan_sha and
                    row['base_record'] == digest(data(base)), 'STALE_OR_CONFLICTING_REQUEST')
            number = done + 1
            require(row['step'] == number and row['steps'] == len(self.steps) and
                    number <= len(self.steps) and row['event_offset'] == self.offset,
                    'REQUEST_PROGRESS_SEQUENCE')
            phase = record['phase']
            require(row['phase'] == phase and not (pending and phase == 'accepted'),
                    'REQUEST_PROGRESS_PHASE')
            actual = signature(files(context['recovered'], record['primary_main']), self.offset)
            require(actual == row['state'] == self.expected[number].get(phase),
                    'REQUEST_ACCEPTED_STATE_MISMATCH')
            require(row['final'] == (phase == 'staged' and number == len(self.steps)),
                    'REQUEST_FINAL_BINDING_MISMATCH')
            pending = phase == 'accepted'
            if not pending:
                done = number
        self.done, self.pending = done, pending
        self.current = context['latest']
        if done and done not in self.seen:
            self.seen.add(done)
            kind = self.steps[done - 1]['kind']
            if kind == 'replace': self.hit('after-accepted-replacement')
            if kind == 'metadata': self.hit('after-metadata-acceptance')

    def apply(self, session):
        require(not self.pending, 'PENDING_MUST_ROLL_FORWARD_FIRST')
        require(signature(snapshot(session.root), self.offset) ==
                self.expected[self.done]['staged'], 'CURRENT_STATE_CHANGED_OR_NEWER')
        if self.done == len(self.steps):
            return
        step = self.steps[self.done]
        if self.done == 0: self.hit('before-first-substep')
        if step['kind'] == 'metadata': self.hit('before-metadata-application')
        self.stage(session.root, step, first=self.done == 0)
        self.invoke(session.store, step)

    def message(self, session):
        number = self.done + 1
        require(number <= len(self.steps), 'UNPLANNED_CORE_TRANSITION')
        reg = parse((session.root / 'automation-state/registry.json').read_bytes())
        phase = reg['transaction_status']
        state = signature(snapshot(session.root), self.offset)
        require(state == self.expected[number].get(phase), 'PREPARED_SUBSTEP_MISMATCH')
        return PREFIX + data({'request': self.request, 'plan': self.plan_sha,
            'base_record': self.before['ledger_record_sha256'], 'step': number,
            'steps': len(self.steps), 'phase': phase, 'state': state,
            'final': number == len(self.steps) and phase == 'staged',
            'event_offset': self.offset}).decode('utf8')

    def verify_final(self, session, context):
        require(self.done == len(self.steps) and not self.pending and
                context['latest'] == self.current and
                signature(snapshot(session.root), self.offset) == self.expected[-1]['staged'],
                'WHOLE_REQUEST_NOT_FINAL')
        reg = session.store.show()
        session.store._scan(reg, strict=True)
        require(not session.store.pending.exists(), 'PENDING_NOT_FINAL')


def run_local_request(lab, primary, anchor, archives, genesis, library_id,
                      primary_genesis, *, source, before, change, evidence,
                      interrupt=None, max_steps=12, integration=None):
    """Only marked disposable Labs. No projection directory/publication is made.

    Resume by supplying the SAME immutable source documents/commit and original
    before evidence (with freshly assessed time). Accepted Git metadata + D3
    latest record determine remaining work; local diagnostic files are ignored.
    """
    hit = interrupt or (lambda point: None)
    try:
        operation = RequestOperation(lab, source, before, change, evidence, hit)
        coordinator = Coordinator(lab, primary, anchor, archives, genesis, library_id,
                                  primary_genesis, hit, operation=operation, integration=integration)
        outcome = coordinator.run(max_steps=max_steps)
        complete = outcome['projection_eligible'] and outcome['status'] in (
            'RECONCILED', 'ALREADY_PROCESSED')
        outcome.update(request_sha256=operation.request,
                       whole_request_verified=bool(complete),
                       publication_authorized=False, live_activation=False,
                       steps_completed=operation.done, total_steps=len(operation.steps),
                       private_source_commit=change['commit'])
        if complete:
            outcome['status'] = 'REQUEST_VERIFIED_FINAL'
        # Diagnostics are deliberately neither an input nor a resumable cursor.
        (operation.job / 'outcome.json').write_bytes(data(outcome))
        return outcome
    except PortStop as exc:
        return {'status': exc.status, 'reason': exc.code,
                'whole_request_verified': False, 'projection_eligible': False,
                'publication_authorized': False, 'live_activation': False}
    except (Reject, ValueError, KeyError, TypeError, OSError) as exc:
        return {'status': 'REQUEST_REJECTED', 'reason': str(exc),
                'whole_request_verified': False, 'projection_eligible': False,
                'publication_authorized': False, 'live_activation': False}
