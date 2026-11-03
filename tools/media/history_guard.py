"""Read-only adaptation of A2 git_tools.history_check. No Git transport/writes."""
import json
import subprocess


def check_history(current, historical):
    """Earlier accepted snapshots must never lose IDs, receipts or revisions."""
    for old in historical:
        if current['seq'] < old['seq'] or any(current['counters'].get(c, -1) < n for c, n in old['counters'].items()):
            raise ValueError('HISTORY_COUNTER_OR_SEQUENCE_ROLLBACK')
        for key, item in old['items'].items():
            new = current['items'].get(key)
            if new is None or any(new.get(k) != item.get(k) for k in ('id', 'collection', 'number', 'page_url')):
                raise ValueError('HISTORY_ID_LOSS_OR_REUSE')
            if new['revisions'][:len(item['revisions'])] != item['revisions']:
                raise ValueError('HISTORY_REVISION_LOSS_OR_CHANGE')
            revisions=new['revisions'];number=new.get('desired_revision')
            if (type(number)!=int or number<len(item['revisions']) or number!=len(revisions) or
                any(type(r.get('number'))!=int or r['number']!=n for n,r in enumerate(revisions,1))):
                raise ValueError('HISTORY_REVISION_SEQUENCE')
        for key, receipt in old['receipts'].items():
            new = current['receipts'].get(key)
            if new is None or any(new.get(k) != receipt.get(k) for k in ('input', 'digest', 'item', 'revision')):
                raise ValueError('HISTORY_RECEIPT_LOSS_OR_CHANGE')


def read_git_history(repo, ref='refs/heads/main'):
    """Inspect a local trusted ref only; no fetch, credentials, commits or remote."""
    if not ref.startswith('refs/') or any(c.isspace() for c in ref):
        raise ValueError('EXPLICIT_LOCAL_REF_REQUIRED')
    def git(*args):
        q = subprocess.run(['git', '--no-optional-locks', '-C', str(repo), *args], capture_output=True, timeout=30)
        if q.returncode:
            raise ValueError('HISTORY_GIT_READ_FAILED')
        return q.stdout
    git('rev-parse', '--verify', ref)
    commits = git('log', ref, '--format=%H', '--', 'automation-state/registry.json').decode('ascii').splitlines()
    return [json.loads(git('show', commit + ':automation-state/registry.json').decode('utf-8-sig', 'strict')) for commit in commits]
