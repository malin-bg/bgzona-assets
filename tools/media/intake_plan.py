"""Inactive read-only planner; never executes importer operations.

SourceEvidence must come from a trusted independent verifier. This module
checks exact commitments, not Git authenticity, latest-state freshness or
privacy. No CLI, Git/network calls, Store instance, allocation or file writes.
"""
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
import math
import os
import re
import stat
import unicodedata
from importer import COLS, EXTS, Reject, Store, data, digest, probe, text

MAX_FILES = 10000
MAX_BYTES = 256_000_000
MAX_FILE = 50_000_000
MAX_OPERATIONS = 512
MAX_STEPS = 128


@dataclass(frozen=True)
class SourceEvidence:
    """External verifier commitments, not a self-authenticating attestation.

    Caller must protect this object separately from untrusted documents.
    authority_evidence_sha256 identifies already independently verified evidence;
    this planner does not authenticate that proof. assessment_time is pinned
    verifier input, not a wall-clock read.
    """
    repository_id: int
    repository: str
    before_sha256: str
    change_sha256: str
    authority_evidence_sha256: str
    assessment_time: int
    source_visibility: str


class PlanError(ValueError):
    def __init__(self, code, status="REJECTED"):
        self.code, self.status = code, status
        super().__init__(code)


def _need(ok, code, status="REJECTED"):
    if not ok:
        raise PlanError(code, status)


def _keys(value, expected, code):
    _need(type(value) is dict and set(value) == set(expected), code)


def _sha(value):
    _need(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value),
          "INVALID_SHA256")


def change_digest(change):
    """Canonical committed-delta digest, independent of operation list order."""
    value = dict(change)
    if type(value.get("operations")) is list:
        value["operations"] = sorted(value["operations"], key=data)
    return digest(data(value))


def _oid(value):
    _need(type(value) is str and re.fullmatch(r"[0-9a-f]{40}", value),
          "INVALID_COMMIT_ID")


def _path(value):
    _need(type(value) is str and value and len(value) <= 512, "UNSAFE_PATH")
    p = PurePosixPath(value)
    _need(not p.is_absolute() and str(p) == value and
          all(x not in ("", ".", "..") for x in p.parts) and
          not any(ord(c) < 32 or c in '\\:<>"|?*\x7f' for c in value) and
          unicodedata.normalize("NFC", value) == value, "UNSAFE_PATH")
    for part in p.parts:
        stem = part.split(".")[0].upper()
        _need(part.casefold() != ".git" and not part.endswith((".", " ")) and
              stem not in {"CON", "PRN", "AUX", "NUL"} and
              not re.fullmatch(r"(COM|LPT)[1-9]", stem), "UNSAFE_PATH")
    _need(p.parts[0] in ("incoming", "library"), "OUTSIDE_MEDIA_NAMESPACE")
    return p


def _manifest(value):
    _need(type(value) is dict and len(value) <= MAX_FILES, "INVALID_FILE_MANIFEST")
    folded = set()
    for name, sha in sorted(value.items()):
        _path(name)
        _sha(sha)
        _need(name.casefold() not in folded, "AMBIGUOUS_CASE_PATH")
        folded.add(name.casefold())


def _link(st):
    return stat.S_ISLNK(st.st_mode) or bool(
        getattr(st, "st_file_attributes", 0) &
        getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _read_snapshot(root, expected):
    """Read exact files with descriptor/path identity checks; never write."""
    _need(isinstance(root, Path) and root.is_absolute(), "ABSOLUTE_SNAPSHOT_REQUIRED")
    for parent in (root, *root.parents):
        _need(not _link(parent.lstat()), "LINK_PATH")
    _need(root.is_dir(), "SNAPSHOT_DIRECTORY_REQUIRED")
    result, total = {}, 0
    for directory, dirs, names in os.walk(root, followlinks=False):
        for name in sorted(dirs):
            p = Path(directory) / name
            _path(p.relative_to(root).as_posix())
            _need(not _link(p.lstat()), "LINK_PATH")
        for name in sorted(names):
            p = Path(directory) / name
            rel = p.relative_to(root).as_posix()
            _path(rel)
            before = p.lstat()
            _need(p.resolve().is_relative_to(root.resolve()), "LINK_PATH")
            _need(not _link(before) and stat.S_ISREG(before.st_mode) and
                  before.st_nlink == 1, "LINK_OR_NONREGULAR_FILE")
            _need(before.st_size <= MAX_FILE, "FILE_SIZE_LIMIT")
            fd = os.open(p, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                opened = os.fstat(fd)
                _need((before.st_dev, before.st_ino) ==
                      (opened.st_dev, opened.st_ino) and not _link(opened),
                      "SNAPSHOT_CHANGED")
                with os.fdopen(fd, "rb", closefd=False) as stream:
                    raw = stream.read(MAX_FILE + 1)
                after = os.fstat(fd)
            finally:
                os.close(fd)
            end = p.lstat()
            identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
            _need(identity(before) == identity(after) == identity(end) and
                  len(raw) == before.st_size, "SNAPSHOT_CHANGED")
            total += len(raw)
            _need(total <= MAX_BYTES and len(result) < MAX_FILES, "SNAPSHOT_LIMIT")
            result[rel] = raw
    _need({p: digest(b) for p, b in result.items()} == expected,
          "SNAPSHOT_MANIFEST_MISMATCH")
    return result


def _changes(change, before, after):
    operations = change["operations"]
    _need(type(operations) is list and len(operations) <= MAX_OPERATIONS,
          "OPERATION_LIMIT")
    covered, normalized = set(), []
    for op in operations:
        _need(type(op) is dict and op.get("op") in ("add", "modify", "delete", "move"),
              "INVALID_FILE_OPERATION")
        kind = op["op"]
        wanted = {"op", "path", "before_sha256", "after_sha256"}
        if kind == "move":
            wanted.add("to")
        _keys(op, wanted, "OPERATION_SCHEMA")
        path, target = op["path"], op.get("to", op["path"])
        _path(path)
        _path(target)
        used = [path, target] if kind == "move" else [path]
        _need(len(set(used)) == len(used) and not (set(used) & covered),
              "CONFLICTING_FILE_OPERATIONS", "CONFLICT")
        covered.update(used)
        old, new = before.get(path), after.get(target)
        _need(op["before_sha256"] == (digest(old) if old is not None else None) and
              op["after_sha256"] == (digest(new) if new is not None else None),
              "FILE_OPERATION_DIGEST_MISMATCH")
        if kind == "add":
            valid = old is None and new is not None
        elif kind == "delete":
            valid = old is not None and new is None
        elif kind == "modify":
            valid = old is not None and new is not None and old != new
        else:
            valid = old is not None and new == old and path not in after and target not in before
        _need(valid, "INCONSISTENT_FILE_OPERATION")
        normalized.append(dict(op))
    actual = {p for p in set(before) | set(after) if before.get(p) != after.get(p)}
    _need(covered == actual, "INCOMPLETE_OWNER_DELTA")
    folded = {}
    for path in sorted(set(before) | set(after)):
        _need(path.casefold() not in folded or folded[path.casefold()] == path,
              "CASE_ONLY_PATH_CONFLICT")
        folded[path.casefold()] = path
    return sorted(normalized, key=lambda x: (x["path"], x.get("to", ""), x["op"]))


def _bundle_rows(files, registry, original=False):
    """Check existing identities/bytes; never invoke Store scan/mutation."""
    grouped = {}
    for path, raw in sorted(files.items()):
        parts = _path(path).parts
        if parts[0] != "library":
            continue
        _need(len(parts) == 5 and parts[1] in COLS and
              parts[2] in ("published", "archived"), "INVALID_LIBRARY_PATH")
        col, state, key, name = parts[1:]
        _need(key in registry["items"] and
              registry["items"][key]["collection"] == col, "UNKNOWN_LIBRARY_ID")
        _need(key not in grouped or grouped[key]["state"] == state,
              "DUPLICATE_LIBRARY_ID", "CONFLICT")
        row = grouped.setdefault(key, {"state": state, "files": {}})
        row["files"][name] = raw
    _need(set(grouped) == set(registry["items"]), "MISSING_MANAGED_BUNDLE")
    for key, item in sorted(registry["items"].items()):
        row, current = grouped[key], grouped[key]["files"]
        originals = {PurePosixPath(r["public_path"]).name: r["sha256"]
                     for r in item["revisions"]}
        _need(all(n in current and digest(current[n]) == h for n, h in originals.items()),
              "MISSING_OR_CHANGED_MANAGED_ORIGINAL")
        _need(set(current) <= set(originals) | {key + ".txt", "og.jpg", "og.png"},
              "INVALID_PARTIAL_BUNDLE")
        ogs = [n for n in ("og.jpg", "og.png") if n in current]
        _need(len(ogs) <= 1, "AMBIGUOUS_OG", "CONFLICT")
        rawtxt = current.get(key + ".txt")
        row["text"] = text(rawtxt) if rawtxt is not None else ""
        row["text_sha256"] = digest(rawtxt) if rawtxt is not None else None
        row["og_sha256"] = digest(current[ogs[0]]) if ogs else None
        row["og_ext"] = PurePosixPath(ogs[0]).suffix if ogs else None
        if original:
            _need(row["state"] == item["state"] and row["text"] == item["description"] and
                  row["text_sha256"] == item["description_hash"] and
                  row["og_sha256"] == (item["og"]["sha256"] if item["og"] else None) and
                  row["og_ext"] == (item["og"]["ext"] if item["og"] else None),
                  "BEFORE_BUNDLE_STATE_MISMATCH")
        elif ogs:
            probe(current[ogs[0]], PurePosixPath(ogs[0]).suffix, True)
    return grouped


def _files_for(paths, operations):
    wanted = set(paths)
    return [x for x in operations if x["path"] in wanted or x.get("to") in wanted]


def _library_steps(before, after, reg, operations):
    old, new = _bundle_rows(before, reg, True), _bundle_rows(after, reg)
    steps, sync_ids, lifecycle_ids = [], set(), set()
    for key, item in sorted(reg["items"].items()):
        a, b, col = old[key], new[key], item["collection"]
        oldprefix = f"library/{col}/{a['state']}/{key}/"
        newprefix = f"library/{col}/{b['state']}/{key}/"
        related = [x for x in operations if x["path"].startswith(oldprefix) or
                   x["path"].startswith(newprefix) or x.get("to", "").startswith(newprefix)]
        if a["state"] != b["state"]:
            _need(a["files"] == b["files"], "MOVE_WITH_METADATA_EDIT", "CONFLICT")
            wanted = {(oldprefix + n, newprefix + n) for n in a["files"]}
            actual = {(x["path"], x.get("to")) for x in related if x["op"] == "move"}
            _need(len(related) == len(wanted) and actual == wanted,
                  "EXPLICIT_COMPLETE_BUNDLE_MOVE_REQUIRED")
            kind = "archive" if b["state"] == "archived" else "restore"
            lifecycle_ids.add(key)
            sync_ids.add(key)
        else:
            _need(not any(x["op"] == "move" for x in related),
                  "UNSUPPORTED_LIBRARY_MOVE", "UNSUPPORTED")
            if not related:
                continue
            _need(a["state"] == "published", "ARCHIVED_METADATA_EDIT_UNSUPPORTED",
                  "UNSUPPORTED")
            kind = "metadata"
            sync_ids.add(key)
        intents = []
        for field, av, bv in (("txt", a["text_sha256"], b["text_sha256"]),
                              ("og", a["og_sha256"], b["og_sha256"])):
            if av != bv or field == "og" and a["og_ext"] != b["og_ext"]:
                action = "remove" if bv is None else "add" if av is None else "replace"
                if field == "txt":
                    action = "clear" if not b["text"] else "add" if av is None else "edit"
                intents.append({"field": field, "action": action})
        steps.append({"kind": kind, "collection": col, "target_id": key,
                      "files": related, "metadata_intent": intents,
                      "slideshow": item["slideshow"], "core_operation": "sync"})
    return steps, sync_ids, lifecycle_ids


def _incoming_groups(files):
    groups, replacements = {}, {}
    for path in sorted(files):
        parts = _path(path).parts
        if parts[0] != "incoming":
            continue
        if len(parts) == 3 and parts[1] in COLS:
            col, name = parts[1:]
            p = PurePosixPath(name)
            _need(p.suffix.lower() in (*EXTS, ".txt"), "UNSUPPORTED_INPUT_FORMAT")
            stem = p.stem
            if stem.casefold().endswith(".og"):
                _need(p.suffix.lower() in (".jpg", ".png"), "INVALID_OG_SIDECAR")
                stem, role = stem[:-3], "og"
            elif p.suffix.lower() == ".txt":
                role = "txt"
            else:
                role = "original"
            group = groups.setdefault((col, stem.casefold()), {})
            _need(role not in group, "AMBIGUOUS_PAIRING", "CONFLICT")
            group[role] = path
        elif len(parts) == 5 and parts[1] == "replace" and parts[2] in COLS:
            col, number, name = parts[2:]
            _need(re.fullmatch(r"[0-9]{5}", number) and number != "00000",
                  "INVALID_REPLACEMENT_TARGET")
            p = PurePosixPath(name)
            _need(p.suffix.lower() in EXTS and not p.stem.casefold().endswith(".og"),
                  "INVALID_REPLACEMENT_FORMAT")
            target = f"bgzona-{COLS[col]}-{number}"
            _need(target not in replacements, "AMBIGUOUS_REPLACEMENT_REQUEST", "CONFLICT")
            replacements[target] = path
        else:
            raise PlanError("INVALID_INCOMING_PATH")
    for group in groups.values():
        _need("original" in group, "ORPHAN_SIDECAR")
    return groups, replacements


def _accepted_paths(reg):
    seen = {}
    for receipt in reg["receipts"].values():
        for path, sha in receipt["input"]["files"].items():
            _path(path)
            _sha(sha)
            key = path.casefold()
            _need(key not in seen or seen[key] == sha, "RECEIPT_PATH_CONFLICT")
            seen[key] = sha
    return seen


def _incoming_steps(before, after, reg, operations):
    groups, replacements = _incoming_groups(after)
    _incoming_groups(before)
    accepted_paths = _accepted_paths(reg)
    for path, raw in after.items():
        if path.startswith("incoming/"):
            _need(accepted_paths.get(path.casefold(), digest(raw)) == digest(raw),
                  "INPUT_PATH_CHANGED_AFTER_ACCEPTANCE")
    steps, replace_ids = [], set()
    touched = {x["path"] for x in operations} | {x.get("to") for x in operations}
    for target, path in sorted(replacements.items()):
        _need(target in reg["items"], "UNKNOWN_REPLACEMENT_ID")
        item = reg["items"][target]
        meta = probe(after[path], PurePosixPath(path).suffix)
        request = dict(op="replace", collection=item["collection"], id=target,
                       files={path: digest(after[path])},
                       blobs={path: f"objects/{digest(after[path])}{PurePosixPath(path).suffix.lower()}"})
        receipt_key = digest(data(request))
        replay = receipt_key in reg["receipts"]
        _need(path in touched or replay, "UNPLANNED_EXISTING_INPUT")
        if path not in touched:
            continue
        if replay:
            _need(reg["receipts"][receipt_key]["item"] == target,
                  "REPLACEMENT_RECEIPT_CONFLICT")
        else:
            _need(all(r["sha256"] != meta["sha256"] for r in item["revisions"]),
                  "REPLACEMENT_REVISION_REUSE")
            replace_ids.add(target)
        steps.append({"kind": "replay" if replay else "replace",
                      "collection": item["collection"], "target_id": target,
                      "files": _files_for([path], operations),
                      "slideshow": item["slideshow"], "core_operation": "add"})
    new_contents = {}
    for (col, stem), group in sorted(groups.items()):
        snapshot = {p: after[p] for p in group.values()}
        original = group["original"]
        meta = probe(after[original], PurePosixPath(original).suffix)
        description = text(after[group["txt"]]) if "txt" in group else None
        og = probe(after[group["og"]], PurePosixPath(group["og"]).suffix, True) if "og" in group else None
        request = dict(op="add", files={p: digest(b) for p, b in snapshot.items()},
                       blobs={p: f"objects/{digest(b)}{PurePosixPath(p).suffix.lower()}" for p, b in snapshot.items()})
        receipt_key = digest(data(request))
        replay = receipt_key in reg["receipts"]
        _need(bool(set(snapshot) & touched) or replay, "UNPLANNED_EXISTING_INPUT")
        if not set(snapshot) & touched:
            continue
        matches = [i for i in reg["items"].values() if i["collection"] == col and
                   any(r["sha256"] == meta["sha256"] for r in i["revisions"])]
        _need(len(matches) <= 1, "AMBIGUOUS_DUPLICATE_CONTENT", "CONFLICT")
        target = matches[0]["id"] if matches else None
        if matches and not replay:
            i = matches[0]
            _need(description is None or description == i["description"],
                  "DUPLICATE_DESCRIPTION_CONFLICT", "CONFLICT")
            _need(og is None or i["og"] and og["sha256"] == i["og"]["sha256"],
                  "DUPLICATE_OG_CONFLICT", "CONFLICT")
        if replay:
            target = reg["receipts"][receipt_key]["item"]
        pool_key = (col, meta["sha256"])
        if not matches and not replay and pool_key in new_contents:
            prev_text, prev_og = new_contents[pool_key]
            _need(description is None or description == prev_text,
                  "DUPLICATE_DESCRIPTION_CONFLICT", "CONFLICT")
            _need(og is None or og["sha256"] == prev_og,
                  "DUPLICATE_OG_CONFLICT", "CONFLICT")
        new_contents.setdefault(pool_key, (description or "", og["sha256"] if og else None))
        needed = sum(c == col for c, h in new_contents
                     if not any(i["collection"] == c and any(v["sha256"] == h for v in i["revisions"])
                                for i in reg["items"].values()))
        _need(reg["counters"][col] + needed <= 99999, "COUNTER_EXHAUSTED")
        steps.append({"kind": "replay" if replay else "duplicate" if matches else "new",
                      "collection": col, "target_id": target,
                      "files": _files_for(snapshot, operations),
                      "input_files": {p: digest(b) for p, b in sorted(snapshot.items())},
                      "pairing_key": stem,
                      "slideshow": matches[0]["slideshow"] if matches else col == "kolaji",
                      "core_operation": "add"})
    for op in operations:
        if op["op"] == "delete" and op["path"].startswith("incoming/") and not any(
                op in s["files"] for s in steps):
            steps.append({"kind": "input_remove", "collection": None, "target_id": None,
                          "files": [op], "core_operation": None})
    _need(not any(x["op"] == "move" and x["path"].startswith("incoming/") for x in operations),
          "INCOMING_MOVE_UNSUPPORTED", "UNSUPPORTED")
    return steps, replace_ids


def _bulk(reg, sync_ids, lifecycle_ids, replace_ids, at):
    _need(len(sync_ids | replace_ids) < 3, "BULK_REVIEW_REQUIRED")
    recent = set()
    for event in reg["state_events"]:
        _need(type(event) is dict and event.get("id") in reg["items"] and
              type(event.get("time")) in (int, float) and
              math.isfinite(event["time"]) and 0 <= event["time"] <= at,
              "INVALID_STATE_EVENT_EVIDENCE")
        if event["time"] >= at - 86400:
            recent.add(event["id"])
    affected = lifecycle_ids | replace_ids
    rolling = recent | affected
    published = sum(i["state"] == "published" for i in reg["items"].values())
    if affected:
        _need(len(rolling) < 3 and
              not (len(rolling) >= 2 and len(rolling) / max(1, published) >= .10),
              "BULK_REVIEW_REQUIRED")
    return {"status": "PASS", "existing_changed_ids": sorted(sync_ids | replace_ids),
            "rolling_lifecycle_replacement_ids": sorted(rolling),
            "published_before": published, "bulk_override": False}


PRIVACY = {
    "scope": "ALL_OWNER_WEBSITES_AND_PUBLIC_DISTRIBUTION",
    "assessment": "NOT_ASSESSED",
    "git_hash_is_privacy_evidence": False,
    "sanitization_implemented": False,
    "publication_safe": False,
    "required_gate": "FORMAT_AWARE_PRIVACY_AND_FIDELITY_BEFORE_ANY_PUBLIC_EXPOSURE",
    "final_public_hashes": "CALCULATE_AFTER_SEPARATELY_VERIFIED_SANITIZATION",
    "plan_storage": "PROTECTED_NONPUBLIC_PROVENANCE_NOT_A_PUBLIC_ARTIFACT",
}


def plan(before, change, evidence, before_root, after_root):
    """Return a deterministic diagnostic plan, never execute it.

    before: schema, repository{id,name}, commit, authority_commit, witness_commit,
      ledger_record_sha256, registry, files{relative_path:sha256}.
    change: schema, repository, parent, commit, before_state_sha256, files,
      operations[{op,path,before_sha256,after_sha256,to (move only)}].
    Roots are COMPLETE editable snapshots (incoming/library only). Every actual
    byte/path change must be declared; lifecycle moves are explicit. Evidence
    is supplied by a trusted external verifier, not untrusted verified=true JSON.
    """
    result = {"schema": 1, "status": "REJECTED", "reason": None,
              "source": None, "request_sha256": None, "steps": [],
              "authority_accepted": False, "execution_authorized": False,
              "publication_authorized": False, "ids_allocated": [],
              "privacy": dict(PRIVACY)}
    try:
        _need(type(evidence) is SourceEvidence, "TRUSTED_SOURCE_EVIDENCE_REQUIRED")
        _need(type(evidence.repository_id) is int and evidence.repository_id > 0 and
              type(evidence.repository) is str and
              re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", evidence.repository),
              "TRUSTED_REPOSITORY_REQUIRED")
        for value in (evidence.before_sha256, evidence.change_sha256,
                      evidence.authority_evidence_sha256):
            _sha(value)
        _need(type(evidence.assessment_time) is int and evidence.assessment_time >= 0,
              "PINNED_ASSESSMENT_TIME_REQUIRED")
        _need(evidence.source_visibility in ("local-unpublished", "private", "public"),
              "SOURCE_VISIBILITY_REQUIRED")
        _keys(before, ("schema", "repository", "commit", "authority_commit",
                       "witness_commit", "ledger_record_sha256", "registry", "files"),
              "BEFORE_SCHEMA")
        _keys(change, ("schema", "repository", "parent", "commit",
                       "before_state_sha256", "files", "operations"), "CHANGE_SCHEMA")
        _need(type(before["schema"]) is int and before["schema"] == 1 and
              type(change["schema"]) is int and change["schema"] == 1, "INPUT_SCHEMA")
        repo = {"id": evidence.repository_id, "name": evidence.repository}
        for source_repo in (before["repository"], change["repository"]):
            _keys(source_repo, ("id", "name"), "REPOSITORY_SCHEMA")
            _need(type(source_repo["id"]) is int and type(source_repo["name"]) is str,
                  "REPOSITORY_IDENTITY_MISMATCH")
        _need(before["repository"] == change["repository"] == repo,
              "REPOSITORY_IDENTITY_MISMATCH")
        for value in (before["commit"], before["authority_commit"],
                      before["witness_commit"], change["parent"], change["commit"]):
            _oid(value)
        _sha(before["ledger_record_sha256"])
        _need(change["parent"] == before["commit"] and change["commit"] != before["commit"],
              "COMMIT_IDENTITY_MISMATCH")
        _need(digest(data(before)) == evidence.before_sha256 ==
              change["before_state_sha256"] and
              change_digest(change) == evidence.change_sha256, "SOURCE_BINDING_MISMATCH")
        identity = asdict(evidence)
        identity.update(before_commit=before["commit"], owner_commit=change["commit"],
                        authority_commit=before["authority_commit"],
                        witness_commit=before["witness_commit"],
                        ledger_record_sha256=before["ledger_record_sha256"])
        request_id = digest(data({"schema": 1, "repository": repo,
                                  "before_sha256": evidence.before_sha256,
                                  "change_sha256": evidence.change_sha256}))
        result.update(source=identity, request_sha256=request_id)
        _need(evidence.source_visibility != "public",
              "PUBLIC_SOURCE_PRIVACY_BOUNDARY_UNVERIFIED", "UNSUPPORTED")
        reg = before["registry"]
        _need(type(reg) is dict and type(reg.get("schema")) is int and
              reg.get("schema") == 1 and reg.get("transaction_status") == "staged",
              "FINAL_BEFORE_STATE_REQUIRED")
        _keys(reg, ("schema", "library_id", "seq", "previous", "counters",
                    "items", "receipts", "bootstrap", "state_events",
                    "transaction_status"), "REGISTRY_SCHEMA")
        _need(type(reg["items"]) is dict and type(reg["receipts"]) is dict and
              len(reg["items"]) <= MAX_FILES and len(reg["receipts"]) <= MAX_FILES,
              "REGISTRY_LIMIT")
        Store._validate(None, reg)  # Existing read-only structural validator only.
        _need(type(reg.get("library_id")) is str and
              re.fullmatch(r"[0-9a-f]{32}", reg["library_id"]) and
              type(reg.get("state_events")) is list, "INVALID_BEFORE_REGISTRY")
        for item in reg["items"].values():
            _keys(item, ("id", "collection", "number", "page_url", "state",
                         "slideshow", "description", "description_hash", "og",
                         "desired_revision", "revisions"), "ITEM_SCHEMA")
            _need(type(item.get("slideshow")) is bool and
                  (item["collection"] == "kolaji" or not item["slideshow"]),
                  "INVALID_SLIDESHOW_STATE")
        _manifest(before["files"])
        _manifest(change["files"])
        old, new = _read_snapshot(before_root, before["files"]), _read_snapshot(after_root, change["files"])
        operations = _changes(change, old, new)
        library, sync_ids, lifecycle_ids = _library_steps(old, new, reg, operations)
        incoming, replace_ids = _incoming_steps(old, new, reg, operations)
        touched_ids = {}
        for step in library + incoming:
            key = step["target_id"]
            if key is not None and step["kind"] != "replay":
                previous = touched_ids.get(key)
                # E4G: only an explicit replacement plus published TXT/OG changes
                # may compose. Lifecycle/repeated originals remain ambiguous.
                _need(previous is None or {previous, step["kind"]} == {"replace", "metadata"},
                      "AMBIGUOUS_SAME_ITEM_COMPOSITION", "CONFLICT")
                touched_ids[key] = step["kind"]
        guards = _bulk(reg, sync_ids, lifecycle_ids, replace_ids, evidence.assessment_time)
        steps = library + incoming
        _need(len(steps) <= MAX_STEPS, "SUBSTEP_LIMIT")
        priority = {"replace": 0, "metadata": 1, "archive": 1, "restore": 1,
                    "new": 2, "duplicate": 2, "replay": 3, "input_remove": 4}
        steps.sort(key=lambda s: (priority[s["kind"]], s["collection"] or "",
                                 s.get("pairing_key", s["target_id"] or ""),
                                 (s["files"][0]["path"].casefold() if s["files"] else "")))
        for n, step in enumerate(steps, 1):
            step["index"] = n
            step["subrequest_sha256"] = digest(data({"request": request_id, "step": step}))
        result.update(status="PLANNED", reason=None, steps=steps,
                      aggregate=guards, changed_paths=len(operations),
                      preconditions=[
                          "INDEPENDENTLY_REVERIFY_SOURCE_AUTHORITY_AND_FRESHNESS",
                          "NO_PENDING_JOURNAL_OR_UNACCEPTED_STATE",
                          "RECHECK_AGGREGATE_AND_CORE_GUARDS_AT_EXECUTION",
                          "ISOLATE_EACH_SUBSTEP_INPUT_VIEW_AND_CARRY_ACCEPTED_RESULTS",
                          "USE_EXISTING_IMPORTER_COORDINATOR_RECEIPTS_AND_BACKUP_GATES",
                          "DO_NOT_PUBLISH_PARTIAL_BATCH",
                          "SEPARATE_PRIVACY_GATE_BEFORE_PUBLIC_GIT_LOGS_ARTIFACTS_RELEASES",
                          "SANITIZED_DERIVATIVES_REQUIRE_NEW_VERIFIED_INPUT_BINDINGS",
                      ])
    except PlanError as exc:
        result.update(status=exc.status, reason=exc.code, steps=[])
    except Reject as exc:
        result.update(status="REJECTED", reason="CORE_" + str(exc).split(":")[0], steps=[])
    except (KeyError, TypeError, ValueError, OSError, OverflowError):
        result.update(status="REJECTED", reason="INVALID_OR_INACCESSIBLE_INPUT", steps=[])
    return result


def plan_bytes(before, change, evidence, before_root, after_root):
    """Canonical UTF-8 JSON bytes; creates no output file."""
    return data(plan(before, change, evidence, before_root, after_root))
