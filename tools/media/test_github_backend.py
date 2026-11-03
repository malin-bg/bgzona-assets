"""NEW E4H offline boundary tests. No Git/network/core transaction execution.

Fake Git objects use actual Git object hashing/tree membership. Release bytes
are FICTITIOUS bundles: no native GitHub CAS, WORM or D3 restore is demonstrated.
All provider identities, actor IDs, account usage and privacy proofs are fake.
"""
import argparse
from copy import deepcopy
from dataclasses import asdict, replace
from hashlib import sha1
from pathlib import Path
from unittest.mock import patch
import ast
import json
import socket
import subprocess
import sys
import time
import unittest
import urllib.request

import github_backend as gb
from importer import data, digest, external

WORK = None
ROWS = []
COUNTS = {"network_attempts": 0, "process_attempts": 0}
SECRET = "PRIVATE_SYNTHETIC_SECRET_DO_NOT_LOG"
RAW = (SECRET + " raw input bytes").encode()
CLEAN = b"FICTITIOUS independently checked derived bytes; not an image"
TXT = b"\xef\xbb\xbfOwner prose: name@example.test, 12345.\r\nSecond line.\r\n"
NOW = 1000


def no_network(*args, **kwargs):
    COUNTS["network_attempts"] += 1
    raise AssertionError("Network forbidden")


def no_process(*args, **kwargs):
    COUNTS["process_attempts"] += 1
    raise AssertionError("Process/Git forbidden")


class Reader:
    def __init__(self, session, repos, objects, refs):
        self.identity, self.repos, self.objects, self.refs = session, repos, objects, refs
        self.assets = {}
        self.hook = None
        self.calls = []

    def session(self):
        return self.identity

    def repository(self, rid):
        self.calls.append("repository")
        return self.repos[rid]

    def ref(self, rid, ref):
        self.calls.append("ref")
        if self.hook:
            self.hook(self, rid, ref)
        return self.refs[rid, ref]

    def git_object(self, rid, oid):
        self.calls.append("git_object")
        return self.objects[rid, oid]

    def asset(self, rid, release, asset):
        self.calls.append("asset")
        result = self.assets[rid, release, asset]
        if isinstance(result, Path):
            return gb.AssetBytes(rid, release, asset, result.read_bytes())
        return result


class Verifier:
    def __init__(self, identity):
        self.identity, self.proofs = identity, {}

    def session(self):
        return self.identity

    def derivation(self, proof):
        return self.proofs[proof]


class Quota:
    def __init__(self, evidence):
        self.evidence = evidence
        self.calls = 0

    def observation(self, account):
        self.calls += 1
        return self.evidence


class Writer:
    def __init__(self, identity, public):
        self.identity, self.public = identity, public
        self.calls, self.mutations = 0, 0
        self.before = None
        self.after = None
        self.caps = frozenset({"single_ref_cas_simulated"})

    def session(self):
        return self.identity

    def capabilities(self):
        return self.caps

    def compare_and_swap(self, rid, ref, expected, target):
        self.calls += 1
        if self.before:
            self.before()
        if self.public.refs[rid, ref] != expected:
            raise RuntimeError(SECRET)
        self.public.refs[rid, ref] = target  # Fake linearization, NOT GitHub proof.
        self.mutations += 1
        if self.after:
            self.after()


class Fixture:
    def __init__(self):
        self.objects, self.refs = {}, {}
        repos = (gb.RepoPin("intake", 101, *gb.NAMES["intake"]),
                 gb.RepoPin("assets", 202, *gb.NAMES["assets"]),
                 gb.RepoPin("control", 303, *gb.NAMES["control"]))
        self.repos = {p.numeric_id: p for p in repos}
        self.raw_pin = self.pin(101, RAW)
        self.output_pin = self.pin(101, CLEAN)
        self.txt_pin = self.pin(101, TXT)
        self.parent = self.commit(101, {}, message="private parent")
        self.source = self.commit(101, {"incoming/kolaji/new.png": RAW,
                                      "incoming/kolaji/new.txt": TXT}, self.parent,
                                  message="private request")
        self.code = self.commit(303, {}, message="trusted execution code")
        self.verifier_code = self.commit(303, {}, message="separate verifier code")
        self.base = self.commit(202, {}, message="synthetic base")
        inp = {"op": "add", "files": {"incoming/kolaji/new.png": digest(RAW)}}
        self.receipt = digest(data(inp))
        self.reg = {"schema": 1, "library_id": "SYNTHETIC_LIBRARY", "seq": 0,
            "previous": None, "transaction_status": "staged",
            "counters": {"kolaji": 1, "poslaniya": 0}, "state_events": [],
            "bootstrap": None,
            "items": {"bgzona-p-00001": {"id": "bgzona-p-00001", "number": 1,
                "collection": "kolaji", "page_url": "/kolaji/kolaj-00001/",
                "state": "published", "desired_revision": 1, "slideshow": True,
                "description": "", "og": None,
                "revisions": [{"number": 1, "sha256": digest(CLEAN), "ext": ".png",
                    "blob": "objects/" + digest(CLEAN) + ".png",
                    "public_path": "/kolaji/full/bgzona-p-00001.png"}]}},
            "receipts": {self.receipt: {"digest": self.receipt, "input": inp,
                "item": "bgzona-p-00001", "revision": 1, "status": "staged"}}}
        self.authority = self.commit(202, {"automation-state/registry.json": data(self.reg)},
                                     self.base, message="synthetic authority")
        witness = {"schema": 1, "authority": self.authority,
                   "library_id": self.reg["library_id"], "seq": 0,
                   "counters": self.reg["counters"], "registry_sha256": digest(data(self.reg)),
                   "previous": None}
        self.witness = self.commit(202, {"witness.json": data(witness)}, message="witness")
        self.bundle = b"FICTITIOUS D3 BACKUP BYTES - NOT A REAL GIT BUNDLE"
        self.record = {"schema": 1, "index": 0, "previous": None,
            "library_id": self.reg["library_id"], "registry_seq": 0,
            "counters": self.reg["counters"], "registry_sha256": digest(data(self.reg)),
            "primary_main": self.authority, "primary_witness": self.witness,
            "primary_base": self.base, "phase": "staged",
            "operation": digest(data({"library": self.reg["library_id"], "seq": 0,
                                     "registry": digest(data(self.reg))})),
            "backup": {"file": digest(self.bundle) + ".bundle", "sha256": digest(self.bundle),
                       "bytes": len(self.bundle), "full": True}}
        self.ledger = self.commit(303, {"anchor.json": data(self.record),
                                      "records/00000000.json": data(self.record)},
                                  message="fake pinned independent record")
        self.delivery = self.commit(303, {}, message="delivery base")
        self.target = self.commit(303, {}, self.delivery, message="next fake control state")
        self.refs.update({(101, gb.MAIN): self.source, (202, gb.MAIN): self.authority,
            (202, gb.WITNESS): self.witness,
            (303, "refs/heads/automation-control"): self.code,
            (303, "refs/heads/automation-ledger"): self.ledger,
            (303, "refs/heads/automation-delivery"): self.delivery})
        actors = (("private_read", 11), ("public_read", 12),
                  ("independent_verify", 13), ("control_write", 14))
        self.policy = gb.Policy(repos, actors, self.code, self.verifier_code,
            self.reg["library_id"], 404, (("private_minutes", 10), ("storage_bytes", 1000)))
        def session(actor, grants, code=self.code):
            return gb.SessionIdentity(actor, code, frozenset(grants), NOW, NOW + 60)
        self.private = Reader(session(11, {(101, "read")}), self.repos, self.objects, self.refs)
        self.public = Reader(session(12, {(202, "read"), (303, "read")}),
                             self.repos, self.objects, self.refs)
        self.verifier = Verifier(session(13, {(101, "verify")}, self.verifier_code))
        self.writer = Writer(session(14, {(303, "cas")}), self.public)
        q = gb.QuotaObservation(404, NOW, NOW + 60, "Free",
             (("private_minutes", 100), ("storage_bytes", 10000)),
             frozenset({"private_minutes", "storage_bytes"}), 0, False)
        self.quota = Quota(q)
        self.ports = gb.OfflinePorts(self.private, self.public, self.verifier,
                                     self.writer, self.quota)
        self.backend = gb.Backend(self.policy, self.ports, clock=lambda: NOW)
        self.pins = gb.StatePins(digest(b"SYNTHETIC request"), self.source, self.parent,
            self.authority, self.authority, self.witness, self.ledger,
            digest(data(self.record)), digest(data(self.reg["receipts"])), self.receipt)
        self.demand = {"private_minutes": 5, "storage_bytes": 1000}
        self.locator = gb.AssetPin("control", 501, 601, digest(self.bundle), len(self.bundle))
        self.public.assets[303, 501, 601] = gb.AssetBytes(303, 501, 601, self.bundle)

    def obj(self, rid, kind, raw):
        oid = sha1(kind.encode() + b" " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        self.objects[rid, oid] = gb.GitObject(kind, raw)
        return oid

    def pin(self, rid, raw):
        return gb.ObjectPin(self.obj(rid, "blob", raw), digest(raw), len(raw))

    def tree(self, rid, paths):
        dirs = {}
        for path, raw in paths.items():
            a, sep, b = path.partition("/")
            if sep:
                dirs.setdefault(a, {})[b] = raw
            else:
                dirs[a] = raw
        rows = []
        for name, child in sorted(dirs.items()):
            mode = b"40000" if isinstance(child, dict) else b"100644"
            oid = self.tree(rid, child) if isinstance(child, dict) else self.obj(rid, "blob", child)
            rows.append(mode + b" " + name.encode() + b"\0" + bytes.fromhex(oid))
        return self.obj(rid, "tree", b"".join(rows))

    def commit(self, rid, paths, parent=None, message="fixture"):
        raw = b"tree " + self.tree(rid, paths).encode() + b"\n"
        if parent:
            raw += b"parent " + parent.encode() + b"\n"
        return self.obj(rid, "commit", raw + b"\n" + message.encode())

    def raw(self):
        r = self.backend.read_source(self.pins, "incoming/kolaji/new.png", self.raw_pin)
        assert r.status == "PRIVATE_BYTES_SIMULATED", r
        return r.payload

    def derivation(self, **changes):
        p = gb.Derivation(self.pins.request_sha256, self.source, self.raw_pin,
             self.output_pin, "original", "bgzona-image-privacy-r1",
             "SANITIZED_AND_VERIFIED", 13, self.verifier_code)
        p = replace(p, **changes)
        key = digest(data(asdict(p)))
        self.verifier.proofs[key] = p
        return key

    def accepted(self):
        return self.backend.inspect(self.pins)


class Tests(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()

    def reject(self, result, reason):
        self.assertNotIn(result.status, ("ADMITTED_SIMULATION", "PINNED_STATE_SIMULATED",
            "APPLIED_SIMULATION", "DERIVATION_BOUND_SIMULATED"), result)
        self.assertEqual(result.reason, reason, result)
        self.assertFalse(result.summary()["publication_authorized"])
        return result

    def test_01_pinned_numeric_roles_and_objects(self):
        r = self.f.accepted()
        self.assertEqual(r.status, "PINNED_STATE_SIMULATED", r)
        self.assertTrue(r.payload["receipt_present"])
        self.assertFalse(r.summary()["d3_chain_verified"])

    def test_02_wrong_numeric_repository(self):
        self.f.repos[101] = replace(self.f.repos[101], numeric_id=999)
        self.reject(self.f.accepted(), "REPOSITORY_IDENTITY")

    def test_03_wrong_role_or_visibility(self):
        self.f.repos[101] = replace(self.f.repos[101], role="assets")
        self.reject(self.f.accepted(), "REPOSITORY_IDENTITY")
        self.f.repos[101] = gb.RepoPin("intake", 101, gb.NAMES["intake"][0], "public")
        self.reject(self.f.accepted(), "REPOSITORY_IDENTITY")

    def test_04_stale_source_commit(self):
        self.f.refs[101, gb.MAIN] = self.f.commit(101, {}, self.f.source)
        self.reject(self.f.accepted(), "SOURCE_IDENTITY")

    def test_05_wrong_source_parent(self):
        r = self.f.backend.inspect(replace(self.f.pins, parent=self.f.authority))
        self.reject(r, "INVALID_ANCESTRY")

    def test_06_unrelated_assets_ancestry(self):
        unrelated = self.f.commit(202, {}, message="unrelated")
        self.f.refs[202, gb.MAIN] = unrelated
        r = self.f.backend.inspect(replace(self.f.pins, assets_tip=unrelated))
        self.reject(r, "INVALID_ANCESTRY")

    def test_07_concurrent_state_advancement(self):
        calls = []
        def hook(port, rid, ref):
            if (rid, ref) == (101, gb.MAIN):
                calls.append(1)
                if len(calls) == 2:
                    port.refs[rid, ref] = self.f.commit(101, {}, self.f.source)
        self.f.private.hook = hook
        self.reject(self.f.accepted(), "STALE_STATE")

    def test_08_non_fast_forward(self):
        unrelated = self.f.commit(303, {}, message="unrelated control")
        r = self.f.backend.simulate_control_ff(self.f.pins, self.f.delivery, unrelated, self.f.demand)
        self.reject(r, "NON_FAST_FORWARD")
        self.assertEqual(self.f.writer.calls, 0)

    def test_09_missing_independent_object(self):
        self.f.objects.pop((303, self.f.ledger))
        self.reject(self.f.accepted(), "PROVIDER_UNAVAILABLE")

    def test_10_corrupt_independent_bytes(self):
        obj = self.f.objects[303, self.f.ledger]
        self.f.objects[303, self.f.ledger] = replace(obj, raw=obj.raw + b"corruption")
        self.reject(self.f.accepted(), "OBJECT_IDENTITY")

    def test_11_independent_record_pin_mismatch(self):
        self.reject(self.f.backend.inspect(replace(self.f.pins, record_sha256="0"*64)),
                    "INDEPENDENT_EVIDENCE")

    def test_12_wrong_expected_authority_witness(self):
        self.reject(self.f.backend.inspect(replace(self.f.pins, witness=self.f.base)), "STALE_STATE")
        self.reject(self.f.backend.inspect(replace(self.f.pins, authority=self.f.base)),
                    "AUTHORITY_IDENTITY")

    def test_13_backup_exact_readback(self):
        path = WORK / "synthetic-backup.bundle"
        if not path.exists():
            path.write_bytes(self.f.bundle)
        self.f.public.assets[303, 501, 601] = path
        r = self.f.backend.recovery_bytes(self.f.pins, self.f.locator, candidate=self.f.bundle)
        self.assertEqual(r.status, "PINNED_RECOVERY_BYTES_SIMULATED", r)
        self.assertEqual(r.payload, path.read_bytes())

    def test_14_backup_hash_pin_mismatch(self):
        r = self.f.backend.recovery_bytes(self.f.pins, replace(self.f.locator, sha256="0"*64))
        self.reject(r, "BACKUP_IDENTITY")

    def test_15_corrupt_recovery_bytes(self):
        self.f.public.assets[303, 501, 601] = gb.AssetBytes(303, 501, 601, b"CORRUPT")
        self.reject(self.f.backend.recovery_bytes(self.f.pins, self.f.locator), "RECOVERY_BYTES")

    def test_16_missing_recovery_bytes(self):
        self.f.public.assets.clear()
        self.reject(self.f.backend.recovery_bytes(self.f.pins, self.f.locator), "PROVIDER_UNAVAILABLE")

    def test_17_inconsistent_recovery_second_read(self):
        original = self.f.public.asset
        def changing(*args):
            value = original(*args)
            self.f.public.assets[303, 501, 601] = gb.AssetBytes(303, 501, 601, b"damaged")
            return value
        self.f.public.asset = changing
        self.reject(self.f.backend.recovery_bytes(self.f.pins, self.f.locator), "RECOVERY_BYTES")

    def test_18_asset_id_not_filename(self):
        self.f.public.assets[303, 501, 601] = gb.AssetBytes(303, 501, 999, self.f.bundle)
        self.reject(self.f.backend.recovery_bytes(self.f.pins, self.f.locator), "BACKUP_IDENTITY")

    def test_19_raw_cannot_enter_public(self):
        raw = self.f.raw()
        self.reject(self.f.backend.public_preview(raw), "RAW_TO_PUBLIC")
        self.reject(self.f.backend.public_preview({"verified": True, "bytes": RAW}), "OUTPUT_CAPABILITY")
        self.reject(self.f.backend.intentional_txt(self.f.pins, raw, "incoming/kolaji/fake.txt"),
                    "TXT_STRUCTURE")

    def test_20_bound_sanitized_preview_provenance_private(self):
        raw = self.f.raw()
        key = self.f.derivation()
        result = self.f.backend.verify_derivation(self.f.pins, raw, self.f.output_pin, key, "original")
        self.assertEqual(result.status, "DERIVATION_BOUND_SIMULATED", result)
        public = self.f.backend.public_preview(result.payload)
        self.assertEqual(public.payload, CLEAN)
        self.assertNotEqual(raw.pin.sha256, self.f.output_pin.sha256)
        self.assertEqual(result.payload.binding.raw, self.f.raw_pin)
        self.assertNotIn(self.f.raw_pin.sha256, json.dumps(public.summary()))
        self.assertFalse(public.summary()["publication_authorized"])

    def test_21_derived_hash_is_not_raw_identity(self):
        raw = self.f.raw(); key = self.f.derivation(raw=self.f.output_pin)
        self.reject(self.f.backend.verify_derivation(self.f.pins, raw, self.f.output_pin,
                                                    key, "original"), "DERIVATION_IDENTITY")

    def test_22_valid_hash_without_privacy_evidence(self):
        raw = self.f.raw(); key = self.f.derivation(status="NEEDS_REVIEW")
        self.reject(self.f.backend.verify_derivation(self.f.pins, raw, self.f.output_pin,
                                                    key, "original"), "DERIVATION_IDENTITY")

    def test_23_wrong_independent_verifier(self):
        raw = self.f.raw(); key = self.f.derivation(verifier_actor=11)
        self.reject(self.f.backend.verify_derivation(self.f.pins, raw, self.f.output_pin,
                                                    key, "original"), "DERIVATION_IDENTITY")

    def test_24_tokens_are_backend_and_identity_bound(self):
        raw = self.f.raw()
        forged = replace(raw)
        key = self.f.derivation()
        self.reject(self.f.backend.verify_derivation(self.f.pins, forged, self.f.output_pin,
                                                    key, "original"), "PRIVACY_EVIDENCE")
        result = self.f.backend.verify_derivation(self.f.pins, raw, self.f.output_pin, key, "original")
        self.reject(self.f.backend.public_preview(replace(result.payload)), "OUTPUT_CAPABILITY")
        other = gb.Backend(self.f.policy, self.f.ports, clock=lambda: NOW)
        self.reject(other.public_preview(result.payload), "OUTPUT_CAPABILITY")

    def test_25_intentional_txt_exact_bytes(self):
        r = self.f.backend.read_source(self.f.pins, "incoming/kolaji/new.txt", self.f.txt_pin)
        p = self.f.backend.intentional_txt(self.f.pins, r.payload, "incoming/kolaji/new.txt")
        self.assertEqual(p.status, "INTENTIONAL_TXT_SIMULATED", p)
        self.assertEqual(self.f.backend.public_preview(p.payload).payload, TXT)

    def test_26_private_reader_cannot_be_public_writer(self):
        self.f.writer.identity = self.f.private.identity
        self.reject(self.f.backend.simulate_control_ff(self.f.pins, self.f.delivery,
                    self.f.target, self.f.demand), "ACTOR_SCOPE")
        self.assertEqual(self.f.writer.calls, 0)

    def test_27_extra_universal_grants_reject(self):
        self.f.private.identity = replace(self.f.private.identity,
            grants=frozenset({(101, "read"), (202, "cas")}))
        self.reject(self.f.accepted(), "CREDENTIAL_SCOPE")

    def test_28_unauthorized_actor(self):
        self.f.private.identity = replace(self.f.private.identity, actor_id=999)
        self.reject(self.f.accepted(), "ACTOR_SCOPE")

    def test_29_trusted_code_revision(self):
        self.f.public.identity = replace(self.f.public.identity, code_oid="0"*40)
        self.reject(self.f.accepted(), "CODE_IDENTITY")

    def test_30_expired_provider_session(self):
        self.f.private.identity = replace(self.f.private.identity, observed_at=800, expires_at=850)
        self.reject(self.f.accepted(), "STALE_SESSION")

    def test_31_missing_quota(self):
        self.f.quota.evidence = None
        self.suspended("QUOTA_UNKNOWN")

    def test_32_expired_quota(self):
        self.f.quota.evidence = replace(self.f.quota.evidence, observed_at=800, expires_at=850)
        self.suspended("QUOTA_EXPIRED")

    def test_33_free_with_exact_conservative_reserve(self):
        self.f.quota.evidence = replace(self.f.quota.evidence,
            remaining=(("private_minutes", 15), ("storage_bytes", 2000)))
        r = self.f.backend.admit(self.f.pins, self.f.demand)
        self.assertEqual(r.status, "ADMITTED_SIMULATION", r)
        self.assertTrue(r.payload["receipt_present"])
        self.assertEqual(self.f.writer.calls, 0)

    def suspended(self, reason):
        before = dict(self.f.refs)
        r = self.f.backend.admit(self.f.pins, self.f.demand)
        self.assertEqual(r.status, "SUSPENDED_FREE_QUOTA", r)
        self.assertEqual(r.reason, reason)
        self.assertIs(r.pending, self.f.pins)
        self.assertFalse(r.summary()["durable_suspension"])
        self.assertEqual(before, self.f.refs)
        self.assertEqual(self.f.writer.calls, 0)
        return r

    def test_34_free_minutes_exhausted(self):
        self.f.quota.evidence = replace(self.f.quota.evidence,
            remaining=(("private_minutes", 0), ("storage_bytes", 10000)))
        self.suspended("QUOTA_RESERVE")

    def test_35_free_storage_exhausted(self):
        self.f.quota.evidence = replace(self.f.quota.evidence,
            remaining=(("private_minutes", 100), ("storage_bytes", 0)))
        self.suspended("QUOTA_RESERVE")

    def test_36_paid_usage_not_blocked(self):
        self.f.quota.evidence = replace(self.f.quota.evidence, paid_limit_cents=None)
        self.suspended("PAID_NOT_BLOCKED")

    def test_37_unknown_resource_quota(self):
        self.f.quota.evidence = replace(self.f.quota.evidence, remaining=(("private_minutes", 100),))
        self.suspended("QUOTA_UNKNOWN")

    def test_38_future_quota_timestamp(self):
        self.f.quota.evidence = replace(self.f.quota.evidence, observed_at=1001)
        self.suspended("QUOTA_EXPIRED")

    def test_39_safe_resume_same_request_and_receipts(self):
        saved = self.f.quota.evidence
        self.f.quota.evidence = None
        r = self.suspended("QUOTA_UNKNOWN")
        self.f.quota.evidence = saved
        for _ in range(2):
            resumed = self.f.backend.admit(r.pending, self.f.demand)
            self.assertEqual(resumed.status, "ADMITTED_SIMULATION", resumed)
            self.assertTrue(resumed.payload["receipt_present"])
        self.assertEqual(self.f.reg["counters"]["kolaji"], 1)
        self.assertEqual(len(self.f.reg["receipts"]), 1)
        self.assertEqual(self.f.writer.calls, 0)

    def test_40_resume_rechecks_current_authority(self):
        self.f.quota.evidence = None
        r = self.suspended("QUOTA_UNKNOWN")
        self.f.quota.evidence = gb.QuotaObservation(404, NOW, NOW+60, "Free",
            (("private_minutes",100),("storage_bytes",10000)),
            frozenset({"private_minutes","storage_bytes"}),0,False)
        self.f.refs[202, gb.MAIN] = self.f.commit(202, {}, self.f.authority)
        self.reject(self.f.backend.admit(r.pending, self.f.demand), "STALE_STATE")

    def test_41_single_ref_cas_replay_idempotence(self):
        for expected_status in ("APPLIED_SIMULATION", "ALREADY_APPLIED_SIMULATION"):
            r = self.f.backend.simulate_control_ff(self.f.pins, self.f.delivery,
                                                   self.f.target, self.f.demand)
            self.assertEqual(r.status, expected_status, r)
        self.assertEqual(self.f.writer.calls, 1)
        self.assertEqual(self.f.writer.mutations, 1)

    def test_42_cas_concurrent_advance(self):
        advanced = self.f.commit(303, {}, self.f.delivery, message="concurrent")
        self.f.writer.before = lambda: self.f.refs.__setitem__(
            (303, self.f.policy.delivery_ref), advanced)
        r = self.f.backend.simulate_control_ff(self.f.pins, self.f.delivery,
                                               self.f.target, self.f.demand)
        self.reject(r, "OUTCOME_UNKNOWN")
        self.assertEqual(self.f.writer.mutations, 0)
        self.assertEqual(self.f.refs[303, self.f.policy.delivery_ref], advanced)

    def test_43_unknown_write_outcome_then_observe(self):
        def lost():
            raise RuntimeError(SECRET)
        self.f.writer.after = lost
        self.reject(self.f.backend.simulate_control_ff(self.f.pins, self.f.delivery,
                    self.f.target, self.f.demand), "OUTCOME_UNKNOWN")
        r = self.f.backend.simulate_control_ff(self.f.pins, self.f.delivery,
                                               self.f.target, self.f.demand)
        self.assertEqual(r.status, "ALREADY_APPLIED_SIMULATION", r)
        self.assertEqual(self.f.writer.mutations, 1)

    def test_44_unsupported_native_atomic_and_upload(self):
        self.assertEqual(self.f.backend.atomic_authority_update().status, "UNSUPPORTED")
        self.assertEqual(self.f.backend.write_backup().status, "UNSUPPORTED")
        self.assertEqual(self.f.writer.calls, 0)

    def test_45_no_sequential_refs_or_unapproved_scope(self):
        self.reject(self.f.backend.simulate_control_ff(self.f.pins, self.f.delivery,
                    self.f.target, self.f.demand, ref=gb.MAIN), "REF_SCOPE")
        self.assertEqual(self.f.writer.calls, 0)

    def test_46_unproven_cas_capability(self):
        self.f.writer.caps = frozenset()
        self.reject(self.f.backend.simulate_control_ff(self.f.pins, self.f.delivery,
                    self.f.target, self.f.demand), "SINGLE_REF_CAS_UNSUPPORTED")

    def test_47_no_live_provider_mode(self):
        self.f.public.identity = replace(self.f.public.identity, mode="LIVE")
        self.reject(self.f.accepted(), "NO_OFFLINE_PORTS")
        self.assertEqual(gb.Backend().inspect(self.f.pins).status, "UNSUPPORTED")

    def test_48_diagnostics_do_not_leak(self):
        def fail(rid):
            raise RuntimeError("token=FAKE_TOKEN " + SECRET + self.f.pins.request_sha256)
        self.f.private.repository = fail
        a = self.f.accepted()
        b = gb.Result("SUSPENDED_FREE_QUOTA", "QUOTA_UNKNOWN", payload=RAW, pending=self.f.pins)
        report = json.dumps([a.summary(), b.summary()]) + repr(a) + repr(b)
        for value in (SECRET, "FAKE_TOKEN", self.f.pins.request_sha256, self.f.raw_pin.sha256):
            self.assertNotIn(value, report)

    def test_49_source_tree_membership_and_bytes(self):
        self.reject(self.f.backend.read_source(self.f.pins, "incoming/kolaji/new.png",
                    self.f.output_pin), "SOURCE_IDENTITY")
        self.reject(self.f.backend.inspect({"verified": True}), "BAD_PINS")

    def test_50_existing_receipts_freshness(self):
        self.reject(self.f.backend.inspect(replace(self.f.pins, receipts_sha256="0"*64)),
                    "RECEIPTS_IDENTITY")

    def test_51_private_recovery_only_private_port(self):
        p = gb.AssetPin("intake", 502, 602, digest(RAW), len(RAW))
        self.f.private.assets[101, 502, 602] = gb.AssetBytes(101, 502, 602, RAW)
        r = self.f.backend.recovery_bytes(self.f.pins, p, private=True)
        self.assertEqual(r.payload, RAW)
        self.reject(self.f.backend.public_preview(r.payload), "OUTPUT_CAPABILITY")
        self.reject(self.f.backend.recovery_bytes(self.f.pins, p), "ROLE_SCOPE")

    def test_52_backend_contains_no_connection_or_execution_api(self):
        tree = ast.parse(Path(gb.__file__).read_bytes())
        names = {a.name.split(".")[0] for n in ast.walk(tree)
                 if isinstance(n, ast.Import) for a in n.names}
        self.assertFalse(names & {"socket","subprocess","requests","http","urllib","os"})
        self.assertEqual(COUNTS, {"network_attempts":0, "process_attempts":0})


    def test_60_untrusted_result_diagnostics(self):
        r = gb.Result(SECRET, SECRET, RAW, self.f.pins)
        self.assertNotIn(SECRET, repr(r) + json.dumps(r.summary()))
        self.assertEqual(r.status, "REJECTED")
        self.assertEqual(r.reason, "PROVIDER_UNAVAILABLE")

    def test_61_verifier_code_object_pin(self):
        raw = self.f.raw(); key = self.f.derivation()
        old = self.f.objects[303, self.f.verifier_code]
        self.f.objects[303, self.f.verifier_code] = replace(old, raw=old.raw+b"tampered")
        self.reject(self.f.backend.verify_derivation(self.f.pins, raw, self.f.output_pin,
                                                    key, "original"), "OBJECT_IDENTITY")

    def test_62_existing_d2_schema_not_replaced(self):
        record = deepcopy(self.f.record); record["operation"] = "0"*64
        ledger = self.f.commit(303, {"anchor.json":data(record)}, self.f.ledger)
        self.f.refs[303, self.f.policy.ledger_ref] = ledger
        pins = replace(self.f.pins, ledger_tip=ledger, record_sha256=digest(data(record)))
        self.reject(self.f.backend.inspect(pins), "INDEPENDENT_EVIDENCE")

    def test_63_additional_free_resource_unknown_suspends(self):
        policy = replace(self.f.policy, reserves=self.f.policy.reserves+(("bandwidth_bytes",100),))
        backend = gb.Backend(policy, self.f.ports, clock=lambda:NOW)
        demand = dict(self.f.demand, bandwidth_bytes=10)
        r = backend.admit(self.f.pins, demand)
        self.assertEqual(r.status, "SUSPENDED_FREE_QUOTA", r)
        self.assertIn(r.reason, ("PAID_NOT_BLOCKED","QUOTA_UNKNOWN"))
        self.assertEqual(self.f.writer.calls, 0)

    def test_64_quota_provider_unavailable(self):
        def unavailable(account):
            raise RuntimeError(SECRET)
        self.f.quota.observation = unavailable
        r = self.suspended("QUOTA_UNKNOWN")
        self.assertNotIn(SECRET, repr(r) + json.dumps(r.summary()))

    def test_65_txt_invalid_utf8_rejects_mechanically(self):
        raw = bytes([255])
        pin = self.f.pin(101, raw)
        source = self.f.commit(101, {"incoming/kolaji/new.txt":raw}, self.f.parent,
                               message="invalid TXT request")
        self.f.refs[101, gb.MAIN] = source
        pins = replace(self.f.pins, source=source, request_sha256=digest(b"bad TXT request"))
        result = self.f.backend.read_source(pins, "incoming/kolaji/new.txt", pin)
        self.assertEqual(result.status, "PRIVATE_BYTES_SIMULATED", result)
        self.reject(self.f.backend.intentional_txt(pins, result.payload, "incoming/kolaji/new.txt"),
                    "TXT_STRUCTURE")


    def test_66_boolean_is_not_numeric_actor_identity(self):
        actors = tuple((k,1 if k=="private_read" else v) for k,v in self.f.policy.actors)
        policy = replace(self.f.policy, actors=actors)
        self.f.private.identity = replace(self.f.private.identity, actor_id=True)
        backend = gb.Backend(policy, self.f.ports, clock=lambda:NOW)
        self.reject(backend.inspect(self.f.pins), "ACTOR_SCOPE")

    def test_67_boolean_is_not_numeric_account_identity(self):
        policy = replace(self.f.policy, account_id=1)
        self.f.quota.evidence = replace(self.f.quota.evidence, account_id=True)
        backend = gb.Backend(policy, self.f.ports, clock=lambda:NOW)
        r = backend.admit(self.f.pins, self.f.demand)
        self.assertEqual((r.status,r.reason), ("SUSPENDED_FREE_QUOTA","QUOTA_UNKNOWN"))

    def test_68_grant_numeric_ids_are_strict(self):
        repos = tuple(replace(p,numeric_id=1) if p.role=="intake" else p
                      for p in self.f.policy.repos)
        policy = replace(self.f.policy, repos=repos)
        self.f.private.identity = replace(self.f.private.identity,
                                         grants=frozenset({(True,"read")}))
        backend = gb.Backend(policy, self.f.ports, clock=lambda:NOW)
        with self.assertRaisesRegex(gb.BoundaryError,"CREDENTIAL_SCOPE"):
            backend._session("private_read")


def quota_case(changes, reason):
    def test(self):
        self.f.quota.evidence = replace(self.f.quota.evidence, **changes)
        self.suspended(reason)
    return test


for n, changes, reason in [
    (53, {"overages_enabled":True}, "PAID_NOT_BLOCKED"),
    (54, {"paid_limit_cents":1}, "PAID_NOT_BLOCKED"),
    (55, {"paid_blocked_resources":frozenset({"private_minutes"})}, "PAID_NOT_BLOCKED"),
    (56, {"plan":"Pro"}, "PAID_NOT_BLOCKED"),
    (57, {"remaining":None}, "QUOTA_UNKNOWN"),
    (58, {"remaining":(("private_minutes",14),("storage_bytes",2000))}, "QUOTA_RESERVE"),
    (59, {"account_id":999}, "QUOTA_UNKNOWN")]:
    setattr(Tests, f"test_{n}_quota_policy", quota_case(changes, reason))


# E4L R2: focused tests of the actual native seam, NOT a real GitHub client.
# Existing fixture FUNCTIONS build genuine local D3 backups/acceptance. No old
# suite is loaded. Injected GraphQL responses remain clearly simulated/replayed.
NATIVE_ROWS = []


class NativeWriter:
    def __init__(self, template, public, mode="generic"):
        self.t, self.public, self.mode = template, public, mode
        self.binding = None
        self.calls = []
        self.override = None
        self.identity_change = None
        self.node = "R_SYNTHETIC_ASSETS_202"
        self.reads_after_write = 0
        self.original_ref = public.ref
        def ref(rid, name):
            if self.calls and rid == 202 and name in (gb.MAIN, gb.WITNESS):
                self.reads_after_write += 1
                if self.mode == "unavailable":
                    raise RuntimeError(SECRET)
                if self.mode == "inconsistent" and self.reads_after_write == 3:
                    return "e" * 40
                if self.override is not None:
                    return self.override[(gb.MAIN, gb.WITNESS).index(name)]
            return self.original_ref(rid, name)
        public.ref = ref

    def session(self):
        now = int(time.time())
        s = gb.SessionIdentity(15, self.t.code, frozenset({(202,"atomic_pair")}), now, now+60)
        return self.identity_change(s) if self.identity_change else s

    def node_id(self, rid):
        assert rid == 202
        return self.node

    def update_refs(self, query, variables):
        import authority_coordinator as d3
        self.calls.append(deepcopy((query, variables)))
        intent = self.binding._intents[-1]
        expected = {"input":{"repositoryId":"R_SYNTHETIC_ASSETS_202",
            "clientMutationId":digest(data([self.node,intent.before,intent.after])),
            "refUpdates":[{"name":ref,"beforeOid":old,"afterOid":new,"force":False}
                for ref,old,new in zip((gb.MAIN,gb.WITNESS),intent.before,intent.after)]}}
        assert variables == expected
        assert query == "mutation($input:UpdateRefsInput!){updateRefs(input:$input){clientMutationId}}"
        assert all(x != "0"*40 for x in (*intent.before,*intent.after))
        assert SECRET not in json.dumps(variables) and self.t.binding.owner_request_sha256 not in json.dumps(variables)
        client = variables["input"]["clientMutationId"]
        if self.mode in ("real_local_git","real_local_git_timeout_after"):
            # Real atomic file-transport push in the marked Lab, NOT GraphQL.
            from git_transport import git
            git(intent.repo,"push","--atomic",str(self.binding.scope[1]),
                intent.after[0]+":"+gb.MAIN,intent.after[1]+":"+gb.WITNESS)
        if self.mode in ("success","timeout_after","missing_after"):
            self.override = intent.after
        if self.mode == "partial": self.override = (intent.after[0],intent.before[1])
        if self.mode == "concurrent": self.override = ("f"*40,intent.before[1])
        if self.mode.startswith("timeout") or self.mode=="real_local_git_timeout_after":
            raise TimeoutError("token=FAKE_TOKEN " + SECRET)
        if self.mode in ("missing","missing_after"): return None
        if self.mode == "malformed": return gb.NativeReply(200,[SECRET])
        if self.mode == "http_error": return gb.NativeReply(503,{"error":SECRET})
        if self.mode in ("typed","unknown_typed"):
            # Recorded R3 refusal shape; unknown_typed deliberately changes type.
            return gb.NativeReply(200,{"data":{"updateRefs":None},"errors":[{
                "locations":[{"column":35,"line":1}],"message":"rejecting non-fast forward update",
                "path":["updateRefs"],"type":"UNPROCESSABLE" if self.mode=="typed" else "INTERNAL"}]})
        if self.mode in ("success","real_local_git","success_unchanged","partial","concurrent","inconsistent","unavailable"):
            return gb.NativeReply(200,{"data":{"updateRefs":{"clientMutationId":client}}})
        # Exact recorded R4 generic response body. It remains UNRESOLVED.
        return gb.NativeReply(200,{"errors":[{"message":"Something went wrong while executing your query on 2026-10-23T21:50:35Z. Please include `B808:23E9FB:1CC346D:5D3B390:6ADBD6AA` when reporting this issue."}]})


class NativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import test_d3_domain_adapter as helpers
        import authority_coordinator as d3
        cls.h = helpers
        helpers.WORK = WORK
        helpers.fixture.WORK = WORK
        helpers.fixture.initialize()
        cls.t = helpers.Template("e4l-native-pending")
        local,*_ = cls.t.ports()
        def stop(point):
            if point == "after-independent-acceptance": raise d3.Interrupted(point)
        result = cls.t.execute(local, interrupt=stop)
        assert result["status"] == "RECOVERABLE_INTERRUPTION", result
        cls.accepted = helpers.fixture.latest(cls.t.c)
        assert cls.accepted["index"] == 1
        # The genuine accepted candidate is durable only in this LOCAL Lab.
        assert helpers.fixture.fingerprint(cls.t.c)[0] != cls.accepted["primary_main"]

    def connect(self, mode="generic", template=None):
        import authority_coordinator as d3
        t = template or self.t
        legacy,private,public,verifier,quota = t.ports()
        backend = legacy.backend
        writer = NativeWriter(t, public, mode)
        backend.native = gb.NativeConfig(backend.repos["assets"],writer.node,15,writer)
        ports = d3.trusted_local_ports(self.h.fixture.LAB,**t.c,backend=backend,
            binding=t.binding,demand={"private_minutes":5,"storage_bytes":1000},mode="LOCAL_NATIVE_TEST")
        writer.binding = ports
        return ports,writer,private,public,verifier,quota

    def invoke(self, ports):
        import authority_coordinator as d3
        outcomes = []
        actual = ports.backend.atomic_authority_update
        def recording(*args, **kwargs):
            r = actual(*args, **kwargs)
            outcomes.append(r)
            return r
        with patch.object(ports.backend,"atomic_authority_update",recording):
            try:
                ports.reconcile(self.h.fixture.domain(self.t.c), self.t.c["primary"])
            except d3.PortStop:
                pass
        self.assertTrue(ports._intents)
        self.assertEqual(len(outcomes),1)
        original = next(iter(ports.backend._native_attempts.values()), ports._intents[-1])
        calls = len(ports.backend.native.port.calls)
        replay = actual(original,dict(ports.demand))
        self.assertEqual(len(ports.backend.native.port.calls),calls)
        self.assertIs(replay.pending,original)
        return outcomes[0], original

    def test_native_01_actual_D3_to_GraphQL_pair(self):
        ports,w,*_ = self.connect("success")
        result,intent = self.invoke(ports)
        self.assertEqual(result.status,"ATOMIC_APPLIED_INACTIVE",result)
        self.assertEqual(len(w.calls),1)
        self.assertIs(result.pending,intent)
        self.assertEqual(intent.after[1],self.accepted["primary_witness"])
        self.assertEqual(intent.record_sha256,digest(data(self.accepted)))
        self.assertGreater(w.reads_after_write,0)
        self.assertFalse(result.summary()["live_activation"])

    def test_native_02_real_coordinator_acceptance_and_recovery(self):
        t=self.h.Template("e4l-real-coordinator")
        ports,w,*_=self.connect("real_local_git",t)
        result=t.execute(ports)
        self.assertEqual(result["status"],"REQUEST_VERIFIED_FINAL",result)
        self.assertGreater(len(w.calls),0)
        latest=self.h.fixture.latest(t.c)
        self.assertTrue(self.h.fixture.domain(t.c).read()["latest"]==latest)
        main,witness,_=self.h.fixture.fingerprint(t.c)
        self.assertEqual(witness,latest["primary_witness"])
        from git_transport import git
        self.assertEqual(git(t.c["primary"],"merge-base","--is-ancestor",latest["primary_main"],main,allow=True).returncode,0)
        self.assertTrue(result["projection_eligible"])
        self.assertFalse(result["live_activation"])

    def test_native_03_unknown_then_resume_same_D3_acceptance(self):
        import authority_coordinator as d3
        t=self.h.Template("e4l-interrupted-native")
        ports,w,*_=self.connect("generic",t)
        result=t.execute(ports)
        self.assertEqual(result["status"],"UNRESOLVED",result)
        self.assertEqual(len(w.calls),1)
        self.assertFalse(result["projection_eligible"])
        original=next(iter(ports.backend._native_attempts.values()))
        # Fresh Coordinator on same local backend: no second mutation, even if
        # repair preparation generates another commit OID.
        second=t.execute(ports)
        self.assertEqual(second["status"],"UNRESOLVED",second)
        self.assertEqual(len(w.calls),1)
        self.assertIs(next(iter(ports.backend._native_attempts.values())),original)
        self.assertEqual(self.h.fixture.latest(t.c)["index"],1)

    def test_native_04_forged_intent_and_verified_flag(self):
        ports,w,*_=self.connect()
        bad=ports.backend.atomic_authority_update({"verified":True},dict(ports.demand))
        self.assertEqual((bad.status,bad.reason),("REJECTED","NATIVE_INTENT"))
        self.assertIsNone(bad.pending)
        _,intent=self.invoke(ports)
        forged=replace(intent)
        result=ports.backend.atomic_authority_update(forged,dict(ports.demand))
        self.assertEqual(result.status,"UNRESOLVED")
        self.assertEqual(len(w.calls),1)

    def test_native_05_missing_independent_backup_no_write(self):
        import authority_coordinator as d3
        ports,w,*_=self.connect()
        domain=self.h.fixture.domain(self.t.c)
        with patch.object(d3.LocalWitness,"read",side_effect=d3.Reject("LATEST_BACKUP_MISSING")):
            with self.assertRaisesRegex(d3.Reject,"LATEST_BACKUP_MISSING"):
                ports.reconcile(domain,self.t.c["primary"])
        self.assertEqual(len(w.calls),0)

    def test_native_06_old_local_and_provider_guards(self):
        import authority_coordinator as d3
        legacy,*_=self.t.ports(mode="PROVIDER_REQUIRED")
        with self.assertRaisesRegex(d3.PortStop,"NATIVE_ATOMIC_UNSUPPORTED"):
            legacy.validate(*legacy.scope_args())
        self.assertEqual(gb.Backend().atomic_authority_update().status,"UNSUPPORTED")
        old,*_=self.t.ports()
        self.assertEqual(old.mode,"LOCAL_LAB")

    def test_native_07_independent_state_changes_before_send(self):
        import authority_coordinator as d3
        ports,w,*_=self.connect()
        original=d3.verify_native_intent
        def changed(intent,backend):
            raise d3.Reject("STALE_INDEPENDENT_ACCEPTANCE")
        with patch.object(d3,"verify_native_intent",changed):
            with self.assertRaisesRegex(d3.Reject,"STALE_INDEPENDENT_ACCEPTANCE"):
                ports.reconcile(self.h.fixture.domain(self.t.c),self.t.c["primary"])
        self.assertEqual(len(w.calls),0)

    def test_native_09_wrong_repository_role_and_numeric_id(self):
        import authority_coordinator as d3
        for repository in (gb.RepoPin("control",202,*gb.NAMES["assets"]),
                           gb.RepoPin("assets",999,*gb.NAMES["assets"])):
            ports,w,*_=self.connect()
            ports.backend.native=replace(ports.backend.native,repository=repository)
            # New trusted setup still cannot authorize the wrong public role.
            ports=replace(ports,_native_config=ports.backend.native)
            w.binding=ports
            with self.assertRaises(d3.PortStop):
                ports.reconcile(self.h.fixture.domain(self.t.c),self.t.c["primary"])
            self.assertEqual(len(w.calls),0)

    def test_native_10_forbidden_targets_and_zero_oids(self):
        ports,w,*_=self.connect()
        _,intent=self.invoke(ports)
        for bad in (replace(intent,before=("0"*40,intent.before[1])),
                    replace(intent,after=(intent.after[0],"0"*40)),
                    replace(intent,after=(intent.after[0],"f"*40))):
            result=ports.backend.atomic_authority_update(bad,dict(ports.demand))
            self.assertNotIn(result.status,("ATOMIC_APPLIED_INACTIVE","ATOMIC_OBSERVED_INACTIVE"))
        self.assertEqual(len(w.calls),1)
        self.assertEqual({x["name"] for x in w.calls[0][1]["input"]["refUpdates"]},{gb.MAIN,gb.WITNESS})

    def test_native_08_secrets_and_pending_are_not_diagnostics(self):
        ports,w,*_=self.connect("timeout_before")
        result,intent=self.invoke(ports)
        rendered=repr(result)+repr(intent)+json.dumps(result.summary())
        for private in (SECRET,"FAKE_TOKEN",self.t.binding.owner_request_sha256,str(intent.repo)):
            self.assertNotIn(private,rendered)
        self.assertFalse(result.summary()["durable_suspension"])
        self.assertEqual(len(w.calls),1)



    def test_native_11_genuine_witness_only_timeout_readback(self):
        import authority_coordinator as d3
        from git_transport import git, value
        t=self.h.Template("e4l-witness-only")
        local,*_=t.ports()
        def stop(point):
            if point=="after-independent-acceptance": raise d3.Interrupted(point)
        interrupted=t.execute(local,interrupt=stop)
        self.assertEqual(interrupted["status"],"RECOVERABLE_INTERRUPTION")
        context=self.h.fixture.domain(t.c).read();accepted=context["latest"]
        # Synthetic local condition: main already accepted, witness still old.
        # Never touch an owner checkout or a remote GitHub ref.
        git(t.c["primary"],"fetch",str(context["recovered"]),accepted["primary_main"])
        git(t.c["primary"],"update-ref",gb.MAIN,accepted["primary_main"])
        before=self.h.fixture.fingerprint(t.c)
        ports,w,*_=self.connect("real_local_git_timeout_after",t)
        result=ports.reconcile(self.h.fixture.domain(t.c),t.c["primary"])
        self.assertTrue(result["witness_completed"])
        self.assertEqual(len(w.calls),1)
        updates=w.calls[0][1]["input"]["refUpdates"]
        self.assertEqual(updates[0]["beforeOid"],updates[0]["afterOid"])
        self.assertNotEqual(updates[1]["beforeOid"],updates[1]["afterOid"])
        self.assertEqual(self.h.fixture.fingerprint(t.c),
            (before[0],accepted["primary_witness"],before[2]))
        intent=next(iter(ports.backend._native_attempts.values()))
        observed=ports.backend.atomic_authority_update(intent,dict(ports.demand))
        self.assertEqual(observed.status,"ATOMIC_OBSERVED_INACTIVE")
        self.assertEqual(len(w.calls),1)

    def test_native_12_arbitrary_publisher_rejected(self):
        import authority_coordinator as d3
        from types import SimpleNamespace
        called=[]
        with self.assertRaisesRegex(d3.Reject,"UNTRUSTED_NATIVE_PUBLISHER"):
            self.h.fixture.domain(self.t.c).reconcile(self.t.c["primary"],
                publisher=SimpleNamespace(publish_pair=lambda *a,**k:called.append(1)))
        self.assertEqual(called,[])

    def test_native_13_caller_cannot_reduce_pinned_quota_demand(self):
        ports,w,*_=self.connect()
        _,intent=self.invoke(ports)
        result=ports.backend.atomic_authority_update(intent,{k:0 for k,v in ports.demand})
        self.assertEqual((result.status,result.reason),("SUSPENDED_FREE_QUOTA","QUOTA_UNKNOWN"))
        self.assertIs(result.pending,intent)
        self.assertEqual(len(w.calls),1)

    def test_native_14_concurrent_client_calls_one_attempt(self):
        import authority_coordinator as d3
        from concurrent.futures import ThreadPoolExecutor
        ports,w,*_=self.connect("success")
        with patch.object(ports.backend,"atomic_authority_update",
                          return_value=gb.Result("UNRESOLVED","OUTCOME_UNKNOWN")):
            with self.assertRaises(d3.PortStop):
                ports.reconcile(self.h.fixture.domain(self.t.c),self.t.c["primary"])
        intent=ports._intents[-1]
        self.assertEqual(len(w.calls),0)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(lambda _:ports.backend.atomic_authority_update(intent,dict(ports.demand)),range(2)))
        self.assertEqual(sorted(r.status for r in results),
                         ["ATOMIC_APPLIED_INACTIVE","ATOMIC_OBSERVED_INACTIVE"])
        self.assertEqual(len(w.calls),1)
        self.assertTrue(all(r.pending is intent for r in results))

    def test_native_15_stale_expected_pair_before_send(self):
        import authority_coordinator as d3
        ports,w,private,public,verifier,quota=self.connect()
        original=public.ref
        public.ref=lambda rid,ref: "f"*40 if rid==202 and ref==gb.MAIN else original(rid,ref)
        with self.assertRaisesRegex(d3.PortStop,"REF_CONFLICT"):
            ports.reconcile(self.h.fixture.domain(self.t.c),self.t.c["primary"])
        self.assertEqual(len(w.calls),0)
        self.assertEqual(ports.backend._native_attempts,{})


def native_response_case(mode, expected):
    def test(self):
        ports,w,*_=self.connect(mode)
        result,intent=self.invoke(ports)
        self.assertEqual(result.status,expected,result)
        self.assertIs(result.pending,intent)
        self.assertEqual(len(w.calls),1)
        if mode == "typed": self.assertEqual(result.reason,"REF_CONFLICT")
        self.assertGreater(w.reads_after_write,0)
        NATIVE_ROWS.append({"mode":mode,"status":result.status,"mutation_attempts":len(w.calls),
                            "provider":"SIMULATED_OR_REPLAYED_RESPONSE_NOT_LIVE"})
    return test


for mode, expected in [("typed","REJECTED"),("generic","UNRESOLVED"),
    ("unknown_typed","UNRESOLVED"),("missing","UNRESOLVED"),("malformed","UNRESOLVED"),
    ("http_error","UNRESOLVED"),("timeout_before","UNRESOLVED"),
    ("timeout_after","ATOMIC_OBSERVED_INACTIVE"),("missing_after","ATOMIC_OBSERVED_INACTIVE"),
    ("success_unchanged","UNRESOLVED"),("partial","UNRESOLVED"),("concurrent","UNRESOLVED"),
    ("inconsistent","UNRESOLVED"),("unavailable","UNRESOLVED")]:
    setattr(NativeTests,"test_native_response_"+mode,native_response_case(mode,expected))


def native_identity_case(change):
    def test(self):
        ports,w,private,public,verifier,quota=self.connect()
        change(ports,w,quota)
        import authority_coordinator as d3
        try: ports.reconcile(self.h.fixture.domain(self.t.c),self.t.c["primary"])
        except (d3.PortStop,d3.Reject): pass
        self.assertEqual(len(w.calls),0)
    return test


for label, change in [
    ("node",lambda p,w,q:setattr(w,"node","R_WRONG_SYNTHETIC_NODE")),
    ("actor",lambda p,w,q:setattr(w,"identity_change",lambda s:replace(s,actor_id=11))),
    ("extra_grant",lambda p,w,q:setattr(w,"identity_change",lambda s:replace(s,grants=s.grants|{(123,"read")}))),
    ("live",lambda p,w,q:setattr(w,"identity_change",lambda s:replace(s,mode="LIVE"))),
    ("stale_session",lambda p,w,q:setattr(w,"identity_change",lambda s:replace(s,observed_at=0,expires_at=1))),
    ("quota",lambda p,w,q:setattr(q,"exhausted",True))]:
    setattr(NativeTests,"test_native_identity_"+label,native_identity_case(change))


# E4L R3: private fixture input is not a report or recovery authority. Children
# use fresh interpreters/backends and actual D3 state; os._exit is real process
# termination. No live GitHub response or cloud durability is proved.
RESTART_ROWS=[]


def restart_input(template):
    b=asdict(template.binding);b["derived_repo"]=str(template.binding.derived_repo)
    q=dict(template.q);q["source"]=str(q["source"]);q["evidence"]=asdict(q["evidence"])
    return {"work":str(WORK),"lab":str(template.c["primary"].parents[2]),
        "c":{k:str(v) if isinstance(v,Path) else v for k,v in template.c.items()},
        "raw_repo":str(template.raw_repo),"code":template.code,"verifier_code":template.verifier_code,
        "binding":b,"policy":asdict(template.policy),"q":q,
        "proofs":{k:asdict(v[0]) for k,v in template.proofs.items()}}


def restore_restart_input(payload):
    import test_d3_domain_adapter as h
    import authority_coordinator as d3
    import intake_plan
    from git_transport import Lab,git
    h.WORK=Path(payload["work"]);h.fixture.WORK=h.WORK
    # The fixed Lab root is derived from the parent run, not a remote URL.
    h.fixture.LAB=Lab(h.WORK/"lab")
    t=object.__new__(h.Template);t.cache={};t.proofs={}
    t.c={k:Path(v) if k in ("primary","anchor","archives") else v for k,v in payload["c"].items()}
    t.raw_repo=Path(payload["raw_repo"]);h.fixture.LAB.remote(t.raw_repo)
    t.code=payload["code"];t.verifier_code=payload["verifier_code"]
    b=dict(payload["binding"]);b["derived_repo"]=Path(b["derived_repo"])
    b["files"]=tuple(d3.DerivedFile(**(f|{"raw":gb.ObjectPin(**f["raw"]),"output":gb.ObjectPin(**f["output"])})) for f in b["files"])
    t.binding=d3.SourceBinding(**b)
    policy=dict(payload["policy"])
    policy["repos"]=tuple(gb.RepoPin(**x) for x in policy["repos"])
    policy["actors"]=tuple(tuple(x) for x in policy["actors"])
    policy["reserves"]=tuple(tuple(x) for x in policy["reserves"])
    t.policy=gb.Policy(**policy)
    t.q=dict(payload["q"]);t.q["source"]=Path(t.q["source"])
    t.q["evidence"]=intake_plan.SourceEvidence(**t.q["evidence"])
    for key,record in payload["proofs"].items():
        r=dict(record);r["raw"]=gb.ObjectPin(**r["raw"]);r["output"]=gb.ObjectPin(**r["output"])
        record=gb.Derivation(**r)
        raw=git(t.raw_repo,"cat-file","blob",record.raw.oid).stdout
        output=git(t.raw_repo,"cat-file","blob",record.output.oid).stdout
        t.proofs[key]=(record,raw,output)
    return t,h


class RestartWriter(NativeWriter):
    def __init__(self,t,public,mode,counter):
        self.terminate_after_apply=mode=="apply_crash"
        super().__init__(t,public,"real_local_git" if mode in ("apply_crash","success") else "generic")
        self.counter=counter
    def update_refs(self,query,variables):
        import os
        # Diagnostic count, never an input to the production recovery decision.
        intent=self.binding._intents[-1]
        with self.counter.open("ab") as f:
            f.write(data({"record":intent.record_sha256})+b"\n");f.flush();os.fsync(f.fileno())
        reply=super().update_refs(query,variables)
        if self.terminate_after_apply:os._exit(81)
        return reply


def durable_ports(t,h,mode="generic",initialize=False,counter=None):
    import authority_coordinator as d3
    legacy,private,public,verifier,quota=t.ports()
    writer=RestartWriter(t,public,mode,counter or t.c["primary"].parent/"private-transport-count.jsonl")
    backend=legacy.backend
    backend.native=gb.NativeConfig(backend.repos["assets"],writer.node,15,writer)
    p=d3.trusted_local_ports(h.fixture.LAB,**t.c,backend=backend,binding=t.binding,
        demand={"private_minutes":5,"storage_bytes":1000},mode="LOCAL_NATIVE_TEST",
        durable=True,initialize_checkpoint=initialize)
    writer.binding=p
    return p,writer


def restart_worker(args):
    import os
    import test_d3_domain_adapter as h
    import authority_coordinator as d3
    global WORK
    WORK=Path(args.work);h.WORK=WORK
    original=subprocess.run
    with patch.object(socket,"socket",no_network),patch.object(socket,"create_connection",no_network), \
         patch.object(urllib.request,"urlopen",no_network),patch.object(subprocess,"run",h.checked_run(original)):
        try:
            assert args.restart_worker.absolute().is_relative_to(WORK/"lab")
            payload=json.loads(args.restart_worker.read_text(encoding="utf-8"))
            with (args.restart_worker.parent/"process-starts.jsonl").open("ab") as f:
                f.write(data({"pid":os.getpid(),"stage":args.worker_stage})+b"\n");f.flush();os.fsync(f.fileno())
            t,h=restore_restart_input(payload)
            p,w=durable_ports(t,h,args.worker_mode)
            stops={"after-independent-acceptance":77,"native-intent-durable":78,
                   "native-before-mutation":79,"native-result-durable":80}
            def hit(point):
                if point==args.worker_stage:os._exit(stops[point])
            if args.readback_only:
                domain=h.fixture.domain(t.c);domain.hit=hit
                result=p.reconcile(domain,t.c["primary"])
                answer={"status":"OBSERVED_ACCEPTED","whole_request_verified":False,
                        "publication_authorized":False,"calls":len(w.calls)}
            else:
                result=t.execute(p,interrupt=hit)
                answer={k:result.get(k) for k in ("status","reason","whole_request_verified","projection_eligible")}
                answer.update(publication_authorized=False,calls=len(w.calls))
        except Exception as exc:
            answer={"status":"UNRESOLVED","reason":exc.code if isinstance(exc,d3.PortStop) else "PRIVATE_RECOVERY_STOP",
                    "whole_request_verified":False,"publication_authorized":False,"calls":0}
        answer["pid"]=os.getpid();answer["network_attempts"]=COUNTS["network_attempts"]
        answer["nonlocal_git_attempts"]=h.COUNTS["nonlocal_git_attempts"]
        print(json.dumps(answer),flush=True)
    return 0


def checked_restart_run(original):
    import test_d3_domain_adapter as h
    guarded=h.checked_run(original)
    def run(command,*args,**kwargs):
        worker=(isinstance(command,list) and len(command)>6 and command[:3]==[sys.executable,"-B",str(Path(__file__))] and
                ("--restart-worker" in command or "--private-worker" in command or "--private-cloud-fixture" in command) and "--work" in command)
        if worker:
            flag="--private-cloud-fixture" if "--private-cloud-fixture" in command else ("--private-worker" if "--private-worker" in command else "--restart-worker")
            source=Path(command[command.index(flag)+1]).absolute()
            assert source.is_relative_to(WORK/"lab") and Path(command[command.index("--work")+1])==WORK
            return original(command,*args,**kwargs)
        return guarded(command,*args,**kwargs)
    return run


class RestartTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import test_d3_domain_adapter as h
        cls.h=h;h.WORK=WORK;h.fixture.WORK=WORK;h.fixture.initialize()
    def new(self,label):
        t=self.h.Template("r3-"+label)
        durable_ports(t,self.h,initialize=True)
        path=t.c["primary"].parent/"PRIVATE-synthetic-worker-input.json"
        path.write_bytes(data(restart_input(t)))
        return t,path
    def child(self,path,stage="none",mode="generic",readback=False,expected_exit=0):
        cmd=[sys.executable,"-B",str(Path(__file__)),"--work",str(WORK),
             "--restart-worker",str(path),"--worker-stage",stage,"--worker-mode",mode]
        if readback:cmd.append("--readback-only")
        pidfile=path.parent/"process-starts.jsonl"
        before=len(pidfile.read_text().splitlines()) if pidfile.exists() else 0
        r=subprocess.run(cmd,capture_output=True,timeout=600)
        self.assertEqual(r.returncode,expected_exit,"isolated child unexpected exit")
        starts=[json.loads(x) for x in pidfile.read_text().splitlines()]
        self.assertEqual(len(starts),before+1)
        if expected_exit:
            self.assertFalse(r.stdout.strip());return {"terminated_exit":r.returncode,"pid":starts[-1]["pid"]}
        self.assertFalse(r.stderr.strip(),"worker diagnostics must remain redacted")
        answer=json.loads(r.stdout)
        self.assertEqual(answer["network_attempts"],0);self.assertEqual(answer["nonlocal_git_attempts"],0)
        self.assertFalse(answer["publication_authorized"])
        return answer
    def calls(self,t):
        p=t.c["primary"].parent/"private-transport-count.jsonl"
        return [json.loads(s)["record"] for s in p.read_text().splitlines()] if p.exists() else []
    def root(self,t):return self.h.fixture.LAB.root/"private-native-intents"/t.binding.owner_request_sha256
    def row(self,t):
        paths=list(self.root(t).glob("*.intent.json"));self.assertEqual(len(paths),1);return paths[0]
    def record(self,label,t,first,second):
        calls=self.calls(t)
        self.assertNotEqual(first["pid"],second["pid"])
        self.assertTrue(all(calls.count(k)==1 for k in set(calls)),"no operation may be resent")
        RESTART_ROWS.append({"case":label,"first":first,"restart":second,
            "mutation_attempts":len(calls),"max_attempts_per_accepted_operation":max([calls.count(k) for k in calls] or [0]),
            "provider":"LOCAL_GIT_APPLY_AND_INJECTED_GRAPHQL_ONLY"})

    def test_restart_security_untrusted_finalizer(self):
        import authority_coordinator as d3
        from types import SimpleNamespace
        f=Fixture();callbacks=[];writes=[]
        session=gb.SessionIdentity(15,f.code,frozenset({(202,"atomic_pair")}),NOW,NOW+60)
        port=SimpleNamespace(session=lambda:session,node_id=lambda rid:"R_SYNTHETIC_ASSETS_202",
                             update_refs=lambda *args:writes.append(args))
        f.backend.native=gb.NativeConfig(f.backend.repos["assets"],"R_SYNTHETIC_ASSETS_202",15,port)
        untrusted=SimpleNamespace(complete_native_attempt=lambda r:callbacks.append(r.status))
        intent=d3.NativeIntent((f.authority,f.witness),(f.authority,f.witness),f.ledger,
            digest(data(f.record)),digest(b"synthetic owner request"),Path("."),untrusted,None,object())
        result=f.backend.atomic_authority_update(intent,f.demand)
        self.assertEqual(result.status,"UNRESOLVED")
        self.assertEqual(callbacks,[]);self.assertEqual(writes,[])

    def test_restart_A_before_mutation(self):
        t,p=self.new("before")
        first=self.child(p,"native-intent-durable",expected_exit=78)
        row=self.row(t).read_bytes()
        second=self.child(p,readback=True)
        self.assertEqual(second["status"],"UNRESOLVED");self.assertEqual(len(self.calls(t)),0)
        self.assertEqual(self.row(t).read_bytes(),row)
        self.record("A/I authorized not sent: conservative STOP after restart",t,first,second)

    def test_restart_B_after_acceptance_before_intent(self):
        t,p=self.new("accepted")
        first=self.child(p,"after-independent-acceptance",expected_exit=77)
        accepted=self.h.fixture.latest(t.c)
        second=self.child(p,readback=True)
        self.assertEqual(second["status"],"UNRESOLVED");self.assertEqual(len(self.calls(t)),0)
        self.assertEqual(self.h.fixture.latest(t.c),accepted)
        self.record("B accepted prefix, missing exact intent: STOP",t,first,second)

    def test_restart_C_applied_before_result_H_exact_pair(self):
        t,p=self.new("applied")
        first=self.child(p,mode="apply_crash",expected_exit=81)
        row=self.row(t).read_bytes();before=self.h.fixture.fingerprint(t.c)
        second=self.child(p,readback=True)
        self.assertEqual(second["status"],"OBSERVED_ACCEPTED");self.assertEqual(len(self.calls(t)),1)
        self.assertEqual(self.h.fixture.fingerprint(t.c),before)
        self.assertEqual(self.row(t).read_bytes(),row)
        self.record("C/H applied then process exit, exact pair reconciled",t,first,second)

    def test_restart_D_unknown_I_unchanged(self):
        t,p=self.new("unknown")
        first=self.child(p,"native-result-durable",expected_exit=80)
        second=self.child(p,readback=True)
        self.assertEqual(second["status"],"UNRESOLVED");self.assertEqual(len(self.calls(t)),1)
        self.record("D/I recorded unknown, unchanged does not prove rejection",t,first,second)

    def test_restart_E_stale_witness_J_conflict(self):
        from git_transport import git,value
        t,p=self.new("conflict")
        first=self.child(p,"native-before-mutation",expected_exit=79)
        old=value(t.c["primary"],"rev-parse",gb.WITNESS)
        tree=value(t.c["primary"],"rev-parse",old+"^{tree}")
        new=value(t.c["primary"],"commit-tree",tree,"-p",old,"-m","synthetic concurrent witness")
        git(t.c["primary"],"update-ref",gb.WITNESS,new)
        before=self.h.fixture.fingerprint(t.c)
        second=self.child(p,readback=True)
        self.assertEqual(second["status"],"UNRESOLVED");self.assertEqual(len(self.calls(t)),0)
        self.assertEqual(self.h.fixture.fingerprint(t.c),before)
        self.record("E/J forward-advanced witness conflict",t,first,second)

    def test_restart_F_duplicate_whole_request(self):
        t,p=self.new("duplicate")
        first=self.child(p,mode="success")
        self.assertEqual(first["status"],"REQUEST_VERIFIED_FINAL");self.assertTrue(first["whole_request_verified"])
        before=self.h.fixture.fingerprint(t.c);calls=len(self.calls(t))
        second=self.child(p,mode="success")
        self.assertEqual(second["status"],"REQUEST_VERIFIED_FINAL");self.assertTrue(second["whole_request_verified"])
        self.assertNotEqual(first["pid"],second["pid"])
        self.assertEqual(self.h.fixture.fingerprint(t.c),before);self.assertEqual(len(self.calls(t)),calls)
        self.record("F fresh process duplicate request, no new IDs/revisions/acceptance",t,first,second)

    def test_restart_G_corrupt_and_missing_evidence(self):
        t,p=self.new("corrupt")
        first=self.child(p,"native-intent-durable",expected_exit=78)
        row=self.row(t);original=row.read_bytes()
        (row.with_name(row.name+".preserved-original")).write_bytes(original)
        row.write_bytes(original+b"corruption")
        second=self.child(p,readback=True)
        self.assertEqual(second["status"],"UNRESOLVED");self.assertEqual(len(self.calls(t)),0)
        # Preserve the malformed file; no cleanup or automatic repair.
        self.record("G corrupt exact intent",t,first,second)
        root=self.root(t);identity=root/"identity.json"
        identity.rename(root/"identity.json.preserved-missing-case")
        third=self.child(p,readback=True)
        self.assertEqual(third["status"],"UNRESOLVED");self.assertEqual(len(self.calls(t)),0)
        self.record("G missing checkpoint identity",t,second,third)

    def test_restart_E_stale_authority(self):
        t,p=self.new("stale-authority")
        first=self.child(p,"native-before-mutation",expected_exit=79)
        # Existing genuine D3 local adapter simulates a separately accepted
        # forward advancement; no new authority algorithm or forged record.
        local,*_=t.ports();result=t.execute(local)
        self.assertEqual(result["status"],"REQUEST_VERIFIED_FINAL")
        before=self.h.fixture.fingerprint(t.c)
        second=self.child(p,readback=True)
        self.assertEqual(second["status"],"UNRESOLVED");self.assertEqual(len(self.calls(t)),0)
        self.assertEqual(self.h.fixture.fingerprint(t.c),before)
        self.record("E stale independent acceptance, no adoption",t,first,second)



# E4M fake provider: actual in-memory Git hashes, atomic lock; NEVER GitHub proof.
PRIVATE_ROWS=[]
class RecoveryProvider:
    def __init__(self,rid=101,code=None):
        from threading import RLock
        self.f=Fixture();self.rid=rid;self.code=code or self.f.code
        self.pin=gb.RepoPin('intake',rid,*gb.NAMES['intake']);self.node='R_PRIVATE_SYNTHETIC_101'
        self.actor=31;self.writable=True;self.mode='success';self.calls=0;self.lock=RLock();self.rows={}
        files={gb.RECOVERY_MARKER:data({'format':'bgzona-private-recovery-r1','repository':rid})}
        self.tip=self.store(files,[])
    def store(self,files,parents):
        head=self.f.commit(self.rid,files,parents[0] if parents else None)
        tree=self.f.objects[self.rid,head].raw.splitlines()[0][5:].decode()
        self.rows[head]={'head':head,'parents':parents,'tree':tree,'files':dict(files)}
        return head
    def repository(self,rid):assert rid==self.rid;return self.pin
    def node_id(self,rid):assert rid==self.rid;return self.node
    def session(self):
        now=int(time.time());return gb.SessionIdentity(self.actor,self.code,
            frozenset({(self.rid,'contents:write' if self.writable else 'contents:read')}),now,now+60)
    def head(self,rid,ref):assert rid==self.rid and ref==gb.RECOVERY_REF;return self.tip
    def snapshot(self,rid,head):
        assert rid==self.rid
        row=deepcopy(self.rows[head])
        if self.mode=='corrupt_read':row['files'][gb.RECOVERY_MARKER]+=b'corrupt'
        return row
    def create_commit(self,query,variables):
        import base64
        with self.lock:
            self.calls+=1
            assert self.writable
            assert query=='mutation($input:CreateCommitOnBranchInput!){createCommitOnBranch(input:$input){commit{oid}}}'
            i=variables['input'];assert set(i)=={'branch','expectedHeadOid','message','fileChanges'}
            if (set(i['branch'])!={'repositoryNameWithOwner','branchName'} or
                i['branch']['repositoryNameWithOwner']!=gb.NAMES['intake'][0] or
                i['branch']['branchName']!='automation-recovery' or self.mode=='schema_rejected'):
                return gb.NativeReply(200,{'errors':[{'message':'Synthetic schema refusal '+SECRET}]})
            assert set(i['fileChanges'])=={'additions'} and len(i['fileChanges']['additions'])==1
            if self.mode=='unknown_before':raise TimeoutError(SECRET)
            if self.tip!=i['expectedHeadOid']:
                return gb.NativeReply(200,{'errors':[{'message':'untyped conflict'}]})
            file=i['fileChanges']['additions'][0];assert set(file)=={'path','contents'}
            files=self.rows[self.tip]['files']|{file['path']:base64.b64decode(file['contents'],validate=True)}
            self.tip=self.store(files,[self.tip])
            if self.mode=='unknown_after':raise TimeoutError(SECRET)
            return gb.NativeReply(200,{'data':{'createCommitOnBranch':{'commit':{'oid':self.tip}}}})
    def client(self,writable=True,head=None):
        return gb.PrivateRecovery(self.pin,self.node,self.actor,self.code,self,
            expected_head=head or self.tip,writable=writable)


class PrivateTests(unittest.TestCase):
    def setUp(self):self.provider=RecoveryProvider();self.request=digest(b'owner');self.record=digest(b'record');self.packet=b'PRIVATE_SYNTHETIC_PACKET'
    def test_private_persist_tree_readback(self):
        c=self.provider.client();old=self.provider.tip;c.persist(self.request,self.record,self.packet)
        self.assertNotEqual(c.expected_head,old);self.assertEqual(c.read()['parents'],[old])
        self.assertEqual(c.read()['tree'],gb.recovery_tree(c.read()['files']))
    def test_private_stale_HEAD(self):
        c=self.provider.client();self.provider.tip=self.provider.store(self.provider.rows[self.provider.tip]['files'],[self.provider.tip])
        with self.assertRaises(gb.RecoveryStop):c.persist(self.request,self.record,self.packet)
        self.assertEqual(self.provider.calls,0)
    def test_private_claim_one_winner(self):
        from concurrent.futures import ThreadPoolExecutor
        c=self.provider.client();c.persist(self.request,self.record,self.packet)
        clients=[self.provider.client(),self.provider.client()]
        def run(client):
            try:client.claim(self.request,self.record,digest(self.packet));return 'WIN'
            except gb.RecoveryStop:return 'STOP'
        with ThreadPoolExecutor(2) as pool:results=list(pool.map(run,clients))
        self.assertEqual(sorted(results),['STOP','WIN'])
        self.assertEqual(sum(bool(x._claims) for x in clients),1)
    def test_private_unknown_never_retry_or_claim(self):
        for mode in ('unknown_before','unknown_after'):
            p=RecoveryProvider();c=p.client();p.mode=mode
            with self.assertRaisesRegex(gb.RecoveryStop,'RECOVERY_UNKNOWN'):c.persist(self.request,self.record,self.packet)
            with self.assertRaises(gb.RecoveryStop):c.persist(self.request,self.record,self.packet)
            self.assertEqual(p.calls,1);self.assertFalse(c._claims)
    def test_private_missing_bootstrap(self):
        c=self.provider.client();self.provider.tip=None
        with self.assertRaisesRegex(gb.RecoveryStop,'BOOTSTRAP_REQUIRED'):c.read()
        self.assertEqual(self.provider.calls,0)
    def test_private_missing_checkpoint(self):
        c=self.provider.client()
        with self.assertRaisesRegex(gb.RecoveryStop,'RECOVERY_MISSING'):c.retrieve(self.request,self.record)
    def test_private_corrupt_readback(self):
        c=self.provider.client();self.provider.mode='corrupt_read'
        with self.assertRaises(gb.RecoveryStop):c.read()
    def test_private_readonly_no_write(self):
        self.provider.writable=False;c=self.provider.client(False)
        with self.assertRaises(gb.RecoveryStop):c.persist(self.request,self.record,self.packet)
        self.assertEqual(self.provider.calls,0)
    def test_private_forbidden_target_and_permissions(self):
        p=self.provider
        for pin,ref in ((replace(p.pin,visibility='public'),gb.RECOVERY_REF),
                        (replace(p.pin,name='malin-bg/bgzona-assets'),gb.RECOVERY_REF),(p.pin,gb.MAIN)):
            with self.assertRaises(gb.RecoveryStop):gb.PrivateRecovery(pin,p.node,p.actor,p.code,p,expected_head=p.tip,writable=True,ref=ref)
        with self.assertRaises(gb.RecoveryStop):p.client(False)
        self.assertEqual(p.calls,0)
    def test_private_claim_loss_and_no_secret_errors(self):
        c=self.provider.client();c.persist(self.request,self.record,self.packet);self.provider.mode='unknown_after'
        with self.assertRaises(gb.RecoveryStop) as e:c.claim(self.request,self.record,digest(self.packet))
        self.assertNotIn(SECRET,str(e.exception));self.assertFalse(c._claims)
        self.assertIn('claim.json',' '.join(c.read()['files']))



    def http_transport(self):
        import base64
        from types import SimpleNamespace
        provider=self.provider;requests=[];headers={};broken={'value':False}
        def open_request(request,timeout):
            self.assertEqual(timeout,30);self.assertTrue(request.full_url.startswith('https://api.github.com/'))
            self.assertEqual(request.get_header('X-github-api-version'),'2026-03-10')
            self.assertEqual(request.get_header('Authorization'),'Bearer SYNTHETIC_CREDENTIAL_NOT_REAL')
            requests.append((request.get_method(),request.full_url))
            path=request.full_url.removeprefix('https://api.github.com');prefix='/repos/'+provider.pin.name
            if path==prefix:row={'id':provider.rid,'full_name':provider.pin.name,'visibility':'private','private':True,'node_id':provider.node}
            elif path==prefix+'/git/ref/heads/automation-recovery':row={'ref':gb.RECOVERY_REF,'object':{'type':'commit','sha':provider.tip}}
            elif '/git/commits/' in path:
                commit=provider.rows[path.rsplit('/',1)[1]];row={'sha':commit['head'],'tree':{'sha':commit['tree']},'parents':[{'sha':x} for x in commit['parents']]}
            elif '/git/trees/' in path:
                tree=path.rsplit('/',1)[1].split('?')[0];commit=next(x for x in provider.rows.values() if x['tree']==tree)
                entries=[]
                for name,raw in commit['files'].items():entries.append({'path':name,'mode':'100644','type':'blob','sha':provider.f.obj(provider.rid,'blob',raw),'size':len(raw)})
                row={'sha':tree,'truncated':False,'tree':entries}
            elif '/git/blobs/' in path:
                oid=path.rsplit('/',1)[1];raw=provider.f.objects[provider.rid,oid].raw
                row={'sha':oid,'encoding':'base64','size':len(raw),'content':base64.b64encode(raw+(b'bad' if broken['value'] else b'')).decode()}
            elif path=='/graphql':
                query=json.loads(request.data);reply=provider.create_commit(query['query'],query['variables']);row=reply.body
            else:raise AssertionError('unexpected request')
            class Response:
                status=200
                def __enter__(self):return self
                def __exit__(self,*a):pass
                def read(self,limit):return data(row)[:limit]
            result=Response();result.headers=headers;return result
        port=gb.PrivateRecoveryHTTP(provider.pin,provider.actor,provider.code,'SYNTHETIC_CREDENTIAL_NOT_REAL',writable=True)
        return port,SimpleNamespace(open=open_request),requests,headers,broken

    def test_private_HTTP_full_transport_intercepted(self):
        port,opener,requests,headers,broken=self.http_transport()
        root=self.provider.tip
        with patch.object(urllib.request,'build_opener',return_value=opener), \
             patch.object(self.provider,'create_commit',wraps=self.provider.create_commit) as create:
            c=gb.PrivateRecovery(self.provider.pin,self.provider.node,self.provider.actor,self.provider.code,port,expected_head=root,writable=True)
            checkpoint=c.persist(self.request,self.record,self.packet)
            c.claim(self.request,self.record,digest(self.packet))
            claim=self.provider.tip
            self.assertEqual(c.expected_head,claim)
            self.assertNotIn(claim,(root,checkpoint))
            self.assertEqual(c.read(claim)['parents'],[checkpoint])
            self.assertEqual(self.provider.rows[checkpoint]['parents'],[root])
            self.assertEqual(c.retrieve(self.request,self.record),self.packet)
            inputs=[call.args[1]['input'] for call in create.call_args_list]
            self.assertEqual([i['expectedHeadOid'] for i in inputs],[root,checkpoint])
            self.assertEqual([i['branch'] for i in inputs],
                             [{'repositoryNameWithOwner':self.provider.pin.name,'branchName':'automation-recovery'}]*2)
            self.assertEqual([i['fileChanges']['additions'][0]['path'].rsplit('/',1)[1] for i in inputs],
                             ['checkpoint.json','claim.json'])
        self.assertEqual(sum(method=='POST' for method,url in requests),2)
        self.assertTrue(all(url.endswith('/graphql') for method,url in requests if method=='POST'))
    def test_private_HTTP_rejects_old_branch_shape(self):
        port,opener,requests,headers,broken=self.http_transport()
        query='mutation($input:CreateCommitOnBranchInput!){createCommitOnBranch(input:$input){commit{oid}}}'
        i={'branch':{'repositoryNameWithOwner':self.provider.pin.name,'refName':gb.RECOVERY_REF},
           'expectedHeadOid':self.provider.tip,'message':{'headline':'PRIVATE recovery checkpoint'},
           'fileChanges':{'additions':[{'path':f'private-recovery/{self.request}/{self.record}/checkpoint.json',
                                        'contents':'AA=='}]}}
        with patch.object(urllib.request,'build_opener',return_value=opener):
            with self.assertRaisesRegex(gb.RecoveryStop,'RECOVERY_SCOPE'):
                port.create_commit(query,{'input':i})
        self.assertEqual(requests,[])
        self.assertEqual(set(self.provider.create_commit(query,{'input':i}).body),{'errors'})

    def test_private_HTTP_schema_refusal_stops(self):
        port,opener,requests,headers,broken=self.http_transport()
        root=self.provider.tip;self.provider.mode='schema_rejected'
        with patch.object(urllib.request,'build_opener',return_value=opener):
            c=gb.PrivateRecovery(self.provider.pin,self.provider.node,self.provider.actor,self.provider.code,port,expected_head=root,writable=True)
            with self.assertRaisesRegex(gb.RecoveryStop,'^RECOVERY_UNKNOWN$'):
                c.persist(self.request,self.record,self.packet)
            self.assertEqual(c._phase,'GRAPHQL_CHECKPOINT')
            with self.assertRaisesRegex(gb.RecoveryStop,'RECOVERY_CLAIMED'):
                c.persist(self.request,self.record,self.packet)
        self.assertEqual(self.provider.tip,root)
        self.assertEqual(c.expected_head,root)
        self.assertEqual(self.provider.calls,1)
        self.assertFalse(c._claims)

    def test_private_HTTP_forbidden_endpoint_no_io(self):
        port,opener,requests,headers,broken=self.http_transport()
        with patch.object(urllib.request,'build_opener',return_value=opener):
            for path,body in (('/repos/malin-bg/bgzona-assets',None),('/graphql',{'query':'mutation{deleteRef}', 'variables':{}})):
                with self.assertRaises(gb.RecoveryStop):port._request(path,body)
        self.assertEqual(requests,[])
    def test_private_HTTP_deprecation_and_corruption_STOP(self):
        port,opener,requests,headers,broken=self.http_transport()
        with patch.object(urllib.request,'build_opener',return_value=opener):
            headers['Deprecation']='true'
            with self.assertRaises(gb.RecoveryStop):port.repository(self.provider.rid)
            self.assertFalse(port._compatible)
            headers.clear();port._compatible=True;broken['value']=True
            with self.assertRaises(gb.RecoveryStop):port.snapshot(self.provider.rid,self.provider.tip)
        self.assertEqual(self.provider.calls,0)
    def test_private_two_driver_processes_actual_exit(self):
        import os
        parent=WORK/'lab';parent.mkdir(exist_ok=True)
        state=parent/'PRIVATE-provider-state.json';output=parent/'PRIVATE-job-outputs.txt'
        pids=[]
        for stage in ('producer','recovery'):
            spec={'stage':stage,'state':str(state),'output':str(output),'root':str(parent/(stage+'-job'))}
            path=parent/('PRIVATE-'+stage+'.json');path.write_bytes(data(spec))
            cmd=[sys.executable,'-B',str(Path(__file__)),'--work',str(WORK),'--private-cloud-fixture',str(path)]
            result=subprocess.run(cmd,capture_output=True,timeout=600)
            self.assertEqual(result.returncode,86 if stage=='producer' else 0,'isolated actual-driver outcome')
            self.assertFalse(result.stderr.strip(),'driver diagnostics must remain redacted')
            row=json.loads(result.stdout);pids.append(row['pid']);self.assertNotEqual(row['pid'],os.getpid())
            if stage=='producer':self.assertEqual(row['authority_mutations'],0)
            else:self.assertEqual(row['native_calls'],0);self.assertTrue(row['recovered']);self.assertTrue(row['original_pair_preserved'])
            PRIVATE_ROWS.append({'case':'actual-driver-'+stage,'exit':result.returncode,**row})
        self.assertNotEqual(*pids)

    def test_private_provider_exception_redaction(self):
        with patch.object(self.provider,'session',side_effect=RuntimeError(SECRET)):
            with self.assertRaises(gb.RecoveryStop) as e:self.provider.client()
        self.assertNotIn(SECRET,str(e.exception))


def private_restore_worker(args):
    """Fresh interpreter, NEW Lab. No old absolute paths in packet or profile."""
    import os
    from types import SimpleNamespace
    import authority_coordinator as d3
    import test_d3_domain_adapter as h
    from git_transport import Lab,git,value
    global WORK
    WORK=Path(args.work);h.WORK=WORK;original=subprocess.run
    spec=json.loads(args.private_worker.read_bytes());new_root=WORK/'lab'/('independent-'+spec['case'])
    guarded=h.checked_run(original)
    def restricted(command,*a,**kw):
        assert command[0]=='git' and Path(command[command.index('-C')+1]).absolute().is_relative_to(new_root)
        return guarded(command,*a,**kw)
    with patch.object(socket,'socket',no_network),patch.object(socket,'create_connection',no_network), \
         patch.object(urllib.request,'urlopen',no_network),patch.object(subprocess,'run',restricted):
        lab=Lab.create(new_root);t=SimpleNamespace(code=spec['policy']['code_oid'],verifier_code=spec['policy']['verifier_code_oid'])
        t.c={k:lab.root/'private-portable'/(k+'.git') for k in ('primary','anchor')};t.raw_repo=lab.root/'RAW_NOT_INCLUDED'
        p=dict(spec['policy']);p['repos']=tuple(gb.RepoPin(**v) for v in p['repos']);p['actors']=tuple(tuple(v) for v in p['actors']);p['reserves']=tuple(tuple(v) for v in p['reserves'])
        policy=gb.Policy(**p);private,public=h.Reader(t,True,11),h.Reader(t,False,12)
        b=gb.Backend(policy,gb.OfflinePorts(private,public,h.Verifier(t),h.NoWriter(t),h.Quota()))
        writer=NativeWriter(t,public,'generic');b.native=gb.NativeConfig(b.repos['assets'],writer.node,15,writer)
        binding=dict(spec['binding']);binding['derived_repo']=lab.root/'private-portable/derived.git'
        binding['files']=tuple(d3.DerivedFile(**(f|{'raw':gb.ObjectPin(**f['raw']),'output':gb.ObjectPin(**f['output'])})) for f in binding['files'])
        result={'pid':os.getpid(),'status':'UNRESOLVED','native_calls':0,'whole_request_verified':False,'publication_authorized':False}
        try:
            packet=args.private_worker.with_suffix('.packet').read_bytes()
            ports,intent=d3.portable_native_restore(packet,lab,expected=spec['expected'],backend=b,binding=d3.SourceBinding(**binding),demand={'private_minutes':5,'storage_bytes':1000})
            writer.binding=ports
            if spec.get('applied'):
                # Local, forward-only synthetic apply, NOT a GraphQL mutation.
                primary=ports.scope[1]
                git(primary,'fetch',str(intent.repo),gb.MAIN,gb.WITNESS)
                git(primary,'update-ref',gb.MAIN,intent.after[0],intent.before[0])
                git(primary,'update-ref',gb.WITNESS,intent.after[1],intent.before[1])
            observed=b.atomic_authority_update(intent,dict(ports.demand))
            result.update(status=observed.status,original_pair_preserved=list(intent.before)==spec['before'] and list(intent.after)==spec['after'],recovered=intent.recovered)
        except Exception as e:
            result['reason']=e.code if isinstance(e,gb.RecoveryStop) else 'PORTABLE_STOP'
        result.update(native_calls=len(writer.calls),network_attempts=COUNTS['network_attempts'],nonlocal_git_attempts=h.COUNTS['nonlocal_git_attempts'])
        if getattr(args,'capture',False):return result
        print(json.dumps(result),flush=True)
    return 0


class PortableTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import authority_coordinator as d3
        import test_d3_domain_adapter as h
        from dataclasses import replace
        cls.h=h;h.WORK=WORK;h.fixture.WORK=WORK;h.fixture.initialize()
        cls.t=h.Template('e4m-producer');cls.provider=RecoveryProvider(123,cls.t.code)
        p,cls.writer=durable_ports(cls.t,h,initialize=True)
        cls.recovery=cls.provider.client();cls.ports=replace(p,_private_recovery=cls.recovery);cls.writer.binding=cls.ports
        cls.outcome=cls.t.execute(cls.ports)
        assert cls.outcome['status']=='UNRESOLVED'
        assert len(cls.writer.calls)==1,'native mutation must follow verified PRIVATE checkpoint and exclusive claim'
        cls.intent=cls.ports._intents[-1]
        cls.packet=cls.recovery.retrieve(cls.intent.request_sha256,cls.intent.record_sha256)
        # These are independently retained fixture profile pins. They are NOT
        # adopted from an untrusted package on restore.
        cls.expected=d3.portable_native_trust(cls.ports,cls.intent.record_sha256,cls.intent.ledger_tip,before=cls.intent.before,after=cls.intent.after)
        assert cls.provider.calls==2
    def worker(self,case,packet=None,expected=None,applied=False):
        import os
        from dataclasses import asdict
        binding=asdict(self.t.binding);binding.pop('derived_repo')
        spec={'case':case,'binding':binding,'policy':asdict(self.t.policy),'expected':expected or self.expected,
              'before':list(self.intent.before),'after':list(self.intent.after),'applied':applied}
        path=WORK/'lab'/('PRIVATE-worker-'+case+'.json');path.write_bytes(data(spec));path.with_suffix('.packet').write_bytes(packet or self.packet)
        self.assertNotIn(str(self.t.c['primary'].parent).encode(),path.read_bytes()+path.with_suffix('.packet').read_bytes())
        cmd=[sys.executable,'-B',str(Path(__file__)),'--work',str(WORK),'--private-worker',str(path)]
        proc=subprocess.run(cmd,capture_output=True,timeout=600)
        self.assertEqual(proc.returncode,0,'isolated portable worker failed');self.assertFalse(proc.stderr.strip(),'worker must not leak provider/private diagnostics')
        result=json.loads(proc.stdout);self.assertNotEqual(result['pid'],os.getpid())
        self.assertEqual(result['native_calls'],0);self.assertEqual(result['network_attempts'],0);self.assertEqual(result['nonlocal_git_attempts'],0)
        self.assertFalse(result['publication_authorized']);PRIVATE_ROWS.append({'case':case,**result});return result
    def test_portable_unknown_new_runner_no_duplicate(self):
        r=self.worker('unknown');self.assertEqual(r['status'],'UNRESOLVED');self.assertTrue(r['recovered']);self.assertTrue(r['original_pair_preserved'])
    def test_portable_exact_pair_after_local_apply(self):
        r=self.worker('applied',applied=True);self.assertEqual(r['status'],'ATOMIC_OBSERVED_INACTIVE');self.assertTrue(r['original_pair_preserved'])
    def test_portable_corrupt_objects_STOP(self):
        payload=json.loads(self.packet);payload['repos']['prepared']['pack']+='corrupt'
        self.assertEqual(self.worker('corrupt',data(payload))['status'],'UNRESOLVED')
    def test_portable_no_independent_acceptance_STOP(self):
        wrong=self.expected|{'record':'f'*64};self.assertEqual(self.worker('wrong-acceptance',expected=wrong)['status'],'UNRESOLVED')




def private_cloud_probe(args):
    from types import SimpleNamespace
    diagnostic=SimpleNamespace(phase='INITIALIZATION',client=None)
    try:
        return _private_cloud_probe(args,diagnostic)
    except Exception as exc:
        phase=diagnostic.phase
        if phase=='RECOVERY_WRITE':
            phase=diagnostic.client._phase
        code=gb.RecoveryStop(exc.code).code if type(exc) is gb.RecoveryStop else 'PROBE_ERROR'
        print(json.dumps({'status':'PRIVATE_RECOVERY_STOP','phase':phase,'code':code}),flush=True)
        return 1


def _private_cloud_probe(args,diagnostic):
    """Future owner-gated SYNTHETIC probe only. No public mutation port exists."""
    import os,base64
    import authority_coordinator as d3
    import test_d3_domain_adapter as h
    from types import SimpleNamespace
    from dataclasses import asdict
    from PIL import __version__ as pillow_version
    global WORK
    required=lambda name:os.environ[name]
    assert required('GITHUB_ACTIONS')=='true' and required('GITHUB_REPOSITORY')==gb.NAMES['intake'][0]
    assert sys.version_info[:3]==(3,12,14) and pillow_version=='12.3.0'
    source=required('BGZONA_REVIEWED_SOURCE_SHA');assert gb.oid(source)
    rid=int(required('GITHUB_REPOSITORY_ID'));actor=int(required('GITHUB_ACTOR_ID'))
    pin=gb.RepoPin('intake',rid,*gb.NAMES['intake'])
    port=gb.PrivateRecoveryHTTP(pin,actor,source,required('GITHUB_TOKEN'),writable=args.private_cloud=='producer')
    client=gb.PrivateRecovery(pin,required('BGZONA_PRIVATE_NODE_ID'),actor,source,port,
        expected_head=required('BGZONA_RECOVERY_HEAD'),writable=args.private_cloud=='producer')
    WORK=external(args.work);assert not WORK.exists();WORK.mkdir(parents=True);h.WORK=WORK
    if args.private_cloud=='producer':
        diagnostic.phase='SYNTHETIC_D3_INTENT'
        # Only genuine local synthetic D3 writes below. GitHub writes can reach
        # ONLY the designated PRIVATE checkpoint ref through the narrow client.
        original=subprocess.run
        with patch.object(subprocess,'run',h.checked_run(original)):
            h.fixture.WORK=WORK;h.fixture.initialize();t=h.Template('e4m-cloud-synthetic')
            p,writer=durable_ports(t,h,initialize=True)
            def stop(point):
                if point=='native-intent-durable':raise d3.Interrupted(point)
            outcome=t.execute(p,interrupt=stop)
            assert outcome['status']=='RECOVERABLE_INTERRUPTION' and len(writer.calls)==0
            intent=p._intents[-1];p.reserve_native_attempt(intent)
            packet,expected=d3.portable_native_export(intent,p.backend)
            binding=asdict(t.binding);binding.pop('derived_repo')
            spec={'case':'cloud','binding':binding,'policy':asdict(t.policy),'expected':expected,
                  'before':list(intent.before),'after':list(intent.after),'applied':False}
        # Storage and exclusive claim precede the simulated uncertain I/O window.
        envelope=data({'format':'bgzona-synthetic-driver-r1','packet':base64.b64encode(packet).decode(),'profile':spec})
        diagnostic.client=client;diagnostic.phase="RECOVERY_WRITE"
        client.persist(intent.request_sha256,intent.record_sha256,envelope)
        client.claim(intent.request_sha256,intent.record_sha256,digest(envelope))
        client.verify_claim(intent.request_sha256,intent.record_sha256,digest(envelope))
        diagnostic.phase='OUTPUTS'
        with Path(required('GITHUB_OUTPUT')).open('a',encoding='utf-8') as output:
            output.write('recovery_head='+client.expected_head+'\n')
            output.write('profile_sha='+digest(data(spec))+'\n')
            output.write('request='+intent.request_sha256+'\n')
            output.write('record='+intent.record_sha256+'\n')
        # Intentional real process termination; never send an authority mutation.
        print(json.dumps({'status':'PRIVATE_CHECKPOINT_VERIFIED_SIMULATED_UNKNOWN','phase':'CONTROLLED_EXIT_86','bytes':len(packet),'authority_mutations':0,'pid':os.getpid()}),flush=True)
        os._exit(86)
    else:
        diagnostic.phase='RECOVERY_READBACK'
        request=required('BGZONA_RECOVERY_REQUEST');record=required('BGZONA_RECOVERY_RECORD')
        envelope=client.retrieve(request,record);row=json.loads(envelope)
        assert set(row)=={'format','packet','profile'} and row['format']=='bgzona-synthetic-driver-r1' and data(row)==envelope
        spec=row['profile'];assert digest(data(spec))==required('BGZONA_TRUSTED_PROFILE_SHA')
        assert spec['expected']['source'][0]==request and spec['expected']['record']==record
        packet=base64.b64decode(row['packet'],validate=True)
        (WORK/'lab').mkdir();path=WORK/'lab/PRIVATE-cloud-profile.json';path.write_bytes(data(spec));path.with_suffix('.packet').write_bytes(packet)
        # The expected profile is from the reviewed producer JOB output, not
        # adopted from the mutable recovery branch. Synthetic D3 domain only.
        result=private_restore_worker(SimpleNamespace(work=WORK,private_worker=path,capture=True))
        assert result.get('recovered') is True and result.get('original_pair_preserved') is True and result['status']=='UNRESOLVED' and result['native_calls']==0
        print(json.dumps(result),flush=True);return 0



def private_cloud_fixture_worker(args):
    """Offline execution of the ACTUAL hosted driver with an intercepted port.

    Only synthetic provider state is persisted for the second process; no live
    token, account, GitHub request or original producer filesystem is consumed.
    """
    import base64,os
    from types import SimpleNamespace
    spec=json.loads(args.private_cloud_fixture.read_bytes())
    provider=RecoveryProvider(123,'1'*40)
    if spec['stage']=='recovery':
        state=json.loads(Path(spec['state']).read_bytes());provider.tip=state['tip']
        provider.rows={k:(v|{'files':{name:base64.b64decode(raw) for name,raw in v['files'].items()}}) for k,v in state['rows'].items()}
    original=provider.create_commit
    def create(query,variables):
        reply=original(query,variables)
        state={'tip':provider.tip,'rows':{k:(v|{'files':{name:base64.b64encode(raw).decode() for name,raw in v['files'].items()}}) for k,v in provider.rows.items()}}
        Path(spec['state']).write_bytes(data(state));return reply
    provider.create_commit=create
    def port(pin,actor,code,token,*,writable=False):
        assert pin==provider.pin and actor==provider.actor and code==provider.code
        provider.writable=writable;return provider
    env={'GITHUB_ACTIONS':'true','GITHUB_REPOSITORY':gb.NAMES['intake'][0],
        'GITHUB_REPOSITORY_ID':'123','GITHUB_ACTOR_ID':str(provider.actor),
        'BGZONA_REVIEWED_SOURCE_SHA':'1'*40,'GITHUB_TOKEN':'SYNTHETIC_CREDENTIAL_NOT_REAL',
        'BGZONA_PRIVATE_NODE_ID':provider.node,'BGZONA_RECOVERY_HEAD':provider.tip,
        'GITHUB_OUTPUT':spec['output']}
    if spec['stage']=='recovery':
        outputs=dict(line.split('=',1) for line in Path(spec['output']).read_text().splitlines())
        env['BGZONA_RECOVERY_HEAD']=outputs['recovery_head'];env['BGZONA_TRUSTED_PROFILE_SHA']=outputs['profile_sha']
        env['BGZONA_RECOVERY_REQUEST']=outputs['request'];env['BGZONA_RECOVERY_RECORD']=outputs['record']
    with patch.dict(os.environ,env),patch.object(gb,'PrivateRecoveryHTTP',side_effect=port), \
         patch.object(socket,'socket',no_network),patch.object(socket,'create_connection',no_network),patch.object(urllib.request,'urlopen',no_network):
        return private_cloud_probe(SimpleNamespace(work=Path(spec['root']),private_cloud=spec['stage']))


class Recorder(unittest.TextTestResult):
    def addSuccess(self, test):
        super().addSuccess(test); ROWS.append({"test":test.id(),"status":"PASS"})
    def addFailure(self, test, err):
        super().addFailure(test, err); ROWS.append({"test":test.id(),"status":"FAIL",
                                                   "traceback":self._exc_info_to_string(err,test)})
    def addError(self, test, err):
        super().addError(test, err); ROWS.append({"test":test.id(),"status":"ERROR",
                                                "traceback":self._exc_info_to_string(err,test)})


def main():
    global WORK
    parser=argparse.ArgumentParser();parser.add_argument("--work",type=Path,required=True)
    parser.add_argument("--native",action="store_true")
    parser.add_argument("--private",action="store_true")
    parser.add_argument("--private-worker",type=Path)
    parser.add_argument("--private-cloud",choices=("producer","recovery"))
    parser.add_argument("--private-cloud-fixture",type=Path)
    parser.add_argument("--durable",action="store_true")
    parser.add_argument("--restart-worker",type=Path)
    parser.add_argument("--worker-stage",default="none")
    parser.add_argument("--worker-mode",default="generic")
    parser.add_argument("--readback-only",action="store_true")
    parser.add_argument("--only")
    args=parser.parse_args()
    if args.restart_worker:return restart_worker(args)
    if args.private_worker:return private_restore_worker(args)
    if args.private_cloud_fixture:return private_cloud_fixture_worker(args)
    if args.private_cloud:return private_cloud_probe(args)
    WORK=external(args.work)
    if WORK.exists():
        raise RuntimeError("NEW_EXTERNAL_WORK_REQUIRED")
    WORK.mkdir(parents=True)
    started=time.perf_counter()
    source={n:digest((Path(__file__).parent/n).read_bytes()) for n in
            ("github_backend.py","test_github_backend.py","authority_coordinator.py")}
    # Guard actual egress and process/Git APIs while all tests execute.
    with (WORK/"tests.log").open("w",encoding="utf8") as log:
        if args.native or args.durable or args.private:
            import test_d3_domain_adapter as helpers
            helpers.WORK = WORK
            original = subprocess.run
            suite = unittest.TestSuite(list(unittest.defaultTestLoader.loadTestsFromTestCase(PortableTests))+list(unittest.defaultTestLoader.loadTestsFromTestCase(PrivateTests))) if args.private else unittest.defaultTestLoader.loadTestsFromTestCase(RestartTests if args.durable else NativeTests)
            if args.only:
                suite = unittest.TestSuite(t for t in suite if any(n in t.id() for n in args.only.split(",")))
            with patch.object(socket,"socket",no_network), \
                 patch.object(socket,"create_connection",no_network), \
                 patch.object(subprocess,"run",checked_restart_run(original) if (args.durable or args.private) else helpers.checked_run(original)), \
                 patch.object(urllib.request,"urlopen",no_network):
                result=unittest.TextTestRunner(stream=log,verbosity=2,resultclass=Recorder).run(suite)
        else:
            with patch.object(socket,"socket",no_network), \
                 patch.object(socket,"create_connection",no_network), \
                 patch.object(subprocess,"run",no_process), \
                 patch.object(subprocess,"Popen",no_process), \
                 patch.object(urllib.request,"urlopen",no_network):
                result=unittest.TextTestRunner(stream=log,verbosity=2,resultclass=Recorder).run(
                    unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
    summary={"tests":result.testsRun,"pass":result.testsRun-len(result.failures)-len(result.errors),
             "fail":len(result.failures),"errors":len(result.errors),
             "seconds":time.perf_counter()-started,"source_sha256":source,
             "provider":"OFFLINE_TEST_DOUBLE","hosted_runs":0,"real_provider_writes":0,
             "network_attempts":COUNTS["network_attempts"],"process_attempts":COUNTS["process_attempts"],
             "real_atomicity_verified":False,"durable_suspension_verified":False,
             "real_sanitization_tested":False,"d3_restore_tested":False}
    if args.native or args.durable or args.private:
        summary.update(genuine_local_D3=True, native_responses="SIMULATED_OR_REPLAYED_NOT_LIVE",
            nonlocal_git_attempts=helpers.COUNTS["nonlocal_git_attempts"],
            fake_cas_calls=helpers.COUNTS["fake_cas_calls"],old_suites_run=0,
            process_counter_scope="blocked process APIs only; genuine Lab Git subprocesses ARE used")
        (WORK/"native-responses.json").write_bytes(data(NATIVE_ROWS))
        if args.private:
            (WORK/"private-recovery-cases.json").write_bytes(data(PRIVATE_ROWS))
            summary.update(private_recovery_integration=True,cloud_recovery_proven=False)
        if args.durable:
            summary.update(real_child_process_termination=True,private_checkpoint_only=True,cloud_durability=False,
                private_intent_restart_tested=True,d3_restore_tested=True,
                interruption_scope="actual os._exit; not power loss or runner disk loss")
            (WORK/"restart-cases.json").write_bytes(data(RESTART_ROWS))
    (WORK/"results.json").write_bytes(data(ROWS))
    (WORK/"summary.json").write_bytes(data(summary))
    print(json.dumps(summary))
    return 0 if result.wasSuccessful() else 1


if __name__=="__main__":
    sys.exit(main())

