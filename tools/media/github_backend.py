"""E4H OFFLINE provider boundary. NO HTTP/Git client, credentials or activation.

Injected ports are trusted I/O boundaries, NOT data supplied by an owner request.
Native two-ref requests are reachable only through sealed LOCAL D3 intent
and an injected offline transport; no built-in HTTP client or live mode. No real
provider capability is proved here. No multi-ref REST atomicity, WORM claim,
D2 acceptance, allocation, sanitizer, queue or coordinator is implemented.

StatePins must come from independently trusted D3/current-state resolution.
Pinned record/schema/object checks below do NOT replace D3 chain/restore checks.
No caller-supplied verified/publication flag is accepted. Production numeric
repository/actor pins are deliberately absent; future setup must establish them.
"""
from dataclasses import dataclass, field, asdict
from functools import wraps
from hashlib import sha1
from types import SimpleNamespace
from typing import Protocol
import re
import time
from threading import RLock

from importer import Store, data, parse, digest, text
from intake_plan import _path
from git_transport import MAIN, WITNESS
from authority_coordinator import LocalWitness, NativeIntent, verify_native_intent, native_intent_binding

NAMES = {"intake": ("malin-bg/bgzona-private-intake", "private"),
         "assets": ("malin-bg/bgzona-assets", "public"),
         "control": ("malin-bg/bgzona-github-lab", "public")}
CODES = frozenset("""NO_OFFLINE_PORTS BAD_POLICY BAD_PINS REPOSITORY_IDENTITY
ROLE_SCOPE CREDENTIAL_SCOPE ACTOR_SCOPE CODE_IDENTITY STALE_SESSION
STALE_STATE OBJECT_IDENTITY OBJECT_TYPE OBJECT_LIMIT INVALID_COMMIT
INVALID_TREE PATH_NOT_FOUND INVALID_ANCESTRY ANCESTRY_LIMIT
AUTHORITY_IDENTITY INDEPENDENT_EVIDENCE REGISTRY_IDENTITY WITNESS_IDENTITY
RECEIPTS_IDENTITY SOURCE_IDENTITY DERIVATION_IDENTITY PRIVACY_EVIDENCE
RAW_TO_PUBLIC OUTPUT_CAPABILITY QUOTA_UNKNOWN QUOTA_EXPIRED PAID_NOT_BLOCKED
QUOTA_RESERVE PROVIDER_UNAVAILABLE NATIVE_ATOMIC_UNSUPPORTED
BACKUP_WRITE_UNSUPPORTED SINGLE_REF_CAS_UNSUPPORTED REF_SCOPE
REF_CONFLICT NON_FAST_FORWARD OUTCOME_UNKNOWN BACKUP_IDENTITY
RECOVERY_BYTES TXT_STRUCTURE NATIVE_INTENT NATIVE_IDENTITY NATIVE_RESPONSE""".split())


class BoundaryError(Exception):
    def __init__(self, code, status="REJECTED"):
        # Even a malicious provider exception cannot inject private diagnostic text.
        self.code = code if code in CODES else "PROVIDER_UNAVAILABLE"
        self.status = status if status in ("REJECTED", "UNSUPPORTED", "UNRESOLVED",
                                           "SUSPENDED_FREE_QUOTA") else "REJECTED"
        super().__init__(self.code)


def need(ok, code, status="REJECTED"):
    if not ok:
        raise BoundaryError(code, status)


def oid(value):
    return type(value) is str and re.fullmatch("[0-9a-f]{40}", value) is not None


def sha(value):
    return type(value) is str and re.fullmatch("[0-9a-f]{64}", value) is not None


def positive(value):
    return type(value) is int and value > 0


@dataclass(frozen=True)
class RepoPin:
    role: str
    numeric_id: int
    name: str
    visibility: str


@dataclass(frozen=True, repr=False)
class Policy:
    repos: tuple[RepoPin, ...]
    actors: tuple[tuple[str, int], ...]
    code_oid: str
    verifier_code_oid: str
    library_id: str
    account_id: int
    reserves: tuple[tuple[str, int], ...]
    ttl: int = 60
    code_ref: str = "refs/heads/automation-control"
    ledger_ref: str = "refs/heads/automation-ledger"
    delivery_ref: str = "refs/heads/automation-delivery"


@dataclass(frozen=True, repr=False)
class SessionIdentity:
    actor_id: int
    code_oid: str
    grants: frozenset[tuple[int, str]]
    observed_at: int
    expires_at: int
    mode: str = "OFFLINE_TEST_DOUBLE"


@dataclass(frozen=True, repr=False)
class GitObject:
    kind: str
    raw: bytes


@dataclass(frozen=True, repr=False)
class ObjectPin:
    oid: str
    sha256: str
    size: int


@dataclass(frozen=True, repr=False)
class StatePins:
    request_sha256: str
    source: str
    parent: str
    assets_tip: str
    authority: str
    witness: str
    ledger_tip: str
    record_sha256: str
    receipts_sha256: str
    receipt_id: str | None = None


@dataclass(frozen=True, repr=False)
class AssetPin:
    role: str
    release_id: int
    asset_id: int
    sha256: str
    size: int


@dataclass(frozen=True, repr=False)
class AssetBytes:
    repository_id: int
    release_id: int
    asset_id: int
    raw: bytes


@dataclass(frozen=True, repr=False)
class Derivation:
    request_sha256: str
    source_commit: str
    raw: ObjectPin
    output: ObjectPin
    role: str
    policy: str
    status: str
    verifier_actor: int
    verifier_code: str


@dataclass(frozen=True, repr=False)
class QuotaObservation:
    account_id: int
    observed_at: int
    expires_at: int
    plan: str
    remaining: tuple[tuple[str, int], ...]
    paid_blocked_resources: frozenset[str]
    paid_limit_cents: int | None
    overages_enabled: bool | None


class ReadPort(Protocol):
    def session(self) -> SessionIdentity: ...
    def repository(self, numeric_id: int) -> RepoPin: ...
    def ref(self, numeric_id: int, ref: str) -> str: ...
    def git_object(self, numeric_id: int, oid: str) -> GitObject: ...
    def asset(self, numeric_id: int, release_id: int, asset_id: int) -> AssetBytes: ...


class VerificationPort(Protocol):
    def session(self) -> SessionIdentity: ...
    def derivation(self, proof_sha256: str) -> Derivation: ...


class QuotaPort(Protocol):
    # Future implementation MUST use fresh authoritative account-wide usage AND
    # restrictive budget/paid-block evidence. No hardcoded monthly allowance.
    def observation(self, account_id: int) -> QuotaObservation: ...


class SimulatedCASPort(Protocol):
    def session(self) -> SessionIdentity: ...
    def capabilities(self) -> frozenset[str]: ...
    def compare_and_swap(self, repository_id: int, ref: str,
                         expected: str, target: str) -> None: ...


@dataclass(frozen=True, repr=False)
class OfflinePorts:
    private_read: ReadPort
    public_read: ReadPort
    independent_verify: VerificationPort
    control_write: SimulatedCASPort
    quota: QuotaPort


class NativeAtomicPort(Protocol):
    # Trusted injection only. No URL, credentials, retries or REST fallback here.
    def session(self) -> SessionIdentity: ...
    def node_id(self, numeric_id: int) -> str: ...
    def update_refs(self, query: str, variables: dict) -> "NativeReply": ...


@dataclass(frozen=True, repr=False)
class NativeConfig:
    repository: RepoPin
    node_id: str
    actor_id: int
    port: NativeAtomicPort


@dataclass(frozen=True, repr=False)
class NativeReply:
    http_status: int
    body: object


@dataclass(frozen=True)
class Result:
    status: str
    reason: str
    payload: object = field(default=None, repr=False)
    pending: StatePins | NativeIntent | None = field(default=None, repr=False)

    def __post_init__(self):
        statuses = {"REJECTED", "UNSUPPORTED", "UNRESOLVED", "SUSPENDED_FREE_QUOTA",
                    "PINNED_STATE_SIMULATED", "ADMITTED_SIMULATION",
                    "PRIVATE_BYTES_SIMULATED", "DERIVATION_BOUND_SIMULATED",
                    "INTENTIONAL_TXT_SIMULATED", "PUBLIC_BYTES_PREVIEW_ONLY",
                    "PINNED_RECOVERY_BYTES_SIMULATED", "ALREADY_APPLIED_SIMULATION",
                    "APPLIED_SIMULATION", "ATOMIC_APPLIED_INACTIVE",
                    "ATOMIC_OBSERVED_INACTIVE"}
        if type(self.status) is not str or self.status not in statuses:
            object.__setattr__(self, "status", "REJECTED")
        if type(self.reason) is not str or self.reason not in CODES | {"OK"}:
            object.__setattr__(self, "reason", "PROVIDER_UNAVAILABLE")

    def summary(self):
        return {"status": self.status, "reason": self.reason, "offline_only": True,
                "live_activation": False, "publication_authorized": False,
                "d3_chain_verified": False, "durable_suspension": False}


@dataclass(frozen=True, repr=False)
class _PrivateBlob:
    pin: ObjectPin
    raw: bytes
    source: str
    path: str
    request: str
    seal: object


@dataclass(frozen=True, repr=False)
class _PublicPayload:
    raw: bytes
    binding: object  # PRIVATE provenance; NEVER serialize to public metadata.
    kind: str
    seal: object


def guarded(fn):
    @wraps(fn)
    def call(self, *args, **kwargs):
        pending = next((v for v in (*args, *kwargs.values()) if type(v) is StatePins), None)
        try:
            need(self.ports is not None, "NO_OFFLINE_PORTS", "UNSUPPORTED")
            return fn(self, *args, **kwargs)
        except BoundaryError as exc:
            return Result(exc.status, exc.code, pending=pending)
        except Exception:
            # No provider exception/string, path, source digest, token or bytes.
            return Result("UNRESOLVED", "PROVIDER_UNAVAILABLE", pending=pending)
    return call


class Backend:
    """No defaults enable a connection. Trusted test ports must be injected.

    inspect/admit are evidence/admission ONLY, never authority acceptance.
    Retaining a suspended Result in RAM is NOT durable persistence. The future
    pipeline must retain original requests and accepted receipts independently.
    """
    def __init__(self, policy=None, ports=None, *, clock=time.time, native=None):
        self.ports, self.clock, self.policy = ports, clock, policy
        self.native = native
        self._native_attempts = {}
        self._native_lock = RLock()
        self._seal = object()
        self._issued_raw, self._issued_public = [], []
        if ports is None:
            return
        need(type(ports) is OfflinePorts and type(policy) is Policy, "BAD_POLICY")
        need(len(policy.repos) == 3 and {p.role for p in policy.repos} == set(NAMES),
             "BAD_POLICY")
        self.repos = {p.role: p for p in policy.repos}
        need(len({p.numeric_id for p in policy.repos}) == 3 and all(
            positive(p.numeric_id) and (p.name, p.visibility) == NAMES[p.role]
            for p in policy.repos), "BAD_POLICY")
        self.actors = dict(policy.actors)
        need(len(policy.actors) == len(self.actors) == 4 and set(self.actors) ==
             {"private_read", "public_read", "independent_verify", "control_write"} and
             all(positive(v) for v in self.actors.values()) and
             len(set(self.actors.values())) == 4, "BAD_POLICY")
        need(oid(policy.code_oid) and oid(policy.verifier_code_oid) and
             type(policy.library_id) is str and bool(policy.library_id) and
             positive(policy.account_id) and type(policy.ttl) is int and
             1 <= policy.ttl <= 300, "BAD_POLICY")
        need(len(dict(policy.reserves)) == len(policy.reserves) and
             {"private_minutes", "storage_bytes"} <= set(dict(policy.reserves)) and
             all(type(k) is str and positive(v) for k, v in policy.reserves), "BAD_POLICY")
        need((policy.code_ref, policy.ledger_ref, policy.delivery_ref) ==
             ("refs/heads/automation-control", "refs/heads/automation-ledger",
              "refs/heads/automation-delivery"), "BAD_POLICY")

    def _fresh(self, observed, expires):
        now = self.clock()
        return type(observed) is int and type(expires) is int and \
            observed <= now < expires and now - observed <= self.policy.ttl and \
            observed < expires <= observed + self.policy.ttl

    def _session(self, port_name):
        port = getattr(self.ports, port_name)
        s = port.session()
        need(type(s) is SessionIdentity and s.mode == "OFFLINE_TEST_DOUBLE",
             "NO_OFFLINE_PORTS", "UNSUPPORTED")
        need(positive(s.actor_id) and s.actor_id == self.actors[port_name], "ACTOR_SCOPE")
        expected_code = self.policy.verifier_code_oid if port_name == "independent_verify" else self.policy.code_oid
        need(s.code_oid == expected_code, "CODE_IDENTITY")
        need(self._fresh(s.observed_at, s.expires_at), "STALE_SESSION")
        i, a, c = (self.repos[x].numeric_id for x in ("intake", "assets", "control"))
        expected = {"private_read": frozenset({(i, "read")}),
                    "public_read": frozenset({(a, "read"), (c, "read")}),
                    "independent_verify": frozenset({(i, "verify")}),
                    "control_write": frozenset({(c, "cas")})}
        need(type(s.grants) is frozenset and all(type(g) is tuple and len(g) == 2 and
             positive(g[0]) and type(g[1]) is str for g in s.grants) and
             s.grants == expected[port_name], "CREDENTIAL_SCOPE")
        return port

    def _repo(self, role):
        need(role in self.repos, "ROLE_SCOPE")
        port = self._session("private_read" if role == "intake" else "public_read")
        pin = self.repos[role]
        actual = port.repository(pin.numeric_id)
        need(type(actual) is RepoPin and type(actual.numeric_id) is int and
             actual == pin, "REPOSITORY_IDENTITY")
        return port, pin.numeric_id

    def _ref(self, role, ref):
        p, rid = self._repo(role)
        value = p.ref(rid, ref)
        need(oid(value), "OBJECT_IDENTITY")
        return value

    def _object(self, role, identity, kind):
        need(oid(identity), "OBJECT_IDENTITY")
        p, rid = self._repo(role)
        obj = p.git_object(rid, identity)
        need(type(obj) is GitObject and obj.kind == kind, "OBJECT_TYPE")
        need(type(obj.raw) is bytes and len(obj.raw) <= 50_000_000, "OBJECT_LIMIT")
        actual = sha1(kind.encode("ascii") + b" " + str(len(obj.raw)).encode() +
                      b"\0" + obj.raw).hexdigest()
        need(actual == identity, "OBJECT_IDENTITY")
        return obj.raw

    def _commit(self, role, identity):
        raw = self._object(role, identity, "commit")
        need(b"\n\n" in raw, "INVALID_COMMIT")
        headers = raw.split(b"\n\n", 1)[0].splitlines()
        trees = [v[5:].decode("ascii") for v in headers if v.startswith(b"tree ")]
        parents = [v[7:].decode("ascii") for v in headers if v.startswith(b"parent ")]
        need(len(trees) == 1 and oid(trees[0]) and all(oid(v) for v in parents),
             "INVALID_COMMIT")
        return trees[0], parents

    def _path(self, role, commit, path):
        tree, _ = self._commit(role, commit)
        parts = path.split("/")
        for i, part in enumerate(parts):
            raw = self._object(role, tree, "tree")
            entries, at = {}, 0
            while at < len(raw):
                space = raw.find(b" ", at); zero = raw.find(b"\0", space + 1)
                need(space > at and zero > space and zero + 21 <= len(raw), "INVALID_TREE")
                mode = raw[at:space]; name = raw[space + 1:zero].decode("utf8")
                need(name not in entries and name not in (".", "..") and
                     "/" not in name, "INVALID_TREE")
                entries[name] = (mode, raw[zero + 1:zero + 21].hex())
                at = zero + 21
            need(part in entries, "PATH_NOT_FOUND")
            mode, tree = entries[part]
            if i < len(parts) - 1:
                need(mode == b"40000", "INVALID_TREE")
            else:
                need(mode == b"100644", "INVALID_TREE")
                return tree, self._object(role, tree, "blob")
        raise BoundaryError("PATH_NOT_FOUND")

    def _ancestor(self, role, old, new):
        seen, todo = set(), [new]
        while todo:
            here = todo.pop()
            if here in seen:
                continue
            seen.add(here)
            need(len(seen) <= 512, "ANCESTRY_LIMIT")
            _, parents = self._commit(role, here)
            if here == old:
                return True
            todo.extend(parents)
        return False

    def _refs(self):
        return (self._ref("intake", MAIN),
                self._ref("assets", MAIN), self._ref("assets", WITNESS),
                self._ref("control", self.policy.ledger_ref),
                self._ref("control", self.policy.code_ref))

    def _state(self, pins):
        need(type(pins) is StatePins and all(oid(getattr(pins, k)) for k in
             ("source", "parent", "assets_tip", "authority", "witness", "ledger_tip")) and
             all(sha(getattr(pins, k)) for k in
                 ("request_sha256", "record_sha256", "receipts_sha256")) and
             (pins.receipt_id is None or sha(pins.receipt_id)), "BAD_PINS")
        expected = (pins.source, pins.assets_tip, pins.witness, pins.ledger_tip,
                    self.policy.code_oid)
        first = self._refs()
        need(first[0] == pins.source, "SOURCE_IDENTITY")
        need(first == expected, "STALE_STATE")
        self._commit("control", self.policy.code_oid)
        need(self._commit("intake", pins.source)[1] == [pins.parent], "INVALID_ANCESTRY")
        self._commit("intake", pins.parent)
        need(self._ancestor("assets", pins.authority, pins.assets_tip), "INVALID_ANCESTRY")
        _, raw_record = self._path("control", pins.ledger_tip, "anchor.json")
        need(digest(raw_record) == pins.record_sha256, "INDEPENDENT_EVIDENCE")
        record = parse(raw_record)
        try:
            LocalWitness.validate_record(SimpleNamespace(library_id=self.policy.library_id), record)
        except Exception:
            raise BoundaryError("INDEPENDENT_EVIDENCE") from None
        need(data(record) == raw_record and record["primary_main"] == pins.authority and
             record["primary_witness"] == pins.witness, "AUTHORITY_IDENTITY")
        need(self._ancestor("assets", record["primary_base"], pins.authority),
             "INVALID_ANCESTRY")
        _, registry_raw = self._path("assets", pins.authority, "automation-state/registry.json")
        need(digest(registry_raw) == record["registry_sha256"], "REGISTRY_IDENTITY")
        reg = parse(registry_raw)
        try:
            Store._validate(None, reg)  # Existing pure schema check; no Store/root/IO.
        except Exception:
            raise BoundaryError("REGISTRY_IDENTITY") from None
        need(data(reg) == registry_raw and reg["library_id"] == self.policy.library_id and
             reg["seq"] == record["registry_seq"] and reg["counters"] == record["counters"] and
             reg["transaction_status"] == record["phase"], "REGISTRY_IDENTITY")
        _, witness_raw = self._path("assets", pins.witness, "witness.json")
        w = parse(witness_raw)
        need(set(w) == {"schema", "authority", "library_id", "seq", "counters",
                        "registry_sha256", "previous"} and type(w["schema"]) is int and
             w["schema"] == 1 and w["authority"] == pins.authority and
             all(w[k] == record[k] for k in ("library_id", "counters", "registry_sha256")) and
             w["seq"] == record["registry_seq"] and
             (w["previous"] is None or oid(w["previous"])), "WITNESS_IDENTITY")
        need(digest(data(reg["receipts"])) == pins.receipts_sha256, "RECEIPTS_IDENTITY")
        need(self._refs() == first, "STALE_STATE")
        return record, reg

    def _quota(self, demand):
        try:
            return self._quota_evidence(demand)
        except BoundaryError:
            raise
        except Exception:
            raise BoundaryError("QUOTA_UNKNOWN", "SUSPENDED_FREE_QUOTA") from None

    def _quota_evidence(self, demand):
        reserves = dict(self.policy.reserves)
        need(type(demand) is dict and set(demand) == set(reserves) and all(
            type(v) is int and v >= 0 for v in demand.values()),
            "QUOTA_UNKNOWN", "SUSPENDED_FREE_QUOTA")
        try:
            q = self.ports.quota.observation(self.policy.account_id)
        except Exception:
            raise BoundaryError("QUOTA_UNKNOWN", "SUSPENDED_FREE_QUOTA") from None
        need(type(q) is QuotaObservation and positive(q.account_id) and q.account_id == self.policy.account_id,
             "QUOTA_UNKNOWN", "SUSPENDED_FREE_QUOTA")
        need(self._fresh(q.observed_at, q.expires_at),
             "QUOTA_EXPIRED", "SUSPENDED_FREE_QUOTA")
        need(q.plan == "Free" and type(q.paid_limit_cents) is int and q.paid_limit_cents == 0 and
             q.overages_enabled is False and set(demand) <= q.paid_blocked_resources,
             "PAID_NOT_BLOCKED", "SUSPENDED_FREE_QUOTA")
        remaining = dict(q.remaining)
        need(len(remaining) == len(q.remaining) and set(demand) <= set(remaining) and all(
            type(remaining[k]) is int and remaining[k] >= 0 for k in demand),
            "QUOTA_UNKNOWN", "SUSPENDED_FREE_QUOTA")
        need(all(remaining[k] - demand[k] >= reserves[k] for k in demand),
             "QUOTA_RESERVE", "SUSPENDED_FREE_QUOTA")
        # No capacity reservation or guarantee against concurrent account activity.
        # Actual restrictive paid-usage blocking remains separately necessary.
        return q

    @guarded
    def inspect(self, pins):
        record, reg = self._state(pins)
        return Result("PINNED_STATE_SIMULATED", "OK",
                      {"record": record, "registry": reg,
                       "receipt_present": pins.receipt_id in reg["receipts"]}, pins)

    @guarded
    def admit(self, pins, demand):
        record, reg = self._state(pins)
        self._quota(demand)
        return Result("ADMITTED_SIMULATION", "OK",
                      {"phase": record["phase"],
                       "receipt_present": pins.receipt_id in reg["receipts"]}, pins)

    @guarded
    def read_source(self, pins, path, expected):
        self._state(pins)
        need(type(expected) is ObjectPin and oid(expected.oid) and sha(expected.sha256) and
             type(expected.size) is int and expected.size >= 0, "BAD_PINS")
        try:
            _path(path)
        except Exception:
            raise BoundaryError("SOURCE_IDENTITY") from None
        identity, raw = self._path("intake", pins.source, path)
        need(identity == expected.oid and len(raw) == expected.size and
             digest(raw) == expected.sha256, "SOURCE_IDENTITY")
        need(self._refs()[0] == pins.source, "STALE_STATE")
        blob = _PrivateBlob(expected, raw, pins.source, path, pins.request_sha256, self._seal)
        self._issued_raw.append(blob)
        return Result("PRIVATE_BYTES_SIMULATED", "OK", blob, pins)

    @guarded
    def verify_derivation(self, pins, raw_blob, output, proof_sha256, role):
        self._state(pins)
        need(type(raw_blob) is _PrivateBlob and any(raw_blob is x for x in self._issued_raw) and
             raw_blob.seal is self._seal and
             raw_blob.request == pins.request_sha256 and raw_blob.source == pins.source,
             "PRIVACY_EVIDENCE")
        need(type(output) is ObjectPin and oid(output.oid) and sha(output.sha256) and
             type(output.size) is int and output.size > 0 and sha(proof_sha256) and role in ("original", "og"),
             "DERIVATION_IDENTITY")
        self._commit("control", self.policy.verifier_code_oid)
        verifier = self._session("independent_verify")
        proof = verifier.derivation(proof_sha256)
        need(type(proof) is Derivation and digest(data(asdict(proof))) == proof_sha256,
             "PRIVACY_EVIDENCE")
        need(proof.request_sha256 == pins.request_sha256 and proof.source_commit == pins.source and
             proof.raw == raw_blob.pin and proof.output == output and proof.role == role and
             proof.policy == "bgzona-image-privacy-r1" and proof.status == "SANITIZED_AND_VERIFIED" and
             proof.verifier_actor == self.actors["independent_verify"] and
             proof.verifier_code == self.policy.verifier_code_oid, "DERIVATION_IDENTITY")
        b = self._object("intake", output.oid, "blob")
        need(len(b) == output.size and digest(b) == output.sha256, "DERIVATION_IDENTITY")
        # Protected verifier must inspect actual source/output under E4C. This
        # adapter verifies binding, NOT sanitization or visible-content approval.
        payload = _PublicPayload(b, proof, "sanitized_image", self._seal)
        self._issued_public.append(payload)
        return Result("DERIVATION_BOUND_SIMULATED", "OK", payload, pins)

    @guarded
    def intentional_txt(self, pins, blob, path):
        self._state(pins)
        need(type(blob) is _PrivateBlob and any(blob is x for x in self._issued_raw) and
             blob.seal is self._seal and blob.path == path and
             blob.request == pins.request_sha256 and blob.source == pins.source, "TXT_STRUCTURE")
        try:
            need(_path(path).suffix.lower() == ".txt", "TXT_STRUCTURE")
            text(blob.raw)
        except Exception:
            raise BoundaryError("TXT_STRUCTURE") from None
        payload = _PublicPayload(blob.raw, blob.pin, "intentional_txt", self._seal)
        self._issued_public.append(payload)
        return Result("INTENTIONAL_TXT_SIMULATED", "OK", payload, pins)

    @guarded
    def public_preview(self, payload, destination="assets"):
        need(destination == "assets", "ROLE_SCOPE")
        need(type(payload) is not _PrivateBlob, "RAW_TO_PUBLIC")
        need(type(payload) is _PublicPayload and any(payload is x for x in self._issued_public) and
             payload.seal is self._seal,
             "OUTPUT_CAPABILITY")
        # Bytes only. Do NOT serialize PRIVATE binding/provenance. No upload.
        return Result("PUBLIC_BYTES_PREVIEW_ONLY", "OK", payload.raw)

    @guarded
    def recovery_bytes(self, pins, locator, *, private=False, candidate=None):
        record, _ = self._state(pins)
        need(type(locator) is AssetPin and positive(locator.release_id) and
             positive(locator.asset_id) and sha(locator.sha256) and
             type(locator.size) is int and 0 < locator.size <= 50_000_000, "BACKUP_IDENTITY")
        need(locator.role == ("intake" if private else "control"), "ROLE_SCOPE")
        if not private:
            need(locator.sha256 == record["backup"]["sha256"] and
                 locator.size == record["backup"]["bytes"], "BACKUP_IDENTITY")
        p, rid = self._repo(locator.role)
        buffers = []
        for _ in range(2):
            a = p.asset(rid, locator.release_id, locator.asset_id)
            need(type(a) is AssetBytes and all(positive(v) for v in
                 (a.repository_id, a.release_id, a.asset_id)) and (a.repository_id, a.release_id, a.asset_id) ==
                 (rid, locator.release_id, locator.asset_id), "BACKUP_IDENTITY")
            need(type(a.raw) is bytes and len(a.raw) == locator.size and
                 digest(a.raw) == locator.sha256, "RECOVERY_BYTES")
            buffers.append(a.raw)
        need(buffers[0] == buffers[1] and
             (candidate is None or type(candidate) is bytes and candidate == buffers[0]),
             "RECOVERY_BYTES")
        self._state(pins)
        return Result("PINNED_RECOVERY_BYTES_SIMULATED", "OK", buffers[0], pins)

    @guarded
    def simulate_control_ff(self, pins, expected, target, demand, *,
                            ref="refs/heads/automation-delivery"):
        self._state(pins); self._quota(demand)
        need(ref == self.policy.delivery_ref, "REF_SCOPE")
        writer = self._session("control_write")
        need("single_ref_cas_simulated" in writer.capabilities(),
             "SINGLE_REF_CAS_UNSUPPORTED", "UNSUPPORTED")
        need(oid(expected) and oid(target), "BAD_PINS")
        need(self._ancestor("control", expected, target), "NON_FAST_FORWARD")
        current = self._ref("control", ref)
        if current == target:
            return Result("ALREADY_APPLIED_SIMULATION", "OK", pending=pins)
        need(current == expected, "REF_CONFLICT", "UNRESOLVED")
        self._state(pins); self._quota(demand)
        try:
            writer.compare_and_swap(self.repos["control"].numeric_id, ref, expected, target)
        except Exception:
            raise BoundaryError("OUTCOME_UNKNOWN", "UNRESOLVED") from None
        need(self._ref("control", ref) == target, "REF_CONFLICT", "UNRESOLVED")
        return Result("APPLIED_SIMULATION", "OK", pending=pins)

    def _native_gate(self, intent, demand):
        n = self.native
        need(type(n) is NativeConfig and n.repository == self.repos["assets"] and
             type(n.repository.numeric_id) is int and n.repository.role == "assets",
             "NATIVE_IDENTITY")
        need(type(n.node_id) is str and re.fullmatch(r"R_[A-Za-z0-9_-]{8,100}", n.node_id),
             "NATIVE_IDENTITY")
        self._repo("assets")
        session = n.port.session()
        need(type(session) is SessionIdentity and session.mode == "OFFLINE_TEST_DOUBLE",
             "NO_OFFLINE_PORTS", "UNSUPPORTED")
        need(positive(n.actor_id) and n.actor_id not in self.actors.values() and
             session.actor_id == n.actor_id and positive(session.actor_id), "ACTOR_SCOPE")
        need(session.code_oid == self.policy.code_oid, "CODE_IDENTITY")
        need(self._fresh(session.observed_at, session.expires_at), "STALE_SESSION")
        need(type(session.grants) is frozenset and
             session.grants == frozenset({(n.repository.numeric_id, "atomic_pair")}) and
             all(type(rid) is int and type(grant) is str for rid, grant in session.grants),
             "CREDENTIAL_SCOPE")
        need(n.port.node_id(n.repository.numeric_id) == n.node_id, "NATIVE_IDENTITY")
        need(type(intent) is NativeIntent and len(intent.before) == len(intent.after) == 2 and
             all(oid(v) and v != "0" * 40 for v in (*intent.before, *intent.after)), "NATIVE_INTENT")
        verify_native_intent(intent, self)
        need(demand == dict(intent._binding.demand),
             "QUOTA_UNKNOWN", "SUSPENDED_FREE_QUOTA")
        self._quota(demand)

    def _native_pair(self):
        first = (self._ref("assets", MAIN), self._ref("assets", WITNESS))
        need(first == (self._ref("assets", MAIN), self._ref("assets", WITNESS)),
             "STALE_STATE", "UNRESOLVED")
        return first

    def atomic_authority_update(self, intent=None, demand=None):
        with self._native_lock:
            result = self._atomic_authority_update(intent, demand)
            if type(result.pending) is NativeIntent and result.pending._binding is not None:
                try:
                    native_intent_binding(result.pending, self).complete_native_attempt(result)
                except Exception:
                    return Result("UNRESOLVED", "OUTCOME_UNKNOWN", pending=result.pending)
            return result

    def _atomic_authority_update(self, intent=None, demand=None):
        """Inactive D3 seam. D3 optionally persists a PRIVATE replay barrier.

        A retained local checkpoint is not durable GitHub cloud recovery. Unknown unchanged state is
        never a verified rejection. No HTTP status or caller flag grants writes.
        """
        if self.ports is None or self.native is None:
            return Result("UNSUPPORTED", "NATIVE_ATOMIC_UNSUPPORTED")
        original = intent if type(intent) is NativeIntent else None
        native = self.native
        try:
            self._native_gate(intent, demand)
            # The D3 accepted-record identity, not a newly generated repair OID,
            # prevents an unknown attempt being silently replaced and resent.
            key = (self.repos["assets"].numeric_id, intent.record_sha256,
                   intent.request_sha256)
            previous = self._native_attempts.get(key)
            if previous is None and intent.recovered:
                previous = intent
                self._native_attempts[key] = intent
            if previous is not None:
                original = previous
                self._native_gate(original, demand)
                pair = self._native_pair()
                if pair == original.after:
                    return Result("ATOMIC_OBSERVED_INACTIVE", "OUTCOME_UNKNOWN", pending=original)
                return Result("UNRESOLVED", "OUTCOME_UNKNOWN", pending=original)
            pair = self._native_pair()
            if pair == intent.after:
                return Result("ATOMIC_OBSERVED_INACTIVE", "OK", pending=intent)
            need(pair == intent.before, "REF_CONFLICT", "UNRESOLVED")
            # IDs bind only public ref transaction data, never private provenance.
            client = digest(data([native.node_id, intent.before, intent.after]))
            variables = {"input": {"repositoryId": native.node_id,
                "clientMutationId": client, "refUpdates": [
                    {"name": ref, "beforeOid": old, "afterOid": new, "force": False}
                    for ref, old, new in zip((MAIN, WITNESS), intent.before, intent.after)]}}
            need(self.native is native, "NATIVE_IDENTITY")
            self._native_attempts[key] = intent  # Reserve BEFORE possible write.
            intent._binding.reserve_native_attempt(intent)
            reply = None
            try:
                reply = native.port.update_refs(
                    "mutation($input:UpdateRefsInput!){updateRefs(input:$input){clientMutationId}}",
                    variables)
            except Exception:
                pass  # Never log or return provider exception/private text.
            # Readback + genuine independent D3 validation, even after timeout.
            pair = self._native_pair()
            self._native_gate(intent, demand)
            body = reply.body if type(reply) is NativeReply else None
            delivered = type(reply) is NativeReply and type(reply.http_status) is int and reply.http_status == 200
            success = delivered and type(body) is dict and body == {
                "data": {"updateRefs": {"clientMutationId": client}}}
            if success and pair == intent.after:
                return Result("ATOMIC_APPLIED_INACTIVE", "OK", pending=intent)
            # Only this recorded explicit semantic refusal is recognized. New
            # generic/untyped/provider diagnostics remain unknown, not PASS.
            rejected = delivered and type(body) is dict and body.get("data") == {"updateRefs": None} and \
                type(body.get("errors")) is list and len(body["errors"]) == 1 and \
                type(body["errors"][0]) is dict and body["errors"][0].get("type") == "UNPROCESSABLE" and \
                body["errors"][0].get("path") == ["updateRefs"] and \
                body["errors"][0].get("message") == "rejecting non-fast forward update"
            if rejected and pair == intent.before:
                return Result("REJECTED", "REF_CONFLICT", pending=intent)
            if not success and not rejected and pair == intent.after:
                # Observed independently accepted state, not mutation success.
                return Result("ATOMIC_OBSERVED_INACTIVE", "OUTCOME_UNKNOWN", pending=intent)
            return Result("UNRESOLVED", "OUTCOME_UNKNOWN", pending=intent)
        except BoundaryError as exc:
            return Result(exc.status, exc.code, pending=original)
        except Exception:
            return Result("UNRESOLVED", "OUTCOME_UNKNOWN", pending=original)

    def write_backup(self, *args, **kwargs):
        # No upload, immutability/WORM, public bundle privacy or remote restore
        # capability has been established. Retrieval/readback is NOT that proof.
        return Result("UNSUPPORTED", "BACKUP_WRITE_UNSUPPORTED")



# E4M: PRIVATE recovery storage only. Not an authority catalog, immutable backup,
# public-media writer or permission to enable PROVIDER_REQUIRED.
RECOVERY_REF = "refs/heads/automation-recovery"
RECOVERY_MARKER = "private-recovery/identity.json"


class RecoveryStop(RuntimeError):
    def __init__(self, code):
        self.code = code if code in {
            "BOOTSTRAP_REQUIRED", "RECOVERY_IDENTITY", "RECOVERY_SCOPE",
            "RECOVERY_INTEGRITY", "RECOVERY_CONFLICT", "RECOVERY_UNKNOWN",
            "RECOVERY_MISSING", "RECOVERY_CLAIMED", "RECOVERY_LIMIT"} else "RECOVERY_UNKNOWN"
        super().__init__(self.code)


def recovery_need(ok, code="RECOVERY_INTEGRITY"):
    if not ok: raise RecoveryStop(code)


def recovery_tree(buffers):
    """Exact Git tree identity; no Git writes, symlinks or arbitrary modes."""
    from git_transport import relative
    root = {}
    recovery_need(type(buffers) is dict and len(buffers) <= 256, "RECOVERY_LIMIT")
    recovery_need(sum(len(v) for v in buffers.values() if type(v) is bytes) <= 16_000_000, "RECOVERY_LIMIT")
    for path, raw in buffers.items():
        recovery_need(type(path) is str and type(raw) is bytes)
        parts = relative(path).parts
        recovery_need(path.startswith("private-recovery/"), "RECOVERY_SCOPE")
        node = root
        for part in parts[:-1]:
            node = node.setdefault(part, {})
            recovery_need(type(node) is dict)
        recovery_need(parts[-1] not in node)
        node[parts[-1]] = raw
    def obj(kind, raw):
        return sha1(kind.encode()+b" "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
    def tree(node):
        rows=[]
        for name, value in sorted(node.items(), key=lambda pair:(pair[0]+("/" if type(pair[1]) is dict else "")).encode()):
            directory=type(value) is dict
            identity=tree(value) if directory else obj("blob",value)
            rows.append((b"40000" if directory else b"100644")+b" "+name.encode()+b"\0"+bytes.fromhex(identity))
        return obj("tree", b"".join(rows))
    return tree(root)


class PrivateRecovery:
    """Narrow injected provider adapter; no default connection or credentials.

    port.repository/head/snapshot/create_commit are trusted I/O, never owner JSON.
    snapshot returns head, parents, tree, and ALL flat regular-file bytes. The
    adapter computes the entire expected tree and verifies fresh post-write state.
    Unknown write outcomes never grant a claim or cause a retry.
    """
    def __init__(self, repository, node_id, actor_id, code_oid, port, *,
                 expected_head, writable=False, clock=time.time, ref=RECOVERY_REF):
        self.repository,self.node_id,self.actor_id,self.code_oid=repository,node_id,actor_id,code_oid
        self.port,self.expected_head,self.writable,self.clock,self.ref=port,expected_head,writable,clock,ref
        self._attempted=set();self._claims={};self._lock=RLock()
        self._gate()

    def _gate(self):
        try:self._check_identity()
        except RecoveryStop:raise
        except Exception:raise RecoveryStop("RECOVERY_UNKNOWN") from None

    def _check_identity(self):
        p=self.repository
        recovery_need(type(p) is RepoPin and p.role=="intake" and positive(p.numeric_id) and
                      (p.name,p.visibility)==NAMES["intake"],"RECOVERY_IDENTITY")
        recovery_need(self.ref==RECOVERY_REF and oid(self.expected_head) and oid(self.code_oid) and
                      type(self.writable) is bool,"RECOVERY_SCOPE")
        recovery_need(type(self.node_id) is str and re.fullmatch(r"R_[A-Za-z0-9_-]{8,100}",self.node_id) and
                      positive(self.actor_id),"RECOVERY_IDENTITY")
        recovery_need(self.port.repository(p.numeric_id)==p and self.port.node_id(p.numeric_id)==self.node_id,
                      "RECOVERY_IDENTITY")
        s=self.port.session();now=self.clock()
        recovery_need(type(s) is SessionIdentity and s.actor_id==self.actor_id and s.code_oid==self.code_oid and
                      s.mode in ("OFFLINE_TEST_DOUBLE","HOSTED_SYNTHETIC_PRIVATE_ONLY") and
                      s.grants==frozenset({(p.numeric_id,"contents:write" if self.writable else "contents:read")}) and
                      type(s.observed_at) is int and type(s.expires_at) is int and
                      s.observed_at<=now<s.expires_at<=s.observed_at+60 and now-s.observed_at<=60,
                      "RECOVERY_IDENTITY")

    def read(self, expected=None):
        try:
            self._gate();rid=self.repository.numeric_id
            head=self.port.head(rid,self.ref)
            if head is None:raise RecoveryStop("BOOTSTRAP_REQUIRED")
            recovery_need(oid(head) and (expected is None or head==expected),"RECOVERY_CONFLICT")
            row=self.port.snapshot(rid,head)
            recovery_need(type(row) is dict and set(row)=={"head","parents","tree","files"} and
                          row["head"]==head and type(row["parents"]) is list and
                          all(oid(v) for v in row["parents"]) and recovery_tree(row["files"])==row["tree"])
            marker=data({"format":"bgzona-private-recovery-r1","repository":rid})
            recovery_need(row["files"].get(RECOVERY_MARKER)==marker,"RECOVERY_IDENTITY")
            recovery_need(self.port.head(rid,self.ref)==head,"RECOVERY_CONFLICT")
            return row
        except RecoveryStop:raise
        except Exception:raise RecoveryStop("RECOVERY_UNKNOWN") from None

    def _append(self,path,raw,expected):
        with self._lock:
            recovery_need(self.writable and type(raw) is bytes,"RECOVERY_SCOPE")
            # Reserve before possible I/O. Unknown/failed calls cannot be replayed.
            recovery_need(path not in self._attempted,"RECOVERY_CLAIMED")
            before=self.read(expected)
            recovery_need(path not in before["files"],"RECOVERY_CLAIMED")
            wanted=before["files"]|{path:raw};tree=recovery_tree(wanted)
            variables={"input":{"branch":{"repositoryNameWithOwner":self.repository.name,"refName":self.ref},
                "expectedHeadOid":expected,"message":{"headline":"PRIVATE recovery checkpoint"},
                "fileChanges":{"additions":[{"path":path,"contents":__import__('base64').b64encode(raw).decode('ascii')}]}}}
            self._gate();self._attempted.add(path)
            try:
                reply=self.port.create_commit("mutation($input:CreateCommitOnBranchInput!){createCommitOnBranch(input:$input){commit{oid}}}",variables)
            except Exception:
                # Best-effort readback retains evidence; it never grants send rights.
                try:self.read()
                except Exception:pass
                raise RecoveryStop("RECOVERY_UNKNOWN") from None
            try:
                recovery_need(type(reply) is NativeReply and reply.http_status==200 and type(reply.body) is dict and
                              set(reply.body)=={"data"} and set(reply.body["data"])=={"createCommitOnBranch"})
                answer=reply.body["data"]["createCommitOnBranch"]
                recovery_need(type(answer) is dict and set(answer)=={"commit"} and
                              type(answer["commit"]) is dict and set(answer["commit"])=={"oid"})
                commit=answer["commit"]["oid"];recovery_need(oid(commit))
                after=self.read(commit)
                recovery_need(after["parents"]==[expected] and after["tree"]==tree and after["files"]==wanted)
                self.expected_head=commit
                return commit
            except Exception:
                try:self.read()
                except Exception:pass
                raise RecoveryStop("RECOVERY_UNKNOWN") from None

    def _slot(self,request,record):
        recovery_need(sha(request) and sha(record),"RECOVERY_SCOPE")
        return "private-recovery/"+request+"/"+record

    def persist(self,request,record,packet):
        return self._append(self._slot(request,record)+"/checkpoint.json",packet,self.expected_head)

    def claim(self,request,record,packet_sha):
        import uuid
        slot=self._slot(request,record);before=self.read(self.expected_head)
        recovery_need(sha(packet_sha) and digest(before["files"].get(slot+"/checkpoint.json",b""))==packet_sha)
        raw=data({"packet":packet_sha,"claim":uuid.uuid4().hex})
        commit=self._append(slot+"/claim.json",raw,self.expected_head)
        self._claims[slot]=(commit,raw)
        self.verify_claim(request,record,packet_sha)

    def verify_claim(self,request,record,packet_sha):
        slot=self._slot(request,record)
        recovery_need(slot in self._claims,"RECOVERY_CLAIMED")
        commit,raw=self._claims[slot];state=self.read(commit)
        recovery_need(state["files"].get(slot+"/claim.json")==raw and
                      digest(state["files"].get(slot+"/checkpoint.json",b""))==packet_sha)

    def retrieve(self,request,record):
        slot=self._slot(request,record);state=self.read(self.expected_head)
        recovery_need(slot+"/checkpoint.json" in state["files"],"RECOVERY_MISSING")
        packet=state["files"][slot+"/checkpoint.json"]
        recovery_need(slot+"/claim.json" in state["files"],"RECOVERY_MISSING")
        claim=parse(state["files"][slot+"/claim.json"])
        recovery_need(type(claim) is dict and set(claim)=={"packet","claim"} and
                      claim["packet"]==digest(packet) and type(claim["claim"]) is str and
                      re.fullmatch('[0-9a-f]{32}',claim["claim"]))
        return packet


class PrivateRecoveryHTTP:
    """Explicit future synthetic PRIVATE transport, never a public authority port.

    No credentials are obtained by import/default construction. Runtime identity
    and declared job grants come from reviewed workflow setup, not a token-scope
    introspection API. Actual effective job permissions remain a pre-run gate.
    """
    def __init__(self,repository,actor_id,code_oid,token,*,writable=False):
        recovery_need(type(repository) is RepoPin and repository.role=='intake' and
                      (repository.name,repository.visibility)==NAMES['intake'] and positive(repository.numeric_id),
                      'RECOVERY_IDENTITY')
        recovery_need(positive(actor_id) and oid(code_oid) and type(token) is str and 0<len(token)<=1024 and
                      not any(c.isspace() for c in token) and type(writable) is bool,'RECOVERY_IDENTITY')
        self.pin,self.actor,self.code,self._token,self.writable=repository,actor_id,code_oid,token,writable
        self._compatible=True;self._writes=0

    def session(self):
        now=int(time.time())
        return SessionIdentity(self.actor,self.code,
            frozenset({(self.pin.numeric_id,'contents:write' if self.writable else 'contents:read')}),now,now+60,
            'HOSTED_SYNTHETIC_PRIVATE_ONLY')

    def _request(self,path,body=None,*,missing=False):
        import json,urllib.request,urllib.error
        # Only internally constructed, exact API paths; no redirects/proxies,
        # retries, URL input, subprocess HTTP or logging of provider diagnostics.
        recovery_need(self._compatible,'RECOVERY_INTEGRITY')
        prefix='/repos/'+self.pin.name
        allowed=path==prefix or path==prefix+'/git/ref/heads/automation-recovery' or bool(re.fullmatch(
            re.escape(prefix)+r'/git/(commits|blobs)/[0-9a-f]{40}',path)) or bool(re.fullmatch(
            re.escape(prefix)+r'/git/trees/[0-9a-f]{40}\?recursive=1',path))
        recovery_need((body is None and allowed) or (body is not None and path=='/graphql' and self.writable),
                      'RECOVERY_SCOPE')
        if body is not None:
            recovery_need(type(body) is dict and set(body)=={'query','variables'},'RECOVERY_SCOPE')
            self._validate_mutation(body['query'],body['variables'])
            recovery_need(self._writes<2,'RECOVERY_LIMIT');self._writes+=1
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self,*a,**kw):raise RecoveryStop('RECOVERY_UNKNOWN')
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
        headers={'Authorization':'Bearer '+self._token,'Accept':'application/vnd.github+json',
                 'X-GitHub-Api-Version':'2026-03-10','User-Agent':'BGZONA-inactive-private-recovery-probe'}
        request=urllib.request.Request('https://api.github.com'+path,
            data=data(body) if body is not None else None,headers=headers,method='POST' if body is not None else 'GET')
        try:
            with opener.open(request,timeout=30) as response:
                if response.headers.get('Deprecation') or response.headers.get('Sunset'):
                    self._compatible=False;raise RecoveryStop('RECOVERY_INTEGRITY')
                raw=response.read(24_000_001)
                recovery_need(len(raw)<=24_000_000,'RECOVERY_LIMIT')
                return response.status,json.loads(raw)
        except urllib.error.HTTPError as e:
            if missing and e.code==404:return 404,None
            raise RecoveryStop('RECOVERY_UNKNOWN') from None
        except RecoveryStop:raise
        except Exception:raise RecoveryStop('RECOVERY_UNKNOWN') from None

    def repository(self,rid):
        recovery_need(rid==self.pin.numeric_id,'RECOVERY_SCOPE')
        status,row=self._request('/repos/'+self.pin.name)
        recovery_need(status==200 and row.get('id')==rid and row.get('full_name')==self.pin.name and
                      row.get('private') is True and row.get('visibility')=='private','RECOVERY_IDENTITY')
        return self.pin

    def node_id(self,rid):
        self.repository(rid);_,row=self._request('/repos/'+self.pin.name);return row['node_id']

    def head(self,rid,ref):
        recovery_need(rid==self.pin.numeric_id and ref==RECOVERY_REF,'RECOVERY_SCOPE')
        status,row=self._request('/repos/'+self.pin.name+'/git/ref/heads/automation-recovery',missing=True)
        if status==404:return None
        recovery_need(status==200 and row.get('ref')==RECOVERY_REF and row['object']['type']=='commit')
        recovery_need(oid(row['object']['sha']));return row['object']['sha']

    def snapshot(self,rid,head):
        import base64
        recovery_need(rid==self.pin.numeric_id and oid(head),'RECOVERY_SCOPE')
        prefix='/repos/'+self.pin.name+'/git/'
        status,commit=self._request(prefix+'commits/'+head)
        recovery_need(status==200 and commit.get('sha')==head and oid(commit['tree']['sha']))
        tree=commit['tree']['sha'];status,listing=self._request(prefix+'trees/'+tree+'?recursive=1')
        recovery_need(status==200 and listing.get('sha')==tree and listing.get('truncated') is False and
                      type(listing.get('tree')) is list and len(listing['tree'])<=1024,'RECOVERY_LIMIT')
        files={};total=0
        for row in listing['tree']:
            recovery_need(row.get('type') in ('tree','blob') and
                          row.get('mode')==('040000' if row['type']=='tree' else '100644'))
            if row['type']=='tree':continue
            recovery_need(oid(row.get('sha')) and type(row.get('size')) is int and 0<=row['size']<=12_000_000)
            status,blob=self._request(prefix+'blobs/'+row['sha'])
            recovery_need(status==200 and blob.get('sha')==row['sha'] and blob.get('encoding')=='base64')
            raw=base64.b64decode(''.join(blob['content'].splitlines()),validate=True)
            recovery_need(len(raw)==row['size']==blob.get('size') and
                          sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==row['sha'])
            total+=len(raw);recovery_need(total<=16_000_000 and row['path'] not in files,'RECOVERY_LIMIT')
            files[row['path']]=raw
        recovery_need(recovery_tree(files)==tree)
        return {'head':head,'parents':[p['sha'] for p in commit['parents']],'tree':tree,'files':files}

    def _validate_mutation(self,query,variables):
        recovery_need(self.writable and query=='mutation($input:CreateCommitOnBranchInput!){createCommitOnBranch(input:$input){commit{oid}}}',
                      'RECOVERY_SCOPE')
        i=variables['input'];additions=i['fileChanges']['additions']
        recovery_need(set(i)=={'branch','expectedHeadOid','message','fileChanges'} and
            i['branch']=={'repositoryNameWithOwner':self.pin.name,'refName':RECOVERY_REF} and oid(i['expectedHeadOid']) and
            i['message']=={'headline':'PRIVATE recovery checkpoint'} and set(i['fileChanges'])=={'additions'} and
            len(additions)==1 and set(additions[0])=={'path','contents'},'RECOVERY_SCOPE')
        recovery_need(bool(re.fullmatch(r'private-recovery/[0-9a-f]{64}/[0-9a-f]{64}/(checkpoint|claim)\.json',additions[0]['path'])),
                      'RECOVERY_SCOPE')

    def create_commit(self,query,variables):
        self._validate_mutation(query,variables)
        status,body=self._request('/graphql',{'query':query,'variables':variables})
        return NativeReply(status,body)
