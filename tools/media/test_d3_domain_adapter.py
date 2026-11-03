"""NEW E4I integration tests only. Reuse fixture FUNCTIONS, never old suites.

Real existing D3/C1 transactions + real Git objects in a NEW marked local Lab.
Provider identities/ref mapping remain OFFLINE doubles, not GitHub capability.
The future automation-ledger ref is explicitly mapped to the Lab's D3 main.
Fictitious bootstrap fixture metadata is reused; no owner/frozen media is read.
"""
import argparse
from copy import deepcopy
from dataclasses import asdict, replace
from hashlib import sha1
from io import BytesIO
from pathlib import Path
import json
import socket
import subprocess
import sys
import time
import unittest
from unittest.mock import patch
from PIL import Image, PngImagePlugin

import test_request_executor as fixture
import github_backend as gb
import authority_coordinator as d3
import request_executor as executor
import privacy_gate
from importer import data, parse, digest, external
from git_transport import git, value, files, Session, MAIN, WITNESS

WORK = None
COMMON = None
COUNTS = {"network_attempts":0,"nonlocal_git_attempts":0,"fake_cas_calls":0}
SECRET = b"E4I_PRIVATE_RAW_METADATA_SENTINEL"
PRIVATE_NAME = "owner-private-name.png"
ROWS = []


def no_network(*args, **kwargs):
    COUNTS["network_attempts"] += 1
    raise AssertionError("NETWORK_FORBIDDEN")


def checked_run(original):
    def run(command, *args, **kwargs):
        root = WORK/"lab"
        local = (isinstance(command,list) and command[0]=="git" and "-C" in command and
                 Path(command[command.index("-C")+1]).absolute().is_relative_to(root))
        after = command[command.index("-C")+2:] if local else []
        transport = ("protocol.allow=never" in command and "protocol.file.allow=always" in command)
        # Existing history_guard is local read-only, with no transport operation.
        history_read = (command[:3]==["git","--no-optional-locks","-C"] and after and
                        after[0] in ("rev-parse","log","show","rev-list"))
        ok = local and (transport or history_read)
        if not ok or any(str(x).startswith(("https:","http:","ssh:","git://","git@")) for x in command):
            COUNTS["nonlocal_git_attempts"] += 1
            raise AssertionError("ONLY_GUARDED_LAB_GIT_ALLOWED")
        return original(command, *args, **kwargs)
    return run


def raw_png(number):
    out=BytesIO();meta=PngImagePlugin.PngInfo()
    meta.add_text("Comment",SECRET.decode())
    Image.new("RGB",(13,11),(number,110,220)).save(out,"PNG",pnginfo=meta)
    raw=out.getvalue();clean=privacy_gate.prepare(raw,".png")
    assert clean.evidence["status"]=="SANITIZED_AND_VERIFIED" and SECRET not in clean.output
    return raw,clean.output


def object_pin(repo, raw):
    oid=value(repo,"hash-object","-w","--stdin",stdin=raw)
    return gb.ObjectPin(oid,digest(raw),len(raw))


class Reader:
    def __init__(self, template, private, actor):
        self.t,self.private,self.actor=template,private,actor
        self.unavailable=False;self.stale=False;self.wrong_repo=False
        self.missing_object=None
        self.calls=0

    def session(self):
        now=int(time.time())
        grants={(123,"read")} if self.private else {(202,"read"),(303,"read")}
        return gb.SessionIdentity(self.actor,self.t.code,frozenset(grants),now,now+60)

    def repository(self, rid):
        if self.unavailable:raise RuntimeError(SECRET.decode())
        p={123:gb.RepoPin("intake",123,*gb.NAMES["intake"]),
           202:gb.RepoPin("assets",202,*gb.NAMES["assets"]),
           303:gb.RepoPin("control",303,*gb.NAMES["control"])}[rid]
        return replace(p,numeric_id=999) if self.wrong_repo else p

    def repo(self, rid):
        return {123:self.t.raw_repo,202:self.t.c["primary"],303:self.t.c["anchor"]}[rid]

    def ref(self, rid, ref):
        self.calls+=1
        if self.unavailable:raise RuntimeError(SECRET.decode())
        if self.stale and rid==202 and ref==MAIN:return "0"*40
        # E4H's future ledger name -> exact existing Lab/D3 main, no writes.
        physical=MAIN if rid==303 and ref=="refs/heads/automation-ledger" else ref
        return value(self.repo(rid),"rev-parse",physical)

    def git_object(self, rid, oid):
        if self.missing_object==oid:raise KeyError("MISSING_SYNTHETIC_OBJECT")
        key=(str(self.repo(rid)),oid)
        if key not in self.t.cache:
            kind=value(self.repo(rid),"cat-file","-t",oid)
            self.t.cache[key]=gb.GitObject(kind,git(self.repo(rid),"cat-file",kind,oid).stdout)
        return self.t.cache[key]

    def asset(self, *args):
        raise AssertionError("NO_FAKE_RECOVERY_ACCEPTANCE")


class Verifier:
    def __init__(self,t):
        self.t=t;self.unavailable=False
    def session(self):
        now=int(time.time())
        return gb.SessionIdentity(13,self.t.verifier_code,frozenset({(123,"verify")}),now,now+60)
    def derivation(self,proof):
        if self.unavailable:raise RuntimeError(SECRET.decode())
        record,raw,expected=self.t.proofs[proof]
        # Actual accepted E4C inspection/independent decode, not a new sanitizer.
        result=privacy_gate.prepare(raw,".png",record.role)
        assert result.evidence["status"]=="SANITIZED_AND_VERIFIED" and result.output==expected
        return record


class Quota:
    def __init__(self):
        self.exhausted=False
    def observation(self,account):
        now=int(time.time())
        return gb.QuotaObservation(account,now,now+60,"Free",
            (("private_minutes",0 if self.exhausted else 100),
             ("storage_bytes",1_000_000)),frozenset({"private_minutes","storage_bytes"}),0,False)


class NoWriter:
    def __init__(self,t):self.t=t
    def session(self):
        now=int(time.time())
        return gb.SessionIdentity(14,self.t.code,frozenset({(303,"cas")}),now,now+60)
    def capabilities(self):return frozenset({"single_ref_cas_simulated"})
    def compare_and_swap(self,*args):
        COUNTS["fake_cas_calls"]+=1
        raise AssertionError("FAKE_CAS_MUST_NOT_REPLACE_D1_ATOMIC")


class Template:
    def __init__(self,label):
        self.c=fixture.fixture(label);self.cache={};self.proofs={}
        self.raw_original,self.original=raw_png(211)
        self.raw_og,self.og=raw_png(201)
        self.txt=b"\xef\xbb\xbfIntentional owner prose: name@example.test.\r\nSecond line.\r\n"
        self.target="incoming/replace/kolaji/00001/replacement.png"
        self.raw_target="incoming/replace/kolaji/00001/"+PRIVATE_NAME
        self.txt_path=fixture.ROOT+fixture.KEY+".txt"
        self.og_path=fixture.ROOT+"og.png"
        def transform(view):
            view[self.target]=self.original
            view[self.txt_path]=self.txt
            view[self.og_path]=self.og
        self.q=fixture.request(self.c,transform)
        self.operation=executor.RequestOperation(fixture.LAB,**self.q,interrupt=lambda p:None)
        self.context=fixture.domain(self.c).read()
        root=self.c["primary"].parent
        self.raw_repo=root/"PRIVATE-raw.git";self.raw_repo.mkdir()
        git(self.raw_repo,"init","--bare","--initial-branch=main")
        old=files(self.q["source"],self.q["before"]["commit"],executor.EDITABLE)
        raw_old=fixture.put_commit(self.raw_repo,old)
        raw_new=dict(old);raw_new[self.raw_target]=self.raw_original
        raw_new[self.txt_path]=self.txt;raw_new[self.og_path]=self.raw_og
        raw_commit=fixture.put_commit(self.raw_repo,raw_new,raw_old)
        # Trusted code OIDs are actual objects in this same synthetic control repo.
        anchor=self.c["anchor"];tree=value(anchor,"mktree",stdin=b"")
        self.code=value(anchor,"commit-tree",tree,"-m","E4I synthetic trusted code")
        self.verifier_code=value(anchor,"commit-tree",tree,"-m","E4I synthetic verifier code")
        git(anchor,"update-ref","refs/heads/automation-control",self.code)
        git(anchor,"update-ref","refs/heads/verification-code",self.verifier_code)
        owner=digest(data({"repository_id":123,"source":raw_commit,"parent":raw_old}))
        items=[]
        for dest,source,raw,output,role in [
            (self.target,self.raw_target,self.raw_original,self.original,"original"),
            (self.txt_path,self.txt_path,self.txt,self.txt,"txt"),
            (self.og_path,self.og_path,self.raw_og,self.og,"og")]:
            raw_pin=object_pin(self.raw_repo,raw);out_pin=object_pin(self.raw_repo,output)
            proof_sha=None
            if role!="txt":
                proof=gb.Derivation(owner,raw_commit,raw_pin,out_pin,role,privacy_gate.POLICY,
                     "SANITIZED_AND_VERIFIED",13,self.verifier_code)
                proof_sha=digest(data(asdict(proof)));self.proofs[proof_sha]=(proof,raw,output)
            items.append(d3.DerivedFile(dest,source,raw_pin,out_pin,role,proof_sha))
        self.binding=d3.SourceBinding(owner,raw_commit,raw_old,self.q["source"],
            self.q["change"]["commit"],self.q["before"]["commit"],self.operation.request,tuple(items))
        self.policy=gb.Policy((gb.RepoPin("intake",123,*gb.NAMES["intake"]),
            gb.RepoPin("assets",202,*gb.NAMES["assets"]),gb.RepoPin("control",303,*gb.NAMES["control"])),
            (("private_read",11),("public_read",12),("independent_verify",13),("control_write",14)),
            self.code,self.verifier_code,self.c["library_id"],404,
            (("private_minutes",10),("storage_bytes",1000)))

    def ports(self,**options):
        private,public=Reader(self,True,11),Reader(self,False,12)
        verifier,quota,writer=Verifier(self),Quota(),NoWriter(self)
        backend=gb.Backend(self.policy,gb.OfflinePorts(private,public,verifier,writer,quota))
        result=d3.trusted_local_ports(fixture.LAB,**self.c,backend=backend,binding=self.binding,
                                     demand={"private_minutes":5,"storage_bytes":1000},**options)
        return result,private,public,verifier,quota

    def execute(self,ports,interrupt=None):
        q=dict(self.q);q["evidence"]=replace(q["evidence"],assessment_time=int(time.time()))
        return executor.run_local_request(fixture.LAB,**self.c,**q,integration=ports,
                                          interrupt=interrupt,max_steps=12)


class Tests(unittest.TestCase):
    def setUp(self):
        self.t=COMMON
        self.ports,self.private,self.public,self.verifier,self.quota=self.t.ports()
        self.before=fixture.fingerprint(self.t.c)

    def tearDown(self):
        self.assertEqual(self.before,fixture.fingerprint(self.t.c))
        self.assertEqual(COUNTS,{"network_attempts":0,"nonlocal_git_attempts":0,"fake_cas_calls":0})

    def gate_reject(self,code,ports=None,context=None):
        with self.assertRaises((d3.PortStop,d3.Reject)) as caught:
            (ports or self.ports).gate(context or self.t.context,self.t.operation)
        self.assertEqual(str(caught.exception),code)

    def test_01_existing_local_default(self):
        result=d3.run_local(fixture.LAB,**self.t.c)
        self.assertEqual(result["status"],"ALREADY_PROCESSED",result)
        self.assertTrue(result["projection_eligible"])

    def test_02_real_factory_selection(self):
        coordinator=d3.Coordinator(fixture.LAB,**self.t.c,operation=self.t.operation,integration=self.ports)
        self.assertIs(type(coordinator.domain),d3.LocalWitness)
        session=self.ports.session(fixture.LAB,self.t.c["primary"],self.t.c["primary_genesis"])
        self.assertIs(type(session),Session)
        self.assertIs(self.ports.domain_factory,d3.LocalWitness)
        self.assertIs(self.ports.session_factory,Session)
        self.ports.gate(self.t.context,self.t.operation)

    def test_03_reject_owner_data_substitution(self):
        result=self.t.execute({"verified":True,"domain":self.t.context})
        self.assertEqual(result["reason"],"UNTRUSTED_D3_PORTS",result)
        self.assertFalse(result["projection_eligible"])

    def test_04_reject_unapproved_factory(self):
        illegal=replace(self.ports,domain_factory=lambda *a:object())
        with self.assertRaisesRegex(d3.Reject,"UNTRUSTED_D3_FACTORY"):
            d3.Coordinator(fixture.LAB,**self.t.c,operation=self.t.operation,integration=illegal)

    def test_05_exact_request_and_derived_source_binding(self):
        b=replace(self.ports.binding,derived_source="0"*40)
        self.gate_reject("REQUEST_SOURCE_BINDING_MISMATCH",replace(self.ports,binding=b))
        b=replace(self.ports.binding,derived_request_sha256="0"*64)
        self.gate_reject("REQUEST_SOURCE_BINDING_MISMATCH",replace(self.ports,binding=b))

    def test_06_wrong_raw_source_not_derived_fallback(self):
        b=replace(self.ports.binding,raw_source="0"*40)
        self.gate_reject("SOURCE_IDENTITY",replace(self.ports,binding=b))

    def test_07_missing_changed_output_proof(self):
        b=replace(self.ports.binding,files=self.ports.binding.files[:-1])
        self.gate_reject("DERIVED_MANIFEST_BINDING_MISMATCH",replace(self.ports,binding=b))

    def test_08_raw_output_substitution_rejects(self):
        fs=list(self.ports.binding.files);fs[0]=replace(fs[0],output=fs[0].raw)
        b=replace(self.ports.binding,files=tuple(fs))
        self.gate_reject("DERIVATION_IDENTITY",replace(self.ports,binding=b))

    def test_09_stale_authority_provider_state(self):
        self.public.stale=True
        self.gate_reject("STALE_STATE")

    def test_10_missing_provider_evidence(self):
        self.public.missing_object=self.t.context["tip"]
        self.gate_reject("PROVIDER_UNAVAILABLE")

    def test_11_context_cannot_substitute_independent_record(self):
        context=dict(self.t.context);context["latest"]=dict(context["latest"])
        context["latest"]["index"]+=1
        self.gate_reject("INDEPENDENT_EVIDENCE",context=context)

    def test_12_unresolved_provider_no_mutation_retry(self):
        self.private.unavailable=True
        result=self.t.execute(self.ports)
        self.assertEqual((result["status"],result["reason"]),("UNRESOLVED","PROVIDER_UNAVAILABLE"),result)
        self.assertFalse(result["projection_eligible"])
        log=repr(result)+json.dumps(result)
        self.assertNotIn(SECRET.decode(),log)

    def test_13_boolean_provider_admission_not_authority(self):
        self.ports.backend.admit=lambda *a:{"verified":True}
        self.gate_reject("UNTRUSTED_PROVIDER_RESULT")

    def test_14_quota_suspend_is_not_durable(self):
        self.quota.exhausted=True
        result=self.t.execute(self.ports)
        self.assertEqual(result["status"],"SUSPENDED_FREE_QUOTA",result)
        self.assertFalse(result["projection_eligible"])
        self.assertFalse(result["whole_request_verified"])

    def test_15_explicit_provider_mode_no_atomic_fallback(self):
        ports,*_=self.t.ports(mode="PROVIDER_REQUIRED")
        result=self.t.execute(ports)
        self.assertEqual((result["status"],result["reason"]),("UNSUPPORTED","NATIVE_ATOMIC_UNSUPPORTED"),result)
        self.assertFalse(result["projection_eligible"])

    def test_16_independent_scope_is_required(self):
        with self.assertRaisesRegex(d3.Reject,"D3_PORT_SCOPE_MISMATCH"):
            self.ports.validate(fixture.LAB,self.t.c["primary"],self.t.c["primary"],
                self.t.c["archives"],self.t.c["genesis"],self.t.c["library_id"],self.t.c["primary_genesis"])

    def test_17_trusted_policy_not_request_mutable(self):
        self.ports.backend.policy=replace(self.ports.backend.policy,code_oid="0"*40)
        self.gate_reject("TRUSTED_POLICY_CHANGED")

    def test_18_genuine_missing_independent_backup(self):
        t=Template("missing-independent")
        ports,*_=t.ports()
        record=fixture.latest(t.c);p=t.c["archives"]/record["backup"]["file"]
        p.rename(p.with_suffix(".quarantined"))
        before=fixture.fingerprint(t.c)
        result=t.execute(ports)
        self.assertEqual(result["status"],"REJECTED_BACKUP",result)
        self.assertIn("LATEST_BACKUP_MISSING",result["reason"])
        self.assertFalse(result["projection_eligible"])
        self.assertEqual(before,fixture.fingerprint(t.c))

    def test_19_full_existing_d3_executor_recovery_with_boundary(self):
        t=Template("genuine-integration")
        ports,private,public,verifier,quota=t.ports()
        baseline=fixture.fingerprint(t.c);old=deepcopy(t.q["before"]["registry"])
        base_record=fixture.latest(t.c)
        # Genuine candidate + genuine independent backup, but provider becomes
        # unresolved BEFORE append. Coordinator returns; no blind retry/accept.
        def unavailable(point):
            if point=="after-backup-before-acceptance":private.unavailable=True
        first=t.execute(ports,unavailable)
        self.assertEqual(first["status"],"UNRESOLVED",first)
        self.assertEqual(baseline,fixture.fingerprint(t.c))
        self.assertFalse(first["projection_eligible"])
        private.unavailable=False
        # Resume from fresh independent truth, then interrupt after replacement.
        def after_replace(point):
            if point=="after-accepted-replacement":raise d3.Interrupted(point)
        partial=t.execute(ports,after_replace)
        self.assertEqual(partial["status"],"RECOVERABLE_INTERRUPTION",partial)
        self.assertFalse(partial["projection_eligible"])
        mid=fixture.fingerprint(t.c)
        self.assertEqual(fixture.state(t.c)["items"][fixture.KEY]["desired_revision"],2)
        quota.exhausted=True
        suspended=t.execute(ports)
        self.assertEqual(suspended["status"],"SUSPENDED_FREE_QUOTA",suspended)
        self.assertEqual(mid,fixture.fingerprint(t.c))
        self.assertFalse(suspended["whole_request_verified"])
        # A FINAL core state is still ineligible when provider admission fails
        # immediately before the mandatory whole-request verification.
        quota.exhausted=False
        def before_final(point):
            if point=="before-final-request-verification":quota.exhausted=True
        almost=t.execute(ports,before_final)
        self.assertEqual(almost["status"],"SUSPENDED_FREE_QUOTA",almost)
        self.assertFalse(almost["projection_eligible"])
        self.assertFalse(almost["whole_request_verified"])
        final_refs=fixture.fingerprint(t.c)
        quota.exhausted=False
        final=t.execute(ports)
        self.assertEqual(final["status"],"REQUEST_VERIFIED_FINAL",final)
        self.assertTrue(final["whole_request_verified"])
        self.assertTrue(final["projection_eligible"])  # LOCAL final projection only.
        self.assertFalse(final["publication_authorized"])
        self.assertEqual(final_refs,fixture.fingerprint(t.c))
        repeated=t.execute(ports)
        self.assertEqual(repeated["status"],"REQUEST_VERIFIED_FINAL",repeated)
        self.assertEqual(final_refs,fixture.fingerprint(t.c))
        reg=fixture.state(t.c);item=reg["items"][fixture.KEY]
        self.assertEqual(reg["counters"],old["counters"])
        self.assertEqual(item["desired_revision"],2)
        self.assertEqual(item["id"],old["items"][fixture.KEY]["id"])
        self.assertEqual(item["page_url"],old["items"][fixture.KEY]["page_url"])
        self.assertEqual(item["slideshow"],old["items"][fixture.KEY]["slideshow"])
        self.assertEqual(item["revisions"][:1],old["items"][fixture.KEY]["revisions"])
        self.assertEqual(item["description"],t.txt.decode("utf-8-sig").strip())
        self.assertEqual(item["og"]["sha256"],digest(t.og))
        self.assertEqual(fixture.latest(t.c)["index"],base_record["index"]+3)
        # Full genuine D3 read verifies the actual existing backup/history chain.
        context=fixture.domain(t.c).read()
        accepted=files(context["recovered"],context["latest"]["primary_main"])
        self.assertTrue(all(SECRET not in b and PRIVATE_NAME.encode() not in b for b in accepted.values()))
        self.assertNotEqual(t.binding.owner_request_sha256,t.binding.derived_request_sha256)
        self.assertNotEqual(t.binding.raw_source,t.binding.derived_source)
        self.assertNotEqual(t.binding.files[0].raw.sha256,t.binding.files[0].output.sha256)
        evidence={"request_identities_distinct":True,"raw_source_distinct":True,
            "raw_metadata_absent_from_authority":True,"new_independent_records":3,
            "substep_revision":2,"counters_preserved":True,"fake_cas_calls":COUNTS["fake_cas_calls"],
            "invocations":[x["status"] for x in (first,partial,suspended,almost,final,repeated)],
            "final_refs":list(final_refs),"final_registry_sha256":digest(data(reg)),
            "d3_evidence_path":final["evidence_path"],"live_activation":False,
            "publication_authorized":False,"durable_cloud_suspension":False}
        (WORK/"integration-evidence.json").write_bytes(data(evidence))

    def test_20_network_guards_and_original_backend_capability(self):
        self.assertEqual(self.ports.backend.atomic_authority_update().status,"UNSUPPORTED")
        self.assertEqual(COUNTS,{"network_attempts":0,"nonlocal_git_attempts":0,"fake_cas_calls":0})


class Recorder(unittest.TextTestResult):
    def startTest(self,test):
        super().startTest(test);print("START "+test.id(),flush=True)
    def save(self):
        (WORK/"results.json").write_bytes(data(ROWS))
    def addSuccess(self,test):
        super().addSuccess(test);ROWS.append({"test":test.id(),"status":"PASS"})
        self.save();print("PASS "+test.id(),flush=True)
    def addFailure(self,test,err):
        super().addFailure(test,err);ROWS.append({"test":test.id(),"status":"FAIL",
                                                "traceback":self._exc_info_to_string(err,test)})
        self.save()
    def addError(self,test,err):
        super().addError(test,err);ROWS.append({"test":test.id(),"status":"ERROR",
                                              "traceback":self._exc_info_to_string(err,test)})
        self.save()


def main():
    global WORK,COMMON
    parser=argparse.ArgumentParser();parser.add_argument("--work",type=Path,required=True)
    parser.add_argument("--only")
    args=parser.parse_args();WORK=external(args.work)
    if WORK.exists():raise RuntimeError("NEW_EXTERNAL_WORK_REQUIRED")
    WORK.mkdir(parents=True)
    source={n:digest((Path(__file__).parent/n).read_bytes()) for n in
            ("authority_coordinator.py","git_transport.py","request_executor.py",
             "github_backend.py","test_d3_domain_adapter.py")}
    started=time.perf_counter();original=subprocess.run
    fixture.WORK=WORK
    with patch.object(socket,"socket",no_network),patch.object(socket,"create_connection",no_network), \
         patch.object(subprocess,"run",checked_run(original)):
        fixture.initialize()
        COMMON=Template("shared-immutable")
        suite=unittest.defaultTestLoader.loadTestsFromTestCase(Tests)
        if args.only:
            names=args.only.split(",");suite=unittest.TestSuite(t for t in suite if any(x in t.id() for x in names))
        with (WORK/"tests.log").open("w",encoding="utf8") as log:
            result=unittest.TextTestRunner(stream=log,verbosity=2,resultclass=Recorder).run(suite)
    summary={"tests":result.testsRun,"pass":result.testsRun-len(result.failures)-len(result.errors),
        "fail":len(result.failures),"errors":len(result.errors),"seconds":time.perf_counter()-started,
        "source_sha256":source,"provider":"OFFLINE_LOCAL_GIT_VIEW","genuine_local_d3":True,
        "network_attempts":COUNTS["network_attempts"],"nonlocal_git_attempts":COUNTS["nonlocal_git_attempts"],
        "fake_cas_calls":COUNTS["fake_cas_calls"],"hosted_runs":0,"live_activation":False,
        "durable_cloud_suspension":False,"fictitious_bootstrap_fixture":True}
    (WORK/"summary.json").write_bytes(data(summary));print(json.dumps(summary),flush=True)
    return 0 if result.wasSuccessful() else 1


if __name__=="__main__":
    sys.exit(main())
