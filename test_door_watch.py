# /// script
# requires-python = ">=3.10"
# dependencies = ["cbor2==6.1.5", "cryptography==50.0.2", "tuf==7.0.1", "securesystemslib==1.6.0", "urllib3==2.8.0"]
# ///
"""Tests check-door.py's --verdict against the fixtures in check_door_fixtures.py, and door_watch.py's retries, streak
and alerts against a stand-in for check-door.py that replays a script of runs. It reads nothing from the network.

Usage: uv run test_door_watch.py
"""

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
import unittest.mock
import urllib.error
from dataclasses import dataclass
from pathlib import Path

sys.dont_write_bytecode = True
from check_door_fixtures import *  # noqa: E402,F403
import door_watch  # noqa: E402

RUN_URL = "https://example.test/run"
FAILED = "2 certificates in CT cover inference.trymorse.ai.\n\nmorse-records is public (check 9)\n  FAIL: https://api.github.com/repos/trymorse/morse-records, read with no token, answers 404\n"
UNREAD = "FAIL: could not read the evidence: <HTTPError 502: 'Bad Gateway'>\n"
PASSED = "0 certificates in CT cover inference.trymorse.ai.\n\nmorse-records is public (check 9)\n  OK\n"
GAP = "Every boot this watcher saw the door's live attestation list has a verified record of each key it held, 2 hours after it first saw it (check 6)\n  NOT ENFORCED: check 6 not enforced on this run\n"
SIGNER = "Only the publisher pushes data to morse-pins main (check 7)\n  NOT ENFORCED: check 7 not enforced on this run: sign.yml's runs could not be read\n"


BAD_GATEWAY = "<HTTPError 502: 'Bad Gateway'>"
BOTH_READ = {"crt.sh": None, "certspotter": None}
CRTSH_DOWN = {"crt.sh": BAD_GATEWAY, "certspotter": None}


def verdict(kind, unenforced=(), failed=(), ct=None, hosts=(), checks=()):
    code = {"passed": 0, "failed": 1, "unenforced": 2, "unread": 1}[kind]
    ct = {} if kind == "unread" else BOTH_READ if ct is None else ct
    return {"kind": kind, "exit": code, "retryable": kind == "unread", "failed": list(failed), "unenforced": list(unenforced), "checks": list(checks), "ct": ct, "hosts": list(hosts)}


def passed(ct=None):
    return {"code": 0, "output": PASSED, "verdict": verdict("passed", ct=ct)}


def failed(*checks):
    checks = checks or (1,)
    first = ("inference.trymorse.ai",) if 1 in checks else ()
    messages = [{"check": 1, "messages": [{"level": "FAIL", "text": "a rogue certificate", "hosts": list(first)}]}] if first else []
    return {"code": 1, "output": FAILED, "verdict": verdict("failed", failed=checks, hosts=first, checks=messages)}


def unread():
    return {"code": 1, "output": UNREAD, "verdict": verdict("unread")}


def unenforced(*checks, output=GAP):
    return {"code": 2, "output": output, "verdict": verdict("unenforced", checks)}


def crashed():
    return {"code": 1, "output": "Traceback (most recent call last):\nModuleNotFoundError: No module named 'cbor2'\n", "verdict": None}


STAND_IN = """import json, sys
from pathlib import Path
script = Path(sys.argv[1])
runs = json.loads(script.read_text())
run = runs.pop(0)
script.write_text(json.dumps(runs))
if run["verdict"] is not None:
    Path(sys.argv[sys.argv.index("--verdict") + 1]).write_text(json.dumps(run["verdict"]))
sys.stdout.write(run["output"])
sys.exit(run["code"])
"""


@dataclass
class Watched:
    code: int
    stdout: str
    alert: str
    label: str
    title: str
    hours: str
    body: str
    summary: str
    slept: list
    ct_alert: str
    ct_title: str
    ct_body: str
    outputs: dict


class Watcher:
    def __init__(self, root):
        self.root = Path(root)
        (self.root / "stand_in.py").write_text(STAND_IN)

    def run(self, *attempts, alerts=True, restored=True, setup=None, sent=True):
        (self.root / "script.json").write_text(json.dumps(list(attempts)))
        for name in ("outputs", "summary", "alert.md", "ct-alert.md"):
            (self.root / name).unlink(missing_ok=True)
        argv = ["--state", str(self.root / "door-state"), "--run-url", RUN_URL, "--alert-body", str(self.root / "alert.md"), "--ct-alert-body", str(self.root / "ct-alert.md")]
        argv += ["--alerts"] if alerts else []
        argv += ["--restored", "door-watch-1-1"] if restored else []
        if setup is not None:
            (self.root / "setup.txt").write_text(setup[1])
            argv += ["--setup-code", str(setup[0]), "--setup-log", str(self.root / "setup.txt")]
        argv += ["--", sys.executable, "-B", str(self.root / "stand_in.py"), str(self.root / "script.json")]
        out, slept = io.StringIO(), []
        env = {"GITHUB_OUTPUT": str(self.root / "outputs"), "GITHUB_STEP_SUMMARY": str(self.root / "summary")}
        with contextlib.redirect_stdout(out), unittest.mock.patch.dict(os.environ, env), unittest.mock.patch.object(door_watch.time, "sleep", slept.append):
            code = door_watch.main(argv)
        left = json.loads((self.root / "script.json").read_text())
        if left and setup is None:
            raise AssertionError(f"door_watch.py left {len(left)} attempts unrun")
        outputs = dict(line.split("=", 1) for line in self.read("outputs").splitlines())
        if sent and outputs.get("ct_alert"):
            streaks = json.loads(self.read("door-state/ct-streak"))
            for source in outputs["ct_alert"].split(","):
                streaks[source]["alerted"] = True
            (self.root / "door-state" / "ct-streak").write_text(json.dumps(streaks))
        return Watched(code, out.getvalue(), outputs.get("alert", ""), outputs.get("label", ""), outputs.get("title", ""), outputs.get("hours", ""),
                       self.read("alert.md"), self.read("summary"), slept, outputs.get("ct_alert", ""), outputs.get("ct_title", ""), self.read("ct-alert.md"), outputs)

    def read(self, name):
        path = self.root / name
        return path.read_text() if path.exists() else ""


class WatchTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.watcher = Watcher(self.tmp.name)

    def runs(self, *runs, **kwargs):
        return [self.watcher.run(*(r if isinstance(r, list) else [r]), **kwargs) for r in runs]

    def test_without_alerts_no_run_alerts_or_fails(self):
        for w in self.runs(failed(), [unread()] * 3, [unread()] * 3, [unread()] * 3, unenforced(6), crashed(), alerts=False, restored=False):
            self.assertEqual((w.code, w.alert, w.body), (0, "", ""))
            self.assertIn("run(s) in a row", w.summary)
        self.assertEqual(self.watcher.read("door-state/streak"), "unread 1\n")

    def test_a_failed_check_alerts_at_once_under_its_own_label(self):
        w = self.watcher.run(failed())
        self.assertEqual((w.code, w.alert, w.label, w.hours, w.title), (1, "failed", "door-watch-failed", "0", "The inference door's watcher failed a check for inference.trymorse.ai"))
        self.assertEqual(w.body, f"check-door.py exited 1 and failed check 1. A certificate for inference.trymorse.ai whose key no verified record attests can be a rogue certificate: read check 1 first, in {RUN_URL}\n\n```\n{FAILED}```\n")

    def test_a_failed_check_6_alone_points_at_check_6_not_check_1(self):
        w = self.watcher.run(failed(6))
        self.assertEqual((w.code, w.alert, w.label), (1, "failed", "door-watch-failed"))
        self.assertIn("check-door.py exited 1 and failed check 6. Check 6 failing usually means /v1/attestation listed a boot that has no verified record", w.body)
        self.assertIn("The FAIL lines below give the cause", w.body)
        self.assertIn("A boot that died before it could log its record never will", w.body)
        self.assertNotIn("check 1", w.body)

    def test_a_run_failing_checks_1_and_6_names_both_and_check_1_first(self):
        w = self.watcher.run(failed(6, 1))
        self.assertIn("failed check 1, check 6. A certificate", w.body)
        self.assertLess(w.body.index("read check 1 first"), w.body.index("Check 6 failing usually means"))

    def test_a_failed_check_outranks_lost_state_and_says_the_state_was_lost(self):
        w = self.watcher.run(failed(), restored=False)
        self.assertEqual((w.code, w.alert, w.label, w.hours), (1, "failed", "door-watch-failed", "0"))
        self.assertIn(f"read check 1 first. It also {door_watch.LOST}, in {RUN_URL}", w.body)

    def test_a_run_with_no_kept_state_alerts_lost_whatever_it_found(self):
        for attempts, exited, code in (([passed()], 0, 0), ([unread()] * 3, 1, 1), ([unenforced(6)], 2, 0), ([crashed()], 1, 1)):
            w = self.watcher.run(*attempts, restored=False)
            self.assertEqual((w.code, w.alert, w.label, w.hours, w.title), (code, "lost", "door-watch", "1", "The inference door's watcher lost its kept state"))
            self.assertEqual(w.body, f"check-door.py exited {exited} and {door_watch.LOST}, in {RUN_URL}\n\n```\n{attempts[-1]['output']}```\n")

    def test_a_run_that_could_not_read_its_evidence_alerts_on_the_third_in_a_row(self):
        ways = {"the evidence": [unread()] * 3, "a crash with no verdict": crashed(), "an exit code the verdict does not give": {**passed(), "code": 1},
                "a clone that failed": None}
        for name, run in ways.items():
            with self.subTest(name):
                self.watcher = Watcher(tempfile.mkdtemp(dir=self.tmp.name))
                setup = (128, "fatal: repository not found\n") if run is None else None
                runs = [self.watcher.run(*(run if isinstance(run, list) else [run] if run else []), setup=setup) for _ in range(4)]
                self.assertEqual([(w.code, w.alert) for w in runs], [(1, ""), (1, ""), (1, "unread"), (1, "unread")])
                self.assertEqual((runs[2].label, runs[2].hours, runs[2].title), ("door-watch", "1", "The inference door's watcher could not read its evidence"))
                self.assertIn("could not read its evidence on three runs in a row, so it checked nothing for about 15 minutes, in " + RUN_URL, runs[2].body)
        self.assertIn("fatal: repository not found", runs[2].body)
        self.assertTrue(runs[2].body.startswith("check-door.py exited 128 and"))

    def test_a_check_left_unenforced_alerts_on_the_third_in_a_row_and_names_it(self):
        cases = {"check 7": ((7,), SIGNER, "check 7", False), "check 6": ((6,), GAP, "check 6", True), "checks 6 and 7": ((6, 7), GAP + SIGNER, "check 6, check 7", True)}
        for name, (checks, output, named, event_bridge) in cases.items():
            with self.subTest(name):
                self.watcher = Watcher(tempfile.mkdtemp(dir=self.tmp.name))
                runs = self.runs(*[unenforced(*checks, output=output)] * 3)
                self.assertEqual([(w.code, w.alert) for w in runs], [(0, ""), (0, ""), (0, "unenforced")])
                self.assertEqual((runs[2].label, runs[2].hours, runs[2].title), ("door-watch", "1", f"The inference door's watcher has not enforced {named}"))
                self.assertIn(f"exited 2 and left {named} unenforced on three runs in a row, as its NOT ENFORCED lines say", runs[2].body)
                self.assertEqual("EventBridge's ClockEvery5Minutes" in runs[2].body, event_bridge)
                self.assertIn(output, runs[2].body)

    def test_a_passing_run_restarts_the_streak(self):
        runs = self.runs([unread()] * 3, [unread()] * 3, passed(), [unread()] * 3, [unread()] * 3)
        self.assertEqual([w.alert for w in runs], [""] * 5)
        self.assertEqual(runs[2].code, 0)

    def test_a_run_of_another_kind_restarts_the_streak(self):
        runs = self.runs([unread()] * 3, [unread()] * 3, unenforced(6), unenforced(6))
        self.assertEqual([w.alert for w in runs], [""] * 4)
        self.assertEqual(self.watcher.read("door-state/streak"), "unenforced 2\n")

    def test_a_streak_an_earlier_run_kept_counts_toward_the_alert(self):
        (self.watcher.root / "door-state").mkdir()
        (self.watcher.root / "door-state" / "streak").write_text("unread 2\n")
        self.assertEqual(self.watcher.run(*[unread()] * 3).alert, "unread")

    def test_a_run_that_could_not_read_its_evidence_tries_twice_more_20_seconds_apart(self):
        w = self.watcher.run(unread(), unread(), passed())
        self.assertEqual((w.code, w.alert, w.slept), (0, "", [20, 20]))
        self.assertEqual(w.stdout, f"attempt 1: {UNREAD.strip()}\nattempt 2: {UNREAD.strip()}\n{PASSED}")
        self.assertNotIn("attempt", w.summary)
        w = self.watcher.run(unread(), unread(), unread())
        self.assertEqual(w.slept, [20, 20])
        self.assertIn(f"attempt 3: {UNREAD.strip()}\n{UNREAD}", w.stdout)

    def test_only_a_run_that_could_not_read_its_evidence_is_tried_again(self):
        for run in (failed(), unenforced(6), crashed(), passed()):
            self.assertEqual(self.watcher.run(run).slept, [])

    def crtsh_down(self, runs, **kwargs):
        return self.runs(*[passed(CRTSH_DOWN)] * runs, **kwargs)

    def test_a_ct_source_down_on_fewer_runs_in_a_row_than_the_threshold_alerts_no_one(self):
        runs = self.crtsh_down(door_watch.CT_ALERT_AFTER - 1)
        self.assertEqual({(w.code, w.alert, w.ct_alert, w.ct_body) for w in runs}, {(0, "", "", "")})
        self.assertIn(f"crt.sh could not be read or parsed for at least one of the door's names on {door_watch.CT_ALERT_AFTER - 1} run(s) in a row.", runs[-1].summary)

    def test_a_ct_source_down_on_the_threshold_alerts_once_under_its_own_label(self):
        runs = self.crtsh_down(door_watch.CT_ALERT_AFTER + 5)
        self.assertEqual([i for i, w in enumerate(runs, 1) if w.ct_alert], [door_watch.CT_ALERT_AFTER])
        w = runs[door_watch.CT_ALERT_AFTER - 1]
        self.assertEqual((w.code, w.alert, w.ct_alert, w.ct_title), (0, "", "crt.sh", f"The inference door's watcher could not read crt.sh on {door_watch.CT_ALERT_AFTER} or more runs in a row"))
        since = json.loads(self.watcher.read("door-state/ct-streak"))["crt.sh"]["since"]
        self.assertTrue(w.ct_body.startswith(f"crt.sh could not be read on {door_watch.CT_ALERT_AFTER} door-watch runs in a row, since {since}, and on the last of those runs certspotter could be read. "), w.ct_body)
        self.assertIn(f"Its last error: {BAD_GATEWAY}\n\nThe last of those runs is {RUN_URL}\n\n```\n{PASSED}```\n", w.ct_body)
        self.assertEqual(door_watch.compose_ct({"crt.sh": {"count": door_watch.CT_ALERT_AFTER, "since": since, "why": BAD_GATEWAY}}, door_watch.judge(0, PASSED, verdict("passed", ct=CRTSH_DOWN)), RUN_URL).label, "door-watch-ct")

    def test_a_ct_source_read_for_one_name_and_not_the_other_alternating_counts_on_and_alerts_its_coverage_incomplete(self):
        first, second = "inference.trymorse.ai", "api.morseinference.com"

        def partial(read, unread):
            run = passed(CRTSH_DOWN)
            run["verdict"]["ct_hosts"] = {"crt.sh": {"read": [read], "unread": [unread]}, "certspotter": {"read": [first, second], "unread": []}}
            return run
        runs = self.runs(*[partial(first, second) if i % 2 == 0 else partial(second, first) for i in range(door_watch.CT_ALERT_AFTER)])
        self.assertEqual([i for i, w in enumerate(runs, 1) if w.ct_alert], [door_watch.CT_ALERT_AFTER])
        w = runs[-1]
        self.assertEqual(w.ct_title, f"The inference door's watcher could not read crt.sh for some of the door's names ({second} and {first} missed at least once) on {door_watch.CT_ALERT_AFTER} or more runs in a row")
        self.assertIn(f"crt.sh could not be read or parsed for at least one of the door's names on {door_watch.CT_ALERT_AFTER} door-watch runs in a row", w.ct_body)
        self.assertIn(f"The names it missed at least once are {second} and {first}. crt.sh's coverage of the door was incomplete on those runs, not wholly unavailable", w.ct_body)
        self.assertNotIn("Check 1's coverage", w.ct_body)
        self.assertIn(f"crt.sh could not be read or parsed for at least one of the door's names on {door_watch.CT_ALERT_AFTER} run(s) in a row, missing {second} and {first} at least once.", w.summary)

    def test_a_source_down_for_both_names_while_the_other_covers_one_names_what_each_source_read(self):
        first, second = "inference.trymorse.ai", "api.morseinference.com"
        run = passed(CRTSH_DOWN)
        run["verdict"]["ct_hosts"] = {"crt.sh": {"read": [], "unread": [first, second]}, "certspotter": {"read": [first], "unread": []}}
        w = self.runs(*[run] * door_watch.CT_ALERT_AFTER)[-1]
        self.assertIn(f"door-watch runs in a row, since {json.loads(self.watcher.read('door-state/ct-streak'))['crt.sh']['since']}, and on the last of those runs certspotter read {first}, and no other source read {second}. ", w.ct_body)
        self.assertNotIn("judged", w.ct_body)
        self.assertIn(f"crt.sh could not be read or parsed for at least one of the door's names on {door_watch.CT_ALERT_AFTER} run(s) in a row.", w.summary)

    def test_a_run_that_reads_the_source_restarts_its_count(self):
        runs = self.crtsh_down(door_watch.CT_ALERT_AFTER - 1) + self.runs(passed()) + self.crtsh_down(door_watch.CT_ALERT_AFTER - 1)
        self.assertEqual([w.ct_alert for w in runs if w.ct_alert], [])
        self.assertEqual(json.loads(self.watcher.read("door-state/ct-streak"))["crt.sh"]["count"], door_watch.CT_ALERT_AFTER - 1)
        self.assertEqual(self.crtsh_down(1)[0].ct_alert, "crt.sh")
        later = self.runs(passed()) + self.crtsh_down(door_watch.CT_ALERT_AFTER)
        self.assertEqual([i for i, w in enumerate(later) if w.ct_alert], [door_watch.CT_ALERT_AFTER])

    def test_a_run_that_read_no_evidence_neither_counts_nor_restarts_a_ct_source(self):
        self.crtsh_down(door_watch.CT_ALERT_AFTER - 1)
        runs = self.runs(*[[unread()] * 3] * 4, passed(CRTSH_DOWN), [unread()] * 3)
        self.assertEqual([w.ct_alert for w in runs], ["", "", "", "", "crt.sh", ""])

    def test_a_ct_source_down_on_a_run_that_failed_a_check_still_counts_and_alerts_both(self):
        self.crtsh_down(door_watch.CT_ALERT_AFTER - 1)
        w = self.watcher.run({**failed(), "verdict": verdict("failed", failed=(1,), ct=CRTSH_DOWN)})
        self.assertEqual((w.code, w.alert, w.ct_alert), (1, "failed", "crt.sh"))

    def test_without_alerts_a_ct_source_is_counted_and_alerts_no_one(self):
        runs = self.crtsh_down(door_watch.CT_ALERT_AFTER, alerts=False)
        self.assertEqual({(w.code, w.ct_alert) for w in runs}, {(0, "")})
        self.assertEqual(json.loads(self.watcher.read("door-state/ct-streak"))["crt.sh"]["count"], door_watch.CT_ALERT_AFTER)

    def test_alerts_turned_on_after_the_threshold_alert_on_the_next_run_with_its_count(self):
        self.crtsh_down(door_watch.CT_ALERT_AFTER + 4, alerts=False)
        runs = self.crtsh_down(3)
        self.assertEqual([w.ct_alert for w in runs], ["crt.sh", "", ""])
        self.assertTrue(runs[0].ct_body.startswith(f"crt.sh could not be read on {door_watch.CT_ALERT_AFTER + 5} door-watch runs in a row"), runs[0].ct_body)

    def test_an_alert_that_was_not_sent_is_decided_again_on_the_next_run(self):
        self.crtsh_down(door_watch.CT_ALERT_AFTER - 1)
        runs = self.crtsh_down(2, sent=False) + self.crtsh_down(3)
        self.assertEqual([w.ct_alert for w in runs], ["crt.sh", "crt.sh", "crt.sh", "", ""])

    def test_a_source_that_reads_again_alerts_again_on_its_next_outage(self):
        first = self.crtsh_down(door_watch.CT_ALERT_AFTER + 2)
        later = self.runs(passed()) + self.crtsh_down(door_watch.CT_ALERT_AFTER + 2)
        self.assertEqual(([i for i, w in enumerate(first, 1) if w.ct_alert], [i for i, w in enumerate(later) if w.ct_alert]), ([door_watch.CT_ALERT_AFTER], [door_watch.CT_ALERT_AFTER]))

    def test_a_passing_run_with_its_state_resolves_the_check_alerts_and_one_that_read_every_ct_source_the_ct_alert(self):
        resolved = lambda w: (w.outputs.get("resolved"), w.outputs.get("ct_resolved"))
        self.assertEqual(resolved(self.watcher.run(passed())), ("true", "true"))
        self.assertEqual(resolved(self.watcher.run(passed(CRTSH_DOWN))), ("true", None))
        self.assertEqual(resolved(self.watcher.run(passed(), restored=False)), (None, "true"))
        self.assertEqual(resolved(self.watcher.run(failed())), (None, "true"))
        self.assertEqual(resolved(self.watcher.run(unenforced(6))), (None, "true"))
        self.assertEqual(resolved(self.watcher.run(*[unread()] * 3)), (None, None))
        self.assertEqual(resolved(self.watcher.run(passed(), alerts=False)), (None, None))

    def test_each_run_writes_its_output_to_the_summary(self):
        w = self.watcher.run(unenforced(6))
        self.assertEqual(w.summary, f"check-door.py exited 2: unenforced, 1 run(s) in a row.\n\n```\n{GAP}```\n")


class VerdictTest(Fixture):
    def verdict(self, *extra, **kwargs):
        path = self.door.root / "verdict.json"
        path.unlink(missing_ok=True)
        code, out = self.door.run("--verdict", str(path), *extra, **kwargs)
        found = json.loads(path.read_text())
        self.assertEqual(found["exit"], code, out)
        return found, door_watch.judge(code, out, found)

    def test_a_clean_run_passes(self):
        found, run = self.verdict()
        self.assertEqual((run.kind, found["failed"], found["unenforced"], run.retryable), ("passed", [], [], False))
        self.assertEqual([c["check"] for c in found["checks"]], list(range(1, 10)))
        self.assertEqual(found["ct"], {str(self.door.root / "ct.json"): None})
        self.assertEqual(found["checks"][0]["title"], "Every certificate in CT for each of the door's names holds a key a verified record attests")

    def test_a_failed_check_is_failed_and_names_its_check(self):
        rogue = self.door.rogue(["inference.trymorse.ai"])
        found, run = self.verdict()
        self.assertEqual((run.kind, found["failed"]), ("failed", [1]))
        self.assertIn(self.unrecorded(rogue), found["checks"][0]["messages"][0]["text"])
        self.assertEqual(found["checks"][0]["messages"][0]["level"], "FAIL")

    def test_a_check_not_enforced_names_its_check(self):
        (self.door.root / "sequence.json").write_text(json.dumps({"boots": {}}))
        found, run = self.verdict()
        self.assertEqual((run.kind, run.unenforced, found["failed"]), ("unenforced", (6,), []))
        self.assertEqual(found["checks"][5]["messages"][-1]["level"], "NOT ENFORCED")
        alert = door_watch.compose("unenforced", run, "door-watch-1-1", RUN_URL)
        self.assertEqual(alert.title, "The inference door's watcher has not enforced check 6")
        self.assertIn("EventBridge's ClockEvery5Minutes", alert.body)

    def test_evidence_that_could_not_be_read_may_be_tried_again(self):
        found, run = self.verdict("--attestation", str(self.door.root / "missing.json"))
        self.assertEqual((run.kind, run.retryable, found["checks"], found["ct"], run.ct), ("unread", True, [], {}, ()))
        self.assertTrue(found["error"].startswith("could not read the evidence: FileNotFoundError("), found["error"])

    def test_a_ct_source_that_cannot_be_read_is_named_with_why_and_the_one_read_is_null(self):
        self.door.crtsh = {check_door.CRTSH_URL.format("trymorse.ai"): urllib.error.URLError(OSError(101, "Network is unreachable"))}
        ct = str(self.door.root / "ct.json")
        found, run = self.verdict("--ct", "crt.sh", "--ct", ct)
        self.assertEqual((run.kind, found["ct"]), ("passed", {"crt.sh": "URLError(OSError(101, 'Network is unreachable'))", ct: None}))
        self.assertEqual(dict(run.ct), found["ct"])

    def test_a_rogue_certificate_for_the_second_host_names_that_host_in_the_alert(self):
        second = "api.morseinference.com"
        self.door.ct[0] = certificate(self.door.tls, self.door.ca, "inference.trymorse.ai", ["inference.trymorse.ai", second], issuer_cn="test ca")
        self.door.caa.append({"name": second, "caa": CAA})
        self.door.rogue([second])
        found, run = self.verdict("--name", "inference.trymorse.ai", "--name", second)
        self.assertEqual((run.kind, run.hosts), ("failed", (second,)))
        alert = door_watch.compose("failed", run, "door-watch-1-1", RUN_URL)
        self.assertEqual(alert.title, "The inference door's watcher failed a check for api.morseinference.com")
        self.assertIn("failed check 1. A certificate for api.morseinference.com whose key no verified record attests can be a rogue certificate", alert.body)
        self.assertNotIn("A certificate for inference.trymorse.ai", alert.body)

    def test_a_caa_record_the_second_host_could_not_read_names_that_host_in_the_unenforced_alert(self):
        second = "api.morseinference.com"
        self.door.ct[0] = certificate(self.door.tls, self.door.ca, "inference.trymorse.ai", ["inference.trymorse.ai", second], issuer_cn="test ca")
        self.door.caa.append({"name": second, "caa": CAA})
        self.door.doh = lambda url: json.dumps({"Status": 2} if second in url else {"Status": 0, "Answer": [{"type": 257, "data": e} for e in CAA]}).encode()
        found, run = self.verdict("--name", "inference.trymorse.ai", "--name", second, sample=True)
        self.assertEqual((run.kind, run.unenforced, run.hosts), ("unenforced", (5,), (second,)))
        alert = door_watch.compose("unenforced", run, "door-watch-1-1", RUN_URL)
        self.assertEqual(alert.title, "The inference door's watcher has not enforced check 5 for api.morseinference.com")

    def test_check_1_failing_for_one_host_and_check_5_for_the_other_names_both_in_the_title_and_only_the_first_as_holding_the_certificate(self):
        second = "api.morseinference.com"
        self.door.ct[0] = certificate(self.door.tls, self.door.ca, "inference.trymorse.ai", ["inference.trymorse.ai", second], issuer_cn="test ca")
        self.door.caa.append({"name": second, "caa": CAA})
        self.door.rogue(["inference.trymorse.ai"])
        stray = '0 issue "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/9; validationmethods=dns-01"'
        self.door.doh = lambda url: json.dumps({"Status": 0, "Answer": [{"type": 257, "data": e} for e in (CAA + [stray] if second in url else CAA)]}).encode()
        found, run = self.verdict("--name", "inference.trymorse.ai", "--name", second, sample=True)
        self.assertEqual((run.kind, sorted(set(run.failed)), run.hosts, run.certificate_hosts), ("failed", [1, 5], ("inference.trymorse.ai", second), ("inference.trymorse.ai",)))
        alert = door_watch.compose("failed", run, "door-watch-1-1", RUN_URL)
        self.assertEqual(alert.title, "The inference door's watcher failed a check for inference.trymorse.ai and api.morseinference.com")
        self.assertIn("failed check 1, check 5. A certificate for inference.trymorse.ai whose key no verified record attests can be a rogue certificate", alert.body)

    def test_a_ct_outage_alert_from_a_mixed_read_and_parse_verdict_claims_no_enforcement_the_reads_do_not_show(self):
        second = "api.morseinference.com"
        self.door.ct[0] = certificate(self.door.tls, self.door.ca, "inference.trymorse.ai", ["inference.trymorse.ai", second], issuer_cn="test ca")
        self.door.caa.append({"name": second, "caa": CAA})
        rows = [{"id": 0, "name_value": "inference.trymorse.ai\n" + second, "entry_timestamp": None}]
        self.door.crtsh = {check_door.CRTSH_URL.format("trymorse.ai"): json.dumps(rows).encode(),
                           check_door.CRTSH_CERT_URL.format(0): self.door.ct[0].public_bytes(serialization.Encoding.PEM),
                           check_door.CRTSH_URL.format("morseinference.com"): json.dumps([{"id": 7, "entry_timestamp": None}]).encode()}
        gone = str(self.door.root / "gone.json")
        found, run = self.verdict("--name", "inference.trymorse.ai", "--name", second, "--ct", "crt.sh", "--ct", gone)
        self.assertEqual((found["ct_hosts"]["crt.sh"], found["unenforced"]), ({"read": ["inference.trymorse.ai"], "unread": [second]}, [1]))
        alert = door_watch.compose_ct({gone: {"count": door_watch.CT_ALERT_AFTER, "since": "then", "why": found["ct"][gone]}}, run, RUN_URL)
        self.assertIn(f"{gone} could not be read on {door_watch.CT_ALERT_AFTER} door-watch runs in a row, since then, and on the last of those runs crt.sh read inference.trymorse.ai, "
                      f"and no other source read {second}. ", alert.body)
        self.assertNotIn("judged", alert.body)
        self.assertIn(f"NOT ENFORCED: check 1 not enforced for {second} on this run: crt.sh answered with an entry this watcher could not parse", alert.body)

    def test_a_github_outage_is_a_result_and_not_evidence_to_read_again(self):
        def down(url, *_):
            raise urllib.error.HTTPError(url, 502, "Bad Gateway", {}, None)

        self.door.visibility = 502
        self.door.fetch_github = down
        found, run = self.verdict()
        self.assertEqual((run.kind, run.retryable, found["error"]), ("failed", False, None))
        self.assertEqual((found["failed"], found["unenforced"]), ([9], [7]))


if __name__ == "__main__":
    unittest.main()
