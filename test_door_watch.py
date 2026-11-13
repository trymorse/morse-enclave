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
from dataclasses import dataclass
from pathlib import Path

sys.dont_write_bytecode = True
from check_door_fixtures import *  # noqa: E402,F403
import door_watch  # noqa: E402

RUN_URL = "https://example.test/run"
FAILED = "2 certificates in CT cover inference.trymorse.ai.\n\nmorse-records is public (check 9)\n  FAIL: https://api.github.com/repos/trymorse/morse-records, read with no token, answers 404\n"
UNREAD = "FAIL: could not read the evidence: <HTTPError 502: 'Bad Gateway'>\n"
PASSED = "0 certificates in CT cover inference.trymorse.ai.\n\nmorse-records is public (check 9)\n  OK\n"
GAP = "The door's live attestation names only boots with verified records (check 6)\n  NOT ENFORCED: check 6 not enforced on this run\n"
SIGNER = "Only the publisher pushes data to morse-pins main (check 7)\n  NOT ENFORCED: check 7 not enforced on this run: sign.yml's runs could not be read\n"


def verdict(kind, unenforced=()):
    code = {"passed": 0, "failed": 1, "unenforced": 2, "unread": 1}[kind]
    return {"kind": kind, "exit": code, "retryable": kind == "unread", "failed": [1] if kind == "failed" else [], "unenforced": list(unenforced), "checks": []}


def passed():
    return {"code": 0, "output": PASSED, "verdict": verdict("passed")}


def failed():
    return {"code": 1, "output": FAILED, "verdict": verdict("failed")}


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


class Watcher:
    def __init__(self, root):
        self.root = Path(root)
        (self.root / "stand_in.py").write_text(STAND_IN)

    def run(self, *attempts, alerts=True, restored=True, setup=None):
        (self.root / "script.json").write_text(json.dumps(list(attempts)))
        for name in ("outputs", "summary", "alert.md"):
            (self.root / name).unlink(missing_ok=True)
        argv = ["--state", str(self.root / "door-state"), "--run-url", RUN_URL, "--alert-body", str(self.root / "alert.md")]
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
        return Watched(code, out.getvalue(), outputs.get("alert", ""), outputs.get("label", ""), outputs.get("title", ""), outputs.get("hours", ""),
                       self.read("alert.md"), self.read("summary"), slept)

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
        self.assertEqual((w.code, w.alert, w.label, w.hours, w.title), (1, "failed", "door-watch-failed", "0", "The inference door's watcher failed a check"))
        self.assertEqual(w.body, f"check-door.py exited 1 and failed a check. A certificate for inference.trymorse.ai whose key no verified record attests can be a rogue certificate: read check 1 first, in {RUN_URL}\n\n```\n{FAILED}```\n")

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
                self.assertEqual("EventBridge's DoorWatchEvery5Minutes" in runs[2].body, event_bridge)
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

    def test_each_run_writes_its_output_to_the_summary(self):
        w = self.watcher.run(unenforced(6))
        self.assertEqual(w.summary, f"check-door.py exited 2: unenforced, 1 run(s) in a row.\n\n```\n{GAP}```\n")


class VerdictTest(Fixture):
    def verdict(self, *extra):
        path = self.door.root / "verdict.json"
        path.unlink(missing_ok=True)
        code, out = self.door.run("--verdict", str(path), *extra)
        found = json.loads(path.read_text())
        self.assertEqual(found["exit"], code, out)
        return found, door_watch.judge(code, out, found)

    def test_a_clean_run_passes(self):
        found, run = self.verdict()
        self.assertEqual((run.kind, found["failed"], found["unenforced"], run.retryable), ("passed", [], [], False))
        self.assertEqual([c["check"] for c in found["checks"]], list(range(1, 10)))
        self.assertEqual(found["checks"][0]["title"], "Every certificate in CT for the door's name holds a key a verified record attests")

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
        self.assertIn("EventBridge's DoorWatchEvery5Minutes", alert.body)

    def test_evidence_that_could_not_be_read_may_be_tried_again(self):
        found, run = self.verdict("--attestation", str(self.door.root / "missing.json"))
        self.assertEqual((run.kind, run.retryable, found["checks"]), ("unread", True, []))
        self.assertTrue(found["error"].startswith("could not read the evidence: FileNotFoundError("), found["error"])


if __name__ == "__main__":
    unittest.main()
