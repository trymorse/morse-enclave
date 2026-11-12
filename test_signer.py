# /// script
# requires-python = ">=3.10"
# dependencies = ["cbor2==6.1.5", "cryptography==50.0.2", "tuf==7.0.1", "securesystemslib==1.6.0", "urllib3==2.8.0"]
# ///
"""Tests check-door.py's check 7, of the public image signer: who pushed morse-pins main, the .github allowlist, the
statements on the statements branch and the numbers of sign.yml's runs, against a local morse-pins, a fake GitHub
API and a fake bundle verifier from check_door_fixtures.py, and signer.py's bundle verification against real
statements of trymorse/morse-pins recorded in this repository. It reads nothing from the network.

Usage: uv run test_signer.py
"""

import json
import sys
import unittest
import unittest.mock
from datetime import timedelta

sys.dont_write_bytecode = True
from check_door_fixtures import *  # noqa: E402,F403

signer = check_door.signer
DOOR_TESTDATA = SOURCE / "internal/door/testdata"
LIVE = SOURCE / "internal/pinsbranch/testdata"
TRUSTED_ROOT = SOURCE / "internal/pinsig/sigstore_trusted_root.json"
REAL_COMMIT = "1297f803b23d81fa647eacc6af2f73b9d0fdea72"
REAL_RUN = "https://github.com/trymorse/morse-pins/actions/runs/42775637517/attempts/1"


class SignerTest(Fixture):
    def setUp(self):
        super().setUp()
        self.door.build_pins()
        self.commit("README", "the publisher's push")

    def check7(self, out):
        return self.section(out, "check 7")

    def commit(self, path, text, branch=None):
        pins = self.door.root / "pins"
        if branch:
            self.door.git("checkout", "-q", "-b", branch)
        (pins / path).parent.mkdir(parents=True, exist_ok=True)
        (pins / path).write_text(text)
        self.door.git("add", "-A")
        self.door.git("commit", "-q", "-m", path)
        head = self.door.head()
        if branch:
            self.door.git("checkout", "-q", "main")
        return head

    def last_push(self, **change):
        def edit(events):
            events[-1] = {**events[-1], **change}
            return events
        self.door.activity_edit = edit

    def test_a_clean_history_passes_and_saves_where_it_stopped(self):
        self.door.sign("prod")
        self.door.sign("dev")
        self.door.runs = [run_of(1, self.door.head()), run_of(2, self.door.head(), event="schedule")]
        out = self.passes()
        self.assertEqual(self.check7(out), "  OK")
        state = self.door.state()
        self.assertEqual(state["tips"]["morse-pins"], self.door.head())
        self.assertEqual(state["runs_seen_through"], 2)
        self.assertEqual(len(state["verified_statements"]), 2)

    def test_a_github_tree_off_the_allowlist_fails_and_signer_tree_allows_it(self):
        self.commit(".github/workflows/sign.yml", "name: sign\non: push\n")
        self.last_push(activity_type="pr_merge", actor={"login": "youdaniel"})
        tree = git(self.door.root / "pins", "rev-parse", "HEAD:.github").strip()
        self.fails(f"FAIL: morse-pins main has a .github tree {tree} that the allowlist does not name, in 1 commits from {self.door.head()} on")
        code, out = self.door.run("--signer-tree", tree)
        self.assertEqual(code, 0, out)

    def test_a_statement_whose_commit_is_not_on_main_fails(self):
        side = self.commit("README", "a side branch", branch="side")
        path = self.door.sign("prod", commit=side)
        self.fails(f"FAIL: {path} names {side}, which is not on morse-pins main")
        self.assertEqual(self.door.state()["verified_statements"], [])

    def test_a_statement_whose_images_differ_by_one_revoked_flag_fails(self):
        images = sorted(({k: p[k] for k in ("pcr0", "pcr1", "pcr2", "revoked")} for p in self.door.pins if p["environment"] == "prod"), key=lambda i: i["pcr0"])
        flipped = [{**images[0], "revoked": not images[0]["revoked"]}] + images[1:]
        path = self.door.sign("prod", images=flipped)
        self.fails(f"FAIL: {path} lists other images than enclave_pins.json at {self.door.head()} give it")
        ok = self.door.sign("prod", images=images)
        self.assertNotIn(ok, self.check7(self.door.run()[1]))

    def test_a_sequence_one_above_the_commit_count_fails(self):
        count = int(git(self.door.root / "pins", "rev-list", "--count", "HEAD"))
        path = self.door.sign("prod", sequence=count + 1)
        self.fails(f"FAIL: {path} has sequence {count + 1}, not the commit count {count} of {self.door.head()}")

    def test_a_statement_signed_at_another_commit_than_it_names_fails(self):
        first = git(self.door.root / "pins", "rev-list", "--max-parents=0", "HEAD").strip()
        path = self.door.sign("prod", signed=fake_bundle(first))
        self.fails(f"FAIL: {path} names pins_commit {self.door.head()}, and its certificate was issued to a run at {first}")

    def test_an_unsigned_statement_fails_on_every_run(self):
        path = self.door.sign("prod", signed=fake_bundle(None, unsigned="the SAN is someone else's"))
        for _ in range(2):
            self.fails(f"FAIL: {path} is not signed by sign.yml on main of trymorse/morse-pins: the SAN is someone else's")

    def test_a_statement_deleted_at_the_tip_is_still_verified(self):
        path = self.door.sign("prod", signed=fake_bundle(None, unsigned="forged"))
        self.door.deleted = [path, path.replace(".statement.json", ".sigstore.json")]
        self.fails(f"FAIL: {path} is not signed by sign.yml on main of trymorse/morse-pins: forged")

    def test_a_statement_changed_after_it_was_added_fails(self):
        path = self.door.sign("prod")
        self.passes()
        self.door.changed = {path: b"{}"}
        self.fails(f"FAIL: {path} was changed after it was added, and the signer only adds statements")

    def test_each_statement_is_verified_once(self):
        self.door.sign("prod")
        calls = []
        with unittest.mock.patch.object(signer, "verify_statement", lambda *a: calls.append(1) or fake_verify(*a)):
            self.passes()
            self.passes()
        self.assertEqual(len(calls), 1)

    def test_a_vendor_statement_hashes_the_jcs_bytes_of_each_vendor_file(self):
        for n, name in enumerate(signer.VENDOR_FILES):
            (self.door.root / "pins" / name).write_text(f'{{\n  "z": [{n}, "é/"],\n  "a": {{"y": null, "b": true}}\n}}\n')
        self.door.git("add", "-A")
        self.door.git("commit", "-q", "-m", "vendor")
        head = self.door.head()
        files = {f"v4/{name}": hashlib.sha256(f'{{"a":{{"b":true,"y":null}},"z":[{n},"é/"]}}'.encode()).hexdigest() for n, name in enumerate(signer.VENDOR_FILES)}
        statement = {"type": "morse-vendor-pins-v1", "sequence": int(git(self.door.root / "pins", "rev-list", "--count", "HEAD")), "pins_commit": head, "time": "2026-11-11T00:00:00Z", "files": files}
        self.door.statements.append(("vendor/1.statement.json", json.dumps(statement).encode(), fake_bundle(head)))
        self.assertEqual(self.check7(self.passes()), "  OK")
        self.door.statements.append(("vendor/2.statement.json", json.dumps({**statement, "files": {**files, "v4/near_pins.json": "0" * 64}}).encode(), fake_bundle(head)))
        self.fails(f"FAIL: vendor/2.statement.json lists other files than the vendor pins files at {head} give it")

    def runs_bound(self):
        """The created>= bound of the newest read of sign.yml's runs."""
        url = [u for u in self.door.github_reads if u.startswith(check_door.signer_watch.RUNS_URL)][-1]
        return datetime.fromisoformat(urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["created"][0].removeprefix(">=").replace("Z", "+00:00"))

    def test_a_deleted_run_fails_on_every_run_while_the_runs_read_stay_recent(self):
        head = self.door.head()
        self.door.runs = [run_of(1, head, created=NOW - timedelta(days=5)), run_of(2, head, created=NOW - timedelta(days=4)), run_of(4, head, created=NOW - timedelta(days=3))]
        self.fails("FAIL: sign.yml run 3 is missing, so it was deleted, and this fails every run until --ack-run 3")
        self.assertLess(abs(self.runs_bound() - (NOW - timedelta(days=14))), timedelta(minutes=5))
        for _ in range(3):
            self.door.github_reads = []
            self.fails("FAIL: sign.yml run 3 is missing, so it was deleted")
            self.assertGreater(self.runs_bound(), NOW - timedelta(hours=2))

    def test_ack_run_clears_that_run_and_no_other(self):
        head = self.door.head()
        self.door.runs = [run_of(1, head), run_of(3, head), run_of(5, head, event="workflow_dispatch")]
        self.fails("FAIL: sign.yml run 2 is missing", "FAIL: sign.yml run 4 is missing", "FAIL: sign.yml run 5 succeeded from a workflow_dispatch")
        code, out = self.door.run("--ack-run", "2", "--ack-run", "7")
        self.assertEqual(code, 1, out)
        self.assertNotIn("sign.yml run 2 is missing", out)
        self.assertIn("FAIL: sign.yml run 4 is missing", out)
        self.assertIn("FAIL: sign.yml run 5 succeeded", out)
        self.assertIn("NOTE: --ack-run 7 names no refused run this watcher keeps", out)
        self.fails("FAIL: sign.yml run 4 is missing")
        code, out = self.door.run("--ack-run", "4", "--ack-run", "5")
        self.assertEqual(code, 0, out)
        self.passes()

    def test_runs_made_while_their_listing_could_not_be_read_for_over_a_day_are_judged(self):
        head, start = self.door.head(), NOW - timedelta(days=2)
        self.door.runs = [run_of(1, head, created=start)]
        self.passes()
        self.door.edit_state(lambda s: s.update({"runs_read_at": (start + timedelta(minutes=30)).isoformat()}))
        self.door.runs += [run_of(2, head, created=start + timedelta(hours=1)), run_of(3, head, event="workflow_dispatch", created=start + timedelta(hours=2)),
                           run_of(4, head, created=start + timedelta(hours=3))]
        fetch = self.door.fetch_github
        self.door.fetch_github = lambda url: (_ for _ in ()).throw(urllib.error.HTTPError(url, 403, "rate limited", {}, None)) if url.startswith(check_door.signer_watch.RUNS_URL) else fetch(url)
        self.assertEqual(self.door.run()[0], 2)
        self.door.fetch_github = fetch
        out = self.fails(f"FAIL: sign.yml run 3 succeeded from a workflow_dispatch on main at {head}")
        self.assertNotIn("so it was deleted", out)
        self.assertEqual(self.door.state()["runs_seen_through"], 4)

    def test_a_run_listed_in_progress_and_deleted_before_the_next_run_is_missing(self):
        head = self.door.head()
        self.door.runs = [run_of(1, head), run_of(2, head, event="workflow_dispatch", status="in_progress", conclusion=None)]
        self.passes()
        self.door.runs = [run_of(1, head), run_of(3, head)]
        self.fails("FAIL: sign.yml run 2 is missing, so it was deleted")

    def test_a_waiting_run_keeps_the_runs_read_recent_and_is_judged_when_it_completes(self):
        head, old = self.door.head(), NOW - timedelta(days=3)
        self.door.runs = [run_of(1, head, created=old), run_of(2, head, event="workflow_dispatch", status="waiting", conclusion=None, created=old)]
        self.passes()
        for _ in range(3):
            self.door.github_reads = []
            self.passes()
            self.assertGreater(self.runs_bound(), NOW - timedelta(hours=2))
            self.assertIn(f"{check_door.signer_watch.RUN_URL}9002", self.door.github_reads)
        self.door.runs[1] = run_of(2, head, event="workflow_dispatch", created=old)
        self.fails(f"FAIL: sign.yml run 2 succeeded from a workflow_dispatch on main at {head}")

    def test_a_successful_workflow_dispatch_run_fails_and_a_failed_one_passes(self):
        head = self.door.head()
        self.door.runs = [run_of(1, head, event="workflow_dispatch", conclusion="failure")]
        self.passes()
        self.door.runs.append(run_of(2, head, event="workflow_dispatch", created=NOW))
        self.fails(f"FAIL: sign.yml run 2 succeeded from a workflow_dispatch on main at {head}, which is not a push or schedule run on main")

    def test_a_successful_run_whose_commit_is_not_on_main_fails(self):
        side = self.commit("README", "x", branch="side")
        self.door.runs = [run_of(1, side)]
        self.fails(f"FAIL: sign.yml run 1 succeeded from a push on main at {side}, which is not on morse-pins main")

    def test_a_successful_run_of_a_commit_this_checkout_lacks_is_a_note_for_an_hour(self):
        self.door.runs = [run_of(1, "a" * 40, created=NOW - timedelta(minutes=5))]
        self.assertIn("NOTE: sign.yml run 1 succeeded from a push on main at " + "a" * 40 + ", which this checkout does not hold", self.passes())
        self.door.runs = [run_of(1, "a" * 40, created=NOW - timedelta(minutes=61))]
        self.fails("FAIL: sign.yml run 1 succeeded from a push on main at " + "a" * 40 + ", which this checkout does not hold")

    def test_a_push_by_github_actions_fails(self):
        self.commit("README", "x")
        self.last_push(actor={"login": "github-actions[bot]"})
        self.fails(f"FAIL: morse-pins main had a push by github-actions[bot] at {PUSHED}, and only a push by morse-pins-publisher[bot] or a pull request an admin merged may move it")

    def test_an_admins_merged_pull_request_may_change_the_signer_and_not_what_it_signs(self):
        tree = signer_tree("name: sign\non: schedule\n")
        self.commit(".github/workflows/sign.yml", "name: sign\non: schedule\n")
        self.last_push(activity_type="pr_merge", actor={"login": "justinyshen"})
        code, out = self.door.run("--signer-tree", tree)
        self.assertEqual(code, 0, out)
        before = self.door.head()
        self.door.edit_state(lambda s: s["tips"].update({"morse-pins": before}))
        self.commit("enclave_pins.json", json.dumps(self.door.revoked("v1")))
        self.last_push(activity_type="pr_merge", actor={"login": "youdaniel"})
        code, out = self.door.run("--signer-tree", tree)
        self.assertEqual(code, 1, out)
        self.assertIn(f"FAIL: the pr_merge by youdaniel at {PUSHED}, from {before} to {self.door.head()}, changes enclave_pins.json: a file the signer signs, which only morse-pins-publisher[bot] pushes", out)

    def test_an_admins_direct_push_fails(self):
        self.commit("README", "x")
        self.last_push(actor={"login": "youdaniel"})
        self.fails("FAIL: morse-pins main had a push by youdaniel")

    def test_a_publisher_push_that_changes_the_signer_fails(self):
        before = self.door.head()
        self.commit(".github/testdata/x.json", "{}")
        self.fails(f"FAIL: the push by morse-pins-publisher[bot] at {PUSHED}, from {before} to {self.door.head()}, changes .github/testdata/x.json: the signer's code")

    def test_a_push_whose_before_is_not_the_last_after_fails(self):
        self.commit("README", "x")
        self.last_push(before="b" * 40)
        self.fails(f"FAIL: morse-pins main moved from {git(self.door.root / 'pins', 'rev-parse', 'HEAD~1').strip()} to {'b' * 40} with no push listed")

    def test_a_refused_push_fails_every_run_until_its_commit_is_acknowledged(self):
        self.commit("README", "x")
        self.last_push(actor={"login": "youdaniel"})
        refused = self.door.head()
        for _ in range(3):
            self.fails(f"FAIL: morse-pins main had a push by youdaniel at {PUSHED}, and only a push by morse-pins-publisher[bot] or a pull request an admin merged may move it, and this fails every run until --ack-refused {refused}")
        self.assertEqual(self.door.state()["tips"]["morse-pins"], refused)
        code, out = self.door.run("--ack-refused", "e" * 40)
        self.assertEqual(code, 1, out)
        self.assertIn(f"NOTE: --ack-refused {'e' * 40} names no refused push this watcher keeps", out)
        code, out = self.door.run("--ack-refused", refused)
        self.assertEqual(code, 0, out)
        self.passes()
        self.commit("README", "y")
        self.door.activity_edit = lambda events: events[:-1] + [{**events[-1], "activity_type": "force_push", "actor": {"login": "justinyshen"}}]
        self.fails("FAIL: morse-pins main had a force_push by justinyshen")
        code, out = self.door.run("--ack-refused", refused)
        self.assertEqual(code, 1, out)
        self.assertIn(f"until --ack-refused {self.door.head()}", out)

    def test_a_force_push_fails(self):
        self.commit("README", "x")
        self.last_push(activity_type="force_push", actor={"login": "youdaniel"})
        self.fails("FAIL: morse-pins main had a force_push by youdaniel")

    def test_a_history_that_ends_before_the_checkout_is_a_note_for_an_hour_then_fails_and_passes_when_listed(self):
        self.passes()
        judged, self.door.activity_reads = self.door.state()["last_push"], 0
        self.commit("README", "x")
        self.door.activity_edit = lambda events: events[:-1]
        unlisted = f"the activity API lists no push that ends at the checkout's morse-pins main {self.door.head()}"
        self.passes(f"NOTE: {unlisted}")
        self.assertEqual(self.door.activity_reads, 2)
        self.assertEqual(self.door.state()["last_push"], judged)
        self.door.edit_state(lambda s: s.update({"unlisted_since": (NOW - timedelta(minutes=59)).isoformat()}))
        self.passes(f"NOTE: {unlisted}")
        self.door.edit_state(lambda s: s.update({"unlisted_since": (NOW - timedelta(minutes=61)).isoformat()}))
        self.fails(f"FAIL: {unlisted}")
        self.assertEqual(self.door.state()["last_push"], judged)
        self.door.activity_reads = 0
        self.door.activity_edit = lambda events: events[:-1] if self.door.activity_reads == 1 else events
        self.passes()
        self.assertNotEqual(self.door.state()["last_push"], judged)
        self.assertIsNone(self.door.state()["unlisted_since"])

    def test_an_unlisted_checkout_is_judged_by_its_pushes_once_listed(self):
        self.passes()
        self.commit("README", "x")
        self.last_push(actor={"login": "youdaniel"})
        edit = self.door.activity_edit
        self.door.activity_edit = lambda events: events[:-1]
        self.passes("NOTE: the activity API lists no push that ends at the checkout's morse-pins main")
        self.door.activity_edit = edit
        self.fails(f"FAIL: morse-pins main had a push by youdaniel at {PUSHED}, and only a push by morse-pins-publisher[bot] or a pull request an admin merged may move it, and this fails every run until --ack-refused {self.door.head()}")
        self.assertEqual(self.door.state()["tips"]["morse-pins"], self.door.head())
        self.assertIsNone(self.door.state()["unlisted_since"])

    def test_a_history_over_two_pages_passes_and_fails_when_the_second_page_is_dropped(self):
        self.door.page_size = 2
        self.passes()
        for text in "xyz":
            self.commit("README", text)
        self.door.github_reads = []
        self.passes()
        self.assertEqual(self.door.github_reads[:2], [check_door.signer_watch.PUSHES_URL, f"{check_door.signer_watch.PUSHES_URL}&after=c1"])
        for text in "uvw":
            self.commit("README", text)
        fetch = self.door.fetch_github
        self.door.fetch_github = lambda url: (fetch(url)[0], None) if url.startswith(check_door.signer_watch.PUSHES_URL) else fetch(url)
        self.fails("FAIL: the activity API no longer lists event")

    def test_a_steady_watcher_reads_only_the_events_since_the_one_it_last_judged(self):
        for n in range(20):
            self.commit("README", str(n))
        self.door.page_size = 2
        self.passes()
        self.door.activity_reads = 0
        self.passes()
        self.assertEqual(self.door.activity_reads, 1)
        self.commit("README", "the next push")
        self.door.activity_reads = 0
        self.passes()
        self.assertEqual(self.door.activity_reads, 1)
        self.assertEqual(self.door.state()["tips"]["morse-pins"], self.door.head())

    def test_the_event_last_judged_vanishing_from_the_activity_fails_and_keeps_the_state(self):
        self.passes()
        self.commit("README", "x")
        self.passes()
        kept = self.door.state()
        self.commit("README", "y")
        self.door.activity_edit = lambda events: events[:-2] + events[-1:]
        self.fails(f"FAIL: the activity API no longer lists event {kept['last_push']['id']} on morse-pins main, at {kept['last_push']['timestamp']}, the last this watcher judged")
        self.assertEqual(self.door.state()["last_push"], kept["last_push"])

    def reverted_push(self, old, run_between):
        """A judged a, then an admin's direct push a->b and force-push b->a, then the publisher's a->c."""
        made = {}
        long_ago = (NOW - timedelta(days=40)).strftime("%Y-%m-%dT%H:%M:%SZ")

        def edit(events):
            n = next((i for i, e in enumerate(events) if e["after"] == made.get("a")), len(events) - 1)
            events = [{**e, "timestamp": long_ago} if old and i <= n else e for i, e in enumerate(events)]
            admin = [push(made["a"], made["b"], actor="youdaniel"), push(made["b"], made["a"], actor="youdaniel", kind="force_push")] if "b" in made else []
            return events[:n + 1] + admin + events[n + 1:]
        self.door.activity_edit = edit
        self.passes()
        self.commit("README", "x")
        self.passes()
        made["a"] = self.door.head()
        made["b"] = self.commit("README", "a direct push")
        self.door.git("reset", "-q", "--hard", made["a"])
        refusals = (f"FAIL: morse-pins main had a push by youdaniel at {PUSHED}, and only a push by morse-pins-publisher[bot] or a pull request an admin merged may move it, and this fails every run until --ack-refused {made['b']}",
                    f"FAIL: morse-pins main had a force_push by youdaniel at {PUSHED}, and only a push by morse-pins-publisher[bot] or a pull request an admin merged may move it, and this fails every run until --ack-refused {made['a']}")
        if run_between:
            self.fails(*refusals)
        self.commit("README", "the publisher's next push")
        for _ in range(2):
            self.fails(*refusals)
        code, out = self.door.run("--ack-refused", made["b"])
        self.assertEqual(code, 1, out)
        self.assertIn(f"until --ack-refused {made['a']}", out)
        self.assertNotIn(f"until --ack-refused {made['b']}", out)
        code, out = self.door.run("--ack-refused", made["a"])
        self.assertEqual(code, 0, out)

    def test_a_push_reverted_between_two_runs_is_refused_until_acknowledged(self):
        self.reverted_push(old=False, run_between=False)

    def test_a_push_reverted_after_a_month_of_quiet_is_refused(self):
        self.reverted_push(old=True, run_between=False)

    def test_a_push_reverted_before_a_run_that_sees_main_unmoved_is_refused(self):
        self.reverted_push(old=True, run_between=True)

    def test_a_force_push_back_does_not_refuse_the_publishers_pushes_after_it(self):
        self.passes()
        a = self.door.head()
        b = self.commit("README", "a direct push")
        self.last_push(actor={"login": "youdaniel"})
        self.fails(f"until --ack-refused {b}")
        self.door.git("reset", "-q", "--hard", a)
        made = {}

        def edit(events):
            n = next(i for i, e in enumerate(events) if e["after"] == a)
            return events[:n + 1] + [push(a, b, actor="youdaniel"), push(b, a, actor="youdaniel", kind="force_push")] + events[n + 1:]
        self.door.activity_edit = edit
        self.fails(f"FAIL: morse-pins main had a force_push by youdaniel at {PUSHED}, and only a push by morse-pins-publisher[bot] or a pull request an admin merged may move it, and this fails every run until --ack-refused {a}")
        for text in ("c", "d"):
            made[text] = self.commit("README", text)
            code, out = self.door.run()
            self.assertEqual(code, 1, out)
            self.assertIn(f"until --ack-refused {b}", out)
            self.assertIn(f"until --ack-refused {a}", out)
            self.assertNotIn("with no push listed", out)
            self.assertNotIn(f"until --ack-refused {made[text]}", out)
        code, out = self.door.run("--ack-refused", a, "--ack-refused", b)
        self.assertNotIn("--ack-refused", self.check7(out))

    def test_a_new_watcher_whose_first_activity_read_fails_checks_the_window_on_its_next_run(self):
        self.last_push(actor={"login": "youdaniel"})
        fetch = self.door.fetch_github
        self.door.fetch_github = lambda url: fetch(url) if url.startswith(check_door.signer_watch.RUNS_URL) else (_ for _ in ()).throw(urllib.error.HTTPError(url, 403, "rate limited", {}, None))
        code, out = self.door.run()
        self.assertEqual(code, 2, out)
        self.assertIn("NOT ENFORCED: check 7 not enforced on this run: the activity of morse-pins main could not be read", out)
        self.assertEqual(self.door.state()["tips"]["morse-pins"], self.door.head())
        self.assertIsNone(self.door.state()["last_push"])
        self.door.fetch_github = fetch
        self.fails(f"FAIL: morse-pins main had a push by youdaniel at {PUSHED}, and only a push by morse-pins-publisher[bot] or a pull request an admin merged may move it")

    def test_a_first_run_with_no_runs_in_the_window_leaves_the_next_run_a_first_run(self):
        self.door.runs = [run_of(1, self.door.head(), created=NOW - timedelta(days=20))]
        self.passes()
        self.assertIsNone(self.door.state()["runs_read_at"])
        self.door.runs.append(run_of(5, self.door.head()))
        self.passes()
        self.assertEqual(self.door.state()["runs_seen_through"], 5)

    def test_a_new_watcher_checks_only_the_last_14_days(self):
        head = self.door.head()
        for n in range(4):
            self.commit("README", str(n))
        old = (NOW - timedelta(days=20)).strftime("%Y-%m-%dT%H:%M:%SZ")

        def edit(events):
            events = [{**e, "timestamp": old} if i < len(events) - 2 else e for i, e in enumerate(events)]
            events[1] = {**events[1], "actor": {"login": "github-actions[bot]"}}
            return events
        self.door.activity_edit, self.door.page_size = edit, 2
        start = NOW - timedelta(days=30)
        self.door.runs = [run_of(n, head, created=start + timedelta(hours=3 * n)) for n in range(1, 241) if n not in (11, 200)]
        out = self.fails("FAIL: sign.yml run 200 is missing, so it was deleted")
        self.assertNotIn("github-actions", out)
        self.assertNotIn("sign.yml run 11 ", out)
        self.assertLess(abs(self.runs_bound() - (NOW - timedelta(days=14))), timedelta(minutes=5))
        self.assertNotIn(f"{check_door.signer_watch.PUSHES_URL}&after=c2", self.door.github_reads)
        self.assertEqual(self.door.state()["runs_seen_through"], 240)

    def test_a_push_listed_after_the_checkout_is_left_for_the_next_run(self):
        head = self.door.head()
        self.door.activity_edit = lambda events: events + [push(head, "c" * 40, actor="github-actions[bot]")]
        self.passes()
        self.assertEqual(self.door.state()["tips"]["morse-pins"], head)

    def test_github_that_cannot_be_read_leaves_check_7_unenforced_and_its_state_unmoved(self):
        self.passes()
        judged = self.door.state()["last_push"]
        self.commit("README", "x")
        self.door.fetch_github = lambda url: (_ for _ in ()).throw(urllib.error.HTTPError(url, 403, "rate limited", {}, None))
        code, out = self.door.run()
        self.assertEqual(code, 2, out)
        self.assertIn("NOT ENFORCED: check 7 not enforced on this run: the activity of morse-pins main could not be read", out)
        self.assertIn("NOT ENFORCED: check 7 not enforced on this run: sign.yml's runs could not be read", out)
        self.assertEqual(self.door.state()["last_push"], judged)

    def test_a_checkout_with_no_statements_branch_fails(self):
        self.door.build_pins()
        code, out = self.door.run("--statements", "origin/none")
        self.assertEqual(code, 1, out)
        self.assertIn("FAIL: the morse-pins checkout has no origin/none", out)


def identity_certificate(**changes):
    """A certificate with sign.yml's identity extensions, with changes by OID suffix, signed by nobody."""
    commit = "1" * 40
    values = {"8": signer.ISSUER, "9": signer.WORKFLOW, "11": "github-hosted", "12": signer.REPOSITORY, "13": commit, "14": "refs/heads/main",
              "15": signer.REPOSITORY_ID, "17": signer.OWNER_ID, "18": signer.WORKFLOW, "19": commit, "20": "push", "21": RUN.format(7), **changes}
    key = ec.generate_private_key(ec.SECP256R1())
    builder = (x509.CertificateBuilder().subject_name(x509.Name([])).issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")]))
               .public_key(key.public_key()).serial_number(1).not_valid_before(NOW).not_valid_after(NOW + timedelta(minutes=10))
               .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(changes.pop("san", signer.WORKFLOW))]), critical=True))
    for suffix, value in values.items():
        if suffix != "san" and value is not None:
            raw = value.encode()
            builder = builder.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier(signer.OID + suffix), b"\x0c" + bytes([len(raw)]) + raw), critical=False)
    return builder.sign(key, hashes.SHA256())


class IdentityTest(unittest.TestCase):
    """signer.check_identity, which pinsig's checkIdentity mirrors, on certificates the test makes."""

    def test_the_enclaves_signer_passes_and_one_field_off_is_refused(self):
        """identity.json is door.Production()'s Identity, which ci_public_scripts_test.go holds it to."""
        trusted = json.loads((SOURCE / "testdata/public-signing/identity.json").read_text())

        def made(**field):
            id_ = {**trusted, **field}
            workflow = f"{id_['source_repository_uri']}/{id_['workflow']}@{id_['ref']}"
            return identity_certificate(**{"san": workflow, "8": id_["issuer"], "9": workflow, "12": id_["source_repository_uri"], "14": id_["ref"],
                                           "15": id_["source_repository_id"], "17": id_["source_owner_id"], "18": workflow, "20": id_["trigger"],
                                           "21": f"{id_['source_repository_uri']}/actions/runs/7/attempts/1"})

        for trigger in trusted["triggers"]:
            self.assertEqual(signer.check_identity(made(trigger=trigger)).commit, "1" * 40)
        for field in ({"issuer": "https://token.actions.example.com"}, {"source_repository_uri": "https://github.com/trymorse/morse-pins-fork"},
                      {"source_repository_id": "1"}, {"source_owner_id": "2"}, {"workflow": ".github/workflows/other.yml"},
                      {"ref": "refs/heads/next"}, *({"trigger": t} for t in ("workflow_dispatch", "pull_request", "workflow_run", "repository_dispatch"))):
            with self.subTest(field=field), self.assertRaises(signer.Unsigned):
                signer.check_identity(made(**{"trigger": trusted["triggers"][0], **field}))

    def test_sign_yml_on_main_in_a_first_attempt_passes(self):
        self.assertEqual(signer.check_identity(identity_certificate()), signer.Signed("1" * 40, RUN.format(7)))

    def test_anything_else_is_refused(self):
        for changes, why in (
            ({"21": "https://github.com/trymorse/morse-pins/actions/runs/7/attempts/2"}, "is not the first attempt of a run"),
            ({"21": "https://github.com/trymorse/other/actions/runs/7/attempts/1"}, "is not the first attempt of a run"),
            ({"20": "workflow_dispatch"}, "the run was started by 'workflow_dispatch'"),
            ({"19": "2" * 40}, "the build config digest"),
            ({"14": "refs/heads/next"}, "the source ref is 'refs/heads/next'"),
            ({"18": signer.WORKFLOW.replace("sign.yml", "call.yml")}, "extension 1.3.6.1.4.1.57264.1.18"),
            ({"11": "self-hosted"}, "extension 1.3.6.1.4.1.57264.1.11"),
            ({"17": "1"}, "extension 1.3.6.1.4.1.57264.1.17"),
            ({"13": None}, "has no extension 1.3.6.1.4.1.57264.1.13"),
            ({"san": "https://github.com/trymorse/morse-pins/.github/workflows/other.yml@refs/heads/main"}, "the SAN is"),
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(signer.Unsigned) as caught:
                    signer.check_identity(identity_certificate(**changes))
                self.assertIn(why, str(caught.exception))


@unittest.skipUnless(TRUSTED_ROOT.exists() and (DOOR_TESTDATA / "prod.sigstore.json").exists(), "the recorded statements are not in this checkout")
class RealBundleTest(unittest.TestCase):
    """signer.py on statements the public sign.yml signed, under check-door.py's own witness policy."""

    def setUp(self):
        root = TRUSTED_ROOT.read_bytes()
        self.shards, _ = rekor.read_shards(root)
        self.authorities = signer.read_authorities(root, rekor.rfc3339)
        self.policy = rekor.make_policy(check_door.WITNESS_K, check_door.WITNESSES)

    def verify(self, name, statement=None, bundle_json=None, **kwargs):
        args = {"shards": self.shards, "authorities": self.authorities, "policy": self.policy, **kwargs}
        statement = statement if statement is not None else (DOOR_TESTDATA / f"{name}.statement.json").read_bytes()
        bundle_json = bundle_json if bundle_json is not None else (DOOR_TESTDATA / f"{name}.sigstore.json").read_bytes()
        return signer.verify_statement(statement, bundle_json, args["shards"], args["authorities"], args["policy"], rekor)

    def refused(self, why, *args, **kwargs):
        with self.assertRaises(signer.Unsigned) as caught:
            self.verify(*args, **kwargs)
        self.assertIn(why, str(caught.exception))

    def test_the_real_prod_dev_and_vendor_statements_verify(self):
        for name in ("prod", "dev"):
            self.assertEqual(self.verify(name), signer.Signed(REAL_COMMIT, REAL_RUN))
        vendor = LIVE / "live-a8c22105/vendor/249-20261110T072937Z"
        signed = self.verify("vendor", vendor.with_suffix(".statement.json").read_bytes(), vendor.with_suffix(".sigstore.json").read_bytes())
        self.assertEqual(signed.commit, REAL_COMMIT)

    def test_the_real_vendor_statement_is_what_its_commit_gives(self):
        statement = json.loads((LIVE / "live-a8c22105/vendor/249-20261110T072937Z.statement.json").read_bytes())
        expected = signer.expected_statement(statement, lambda name: (LIVE / "pins-1297f803" / name).read_bytes(), lambda: 249)
        self.assertEqual(expected, statement)

    def test_a_statement_changed_by_one_byte_is_refused(self):
        statement = (DOOR_TESTDATA / "prod.statement.json").read_bytes().replace(b'"revoked":false', b'"revoked":true ', 1)
        self.refused("the bundle signs another digest than the statement's", "prod", statement=statement)

    def test_the_private_signer_is_refused(self):
        private = DOOR_TESTDATA / "private-signer"
        self.refused("the SAN is https://github.com/Watermark-Labs/pins/.github/workflows/sign.yml@refs/heads/main",
                     "prod", (private / "prod.statement.json").read_bytes(), (private / "prod.sigstore.json").read_bytes())

    def test_another_repository_id_or_trigger_is_refused(self):
        with unittest.mock.patch.object(signer, "REPOSITORY_ID", "1"):
            self.refused("extension 1.3.6.1.4.1.57264.1.15 is '1437511167', not '1'", "prod")
        with unittest.mock.patch.object(signer, "TRIGGERS", ("schedule",)):
            self.refused("the run was started by 'push', not by one of schedule", "prod")

    def test_a_checkpoint_these_witnesses_did_not_cosign_is_refused(self):
        self.refused("the log entry does not verify: witnesses", "prod", policy=rekor.make_policy(3, [(w.vkey, w.operator) for w in WITNESSES]))

    def test_cosignatures_after_the_certificates_not_after_are_not_counted(self):
        load = x509.load_der_x509_certificate

        class Expired:
            def __init__(self, cert):
                self.cert, self.not_valid_after_utc = cert, cert.not_valid_before_utc

            def __getattr__(self, name):
                return getattr(self.cert, name)

        with unittest.mock.patch.object(signer.x509, "load_der_x509_certificate", lambda der: Expired(load(der))):
            self.refused("fewer than 3 counted cosignatures are at or before the certificate's NotAfter", "prod")

    def test_a_certificate_with_no_fulcio_ca_is_refused(self):
        self.refused("the certificate does not chain to a Fulcio CA", "prod", authorities=[])


if __name__ == "__main__":
    unittest.main()
