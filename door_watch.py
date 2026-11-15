"""Runs check-door.py on a schedule: retries a run that could not read its evidence, counts the runs in a row that ended the same way, and decides the alert a run sends.

Usage: python3 door_watch.py --state <dir> [--alerts] [--restored <cache key>] --run-url <url> --alert-body alert.md [--setup-code N --setup-log setup.txt] -- <check-door.py command>

It passes --verdict to the command, so the kind of each run comes from check-door.py's JSON verdict. It reruns only a
run whose reads of CT, Rekor, TUF or DNS raised. GitHub is retried inside check-door.py (github_read.py, after 2s and 5s), and a
GitHub read that still fails ends as a check 7 or check 9 result, so this does not rerun it. A run with no
verdict, or one whose exit code is not the verdict's, could not watch the door. It keeps the last kind and how many
runs in a row had it in <dir>/streak. It also keeps, in <dir>/ct-streak, how many runs in a row each CT source could
not be read and since when: a run that read the source restarts it, and a run that read no evidence leaves it as it
was. With --alerts it writes the alert's label, title and comment hours to GITHUB_OUTPUT and its body to
--alert-body, and exits 1 when the run failed a check or could not read its evidence. On each run that finds a CT
source's count at CT_ALERT_AFTER or more and its entry not marked "alerted" it also writes ct_alert and ct_title to
GITHUB_OUTPUT and that alert's body to --ct-alert-body. The workflow's step that sends that alert marks the entry
"alerted" once the alert is sent, so a send that fails is tried again on the next run, and each time the source goes
down alerts once.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

ATTEMPTS = 3
RETRY_WAIT = 20
ALERT_AFTER = 3
CT_ALERT_AFTER = 36
LOST = "found no state from an earlier run in the Actions cache, so the checks that the Rekor shards and the morse-pins and morse-records histories only grow restarted from this run"


@dataclass(frozen=True)
class Run:
    code: int
    output: str
    kind: str
    unenforced: tuple = ()
    retryable: bool = False
    failed: tuple = ()
    ct: tuple = ()


@dataclass(frozen=True)
class Alert:
    label: str
    title: str
    hours: int
    body: str


def judge(code, output, verdict):
    if verdict is None or verdict.get("exit") != code:
        return Run(code, output, "unread")
    return Run(code, output, verdict["kind"], tuple(verdict["unenforced"]), verdict["retryable"], tuple(verdict["failed"]), tuple((verdict.get("ct") or {}).items()))


def read_verdict(path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def watch(command):
    with tempfile.TemporaryDirectory() as tmp:
        verdict = Path(tmp) / "verdict.json"
        for attempt in range(1, ATTEMPTS + 1):
            verdict.unlink(missing_ok=True)
            done = subprocess.run([*command, "--verdict", str(verdict)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")
            run = judge(done.returncode, done.stdout, read_verdict(verdict))
            if not run.retryable:
                return run
            print(f"attempt {attempt}: {run.output.rstrip(chr(10))}", flush=True)
            if attempt < ATTEMPTS:
                time.sleep(RETRY_WAIT)
        return run


def streak(path, kind):
    kept = path.read_text().split() if path.exists() else []
    count = int(kept[1]) + 1 if kept[:1] == [kind] and len(kept) > 1 and kept[1].isdigit() else 1
    path.write_text(f"{kind} {count}\n")
    return count


def ct_streaks(path, ct, now):
    try:
        kept = json.loads(path.read_text())
    except (OSError, ValueError):
        kept = {}
    kept = kept if isinstance(kept, dict) else {}
    for source, why in ct:
        if why is None:
            kept.pop(source, None)
            continue
        was = kept.get(source) if isinstance(kept.get(source), dict) else {}
        kept[source] = {**was, "count": int(was.get("count") or 0) + 1, "since": was.get("since") or now.isoformat(timespec="seconds"), "why": why}
    path.write_text(json.dumps(kept, sort_keys=True) + "\n")
    return kept


def ct_down(streaks, run):
    return {source: streaks[source] for source, why in run.ct if why is not None and streaks[source]["count"] >= CT_ALERT_AFTER and not streaks[source].get("alerted")}


def compose_ct(down, run, run_url):
    read = ", ".join(source for source, why in run.ct if why is None) or "the other sources"
    lines = [f"{source} could not be read on {kept['count']} door-watch runs in a row, since {kept['since']}, so check 1 has judged the door's certificates from {read} alone, "
             f"and a certificate that only {source} returns goes unseen until it reads again. Its last error: {kept['why']}" for source, kept in down.items()]
    title = f"The inference door's watcher could not read {', '.join(down)} on {CT_ALERT_AFTER} or more runs in a row"
    return Alert("door-watch-ct", title, 0, "\n\n".join(lines) + f"\n\nThe last of those runs is {run_url}\n\n```\n{run.output}```\n")


def alert_for(kind, count, restored):
    if kind == "failed":
        return "failed"
    if not restored:
        return "lost"
    if kind != "passed" and count >= ALERT_AFTER:
        return kind
    return None


def compose(alert, run, restored, run_url):
    label, hours = "door-watch", 1
    match alert:
        case "failed":
            label, hours = "door-watch-failed", 0
            title = "The inference door's watcher failed a check"
            failed = sorted(set(run.failed))
            what = f"failed {', '.join(f'check {n}' for n in failed) or 'a check'}"
            if 1 in failed:
                what += ". A certificate for inference.trymorse.ai whose key no verified record attests can be a rogue certificate: read check 1 first"
            if 6 in failed:
                what += ". Check 6 failing usually means /v1/attestation listed a boot that has no verified record of a key it held 2 hours after this watcher first saw it, or one from an image no record can admit. The FAIL lines below give the cause, which can also be a bad or stale --ack-boot, a clock behind the last run, or a live document that could not be read. A boot that died before it could log its record never will, and once its entry is in UNRECORDED-BOOTS.md, --ack-boot acknowledges it"
            if not restored:
                what += f". It also {LOST}"
        case "unread":
            title = "The inference door's watcher could not read its evidence"
            what = "could not read its evidence on three runs in a row, so it checked nothing for about 15 minutes"
        case "unenforced":
            checks = ", ".join(f"check {n}" for n in sorted(set(run.unenforced)))
            title = f"The inference door's watcher has not enforced {checks}"
            what = f"left {checks} unenforced on three runs in a row, as its NOT ENFORCED lines say"
            if 6 in run.unenforced:
                what += ". Check 6 unenforced means runs are more than 7 minutes apart and a boot listed only between two of them without a record cannot show. Check that EventBridge's DoorWatchEvery5Minutes dispatches this workflow"
        case "lost":
            title, what = "The inference door's watcher lost its kept state", LOST
    return Alert(label, title, hours, f"check-door.py exited {run.code} and {what}, in {run_url}\n\n```\n{run.output}```\n")


def append(path, text):
    if path:
        with open(path, "a") as f:
            f.write(text)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--state", required=True, help="the directory check-door.py keeps its state in, where this keeps the streak")
    parser.add_argument("--alerts", action="store_true", help="decide an alert and fail a run that failed a check or could not read its evidence; without it no run alerts or fails")
    parser.add_argument("--restored", default="", help="the cache key the state was restored from; empty when no earlier run's state was found")
    parser.add_argument("--run-url", default="", help="the run's URL, for the alert's body")
    parser.add_argument("--alert-body", required=True, help="the file to write the alert's body to")
    parser.add_argument("--ct-alert-body", required=True, help="the file to write the alert's body to when a CT source could not be read on CT_ALERT_AFTER or more runs in a row and has not been alerted")
    parser.add_argument("--setup-code", type=int, default=0, help="the exit code of the setup before check-door.py; when not 0 check-door.py does not run and the run could not watch")
    parser.add_argument("--setup-log", help="the setup's output, which stands in for check-door.py's when the setup failed")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="-- and then the check-door.py command")
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command

    if args.setup_code:
        run = Run(args.setup_code, Path(args.setup_log).read_text(errors="replace") if args.setup_log else "", "unread")
    else:
        run = watch(command)
    print(run.output, end="", flush=True)
    state = Path(args.state)
    state.mkdir(parents=True, exist_ok=True)
    count = streak(state / "streak", run.kind)
    streaks = ct_streaks(state / "ct-streak", run.ct, datetime.now(timezone.utc))
    unread = "".join(f" {source} could not be read on {kept['count']} run(s) in a row." for source, kept in sorted(streaks.items()))
    append(os.environ.get("GITHUB_STEP_SUMMARY"), f"check-door.py exited {run.code}: {run.kind}, {count} run(s) in a row.{unread}\n\n```\n{run.output}```\n")
    if not args.alerts:
        return 0
    down = ct_down(streaks, run)
    if down:
        sent = compose_ct(down, run, args.run_url)
        Path(args.ct_alert_body).write_text(sent.body)
        append(os.environ.get("GITHUB_OUTPUT"), f"ct_alert={','.join(down)}\nct_title={sent.title}\n")
    alert = alert_for(run.kind, count, args.restored)
    if alert:
        sent = compose(alert, run, args.restored, args.run_url)
        Path(args.alert_body).write_text(sent.body)
        append(os.environ.get("GITHUB_OUTPUT"), f"alert={alert}\nlabel={sent.label}\ntitle={sent.title}\nhours={sent.hours}\n")
    return 1 if run.kind in ("failed", "unread") else 0


if __name__ == "__main__":
    sys.exit(main())
