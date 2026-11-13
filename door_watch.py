"""Runs check-door.py on a schedule: retries a run that could not read its evidence, counts the runs in a row that ended the same way, and decides the alert a run sends.

Usage: python3 door_watch.py --state <dir> [--alerts] [--restored <cache key>] --run-url <url> --alert-body alert.md [--setup-code N --setup-log setup.txt] -- <check-door.py command>

It passes --verdict to the command, so the kind of each run comes from check-door.py's JSON verdict. A run with no
verdict, or one whose exit code is not the verdict's, could not watch the door. It keeps the last kind and how many
runs in a row had it in <dir>/streak. With --alerts it writes the alert's label, title and comment hours to
GITHUB_OUTPUT and its body to --alert-body, and exits 1 when the run failed a check or could not read its evidence.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

ATTEMPTS = 3
RETRY_WAIT = 20
ALERT_AFTER = 3
LOST = "found no state from an earlier run in the Actions cache, so the checks that the Rekor shards and the morse-pins and morse-records histories only grow restarted from this run"


@dataclass(frozen=True)
class Run:
    code: int
    output: str
    kind: str
    unenforced: tuple = ()
    retryable: bool = False


@dataclass(frozen=True)
class Alert:
    label: str
    title: str
    hours: int
    body: str


def judge(code, output, verdict):
    if verdict is None or verdict.get("exit") != code:
        return Run(code, output, "unread")
    return Run(code, output, verdict["kind"], tuple(verdict["unenforced"]), verdict["retryable"])


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
            what = "failed a check. A certificate for inference.trymorse.ai whose key no verified record attests can be a rogue certificate: read check 1 first"
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
                what += ". Check 6 unenforced means runs are more than 7 minutes apart and a boot that served between two of them without a record cannot show. Check that EventBridge's DoorWatchEvery5Minutes dispatches this workflow"
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
    append(os.environ.get("GITHUB_STEP_SUMMARY"), f"check-door.py exited {run.code}: {run.kind}, {count} run(s) in a row.\n\n```\n{run.output}```\n")
    if not args.alerts:
        return 0
    alert = alert_for(run.kind, count, args.restored)
    if alert:
        sent = compose(alert, run, args.restored, args.run_url)
        Path(args.alert_body).write_text(sent.body)
        append(os.environ.get("GITHUB_OUTPUT"), f"alert={alert}\nlabel={sent.label}\ntitle={sent.title}\nhours={sent.hours}\n")
    return 1 if run.kind in ("failed", "unread") else 0


if __name__ == "__main__":
    sys.exit(main())
