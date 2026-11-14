"""Check 7 of check_door.py: the public image signer, sign.yml in trymorse/morse-pins. It reads GitHub's record of who
pushed morse-pins main and which sign.yml runs there were, the .github trees on main, and the statements branch, whose
statements signer.py verifies."""

import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta

import rekor
import signer
from door_checks import Note, Unenforced
from door_git import descends, git
from github_read import read_github

# The public image signer, sign.yml in trymorse/morse-pins, for check 7. Its code is the .github tree of the commit a
# run signs, so a change to it shows twice in public: once as the commit, and once as a change to this allowlist.
# b06ce985 is the tree of 4e2a388c, the commit that added sign.yml (trymorse/morse-pins#1).
SIGNER_TREES = {"b06ce985178151ac41cc22a84b2b8a7d033b2f80"}
SIGNER_WORKFLOW = ".github/workflows/sign.yml"
STATEMENTS_REF = "origin/statements/images"
GITHUB_API = "https://api.github.com/"
PUSHES_URL = GITHUB_API + "repos/trymorse/morse-pins/activity?ref=refs%2Fheads%2Fmain&direction=desc&per_page=100"
RUNS_URL = GITHUB_API + "repos/trymorse/morse-pins/actions/workflows/sign.yml/runs?per_page=100"
RUN_URL = GITHUB_API + "repos/trymorse/morse-pins/actions/runs/"
RUNS_OVERLAP = timedelta(hours=1)
FIRST_LOOKBACK = timedelta(days=14)
# Data reaches main only as the publisher app's push, and a person's change only as a pull request an admin merged.
PUBLISHER = "morse-pins-publisher[bot]"
ADMINS = ("youdaniel", "justinyshen")
# The activity list can lag a push, and a run can sign a commit pushed after the checkout.
ACTIVITY_LAG = 30
SIGNER_LATE = timedelta(hours=1)


def add_arguments(parser):
    """check-door.py's options for check 7."""
    parser.add_argument("--statements", default=STATEMENTS_REF, help=f"the ref of the --pins checkout that holds the signer's statements, {STATEMENTS_REF} if omitted")
    parser.add_argument("--ack-refused", action="append", default=[], metavar="SHA", help="the commit a refused push to morse-pins main ends at, once it has been read; check 7 fails every run until it is named")
    parser.add_argument("--ack-run", action="append", default=[], type=int, metavar="NUMBER", help="the number of a refused or missing sign.yml run, once it has been read; check 7 fails every run until it is named")
    parser.add_argument("--signer-tree", action="append", default=[], metavar="TREE", help="a .github tree of morse-pins to allow beside the ones signer_watch.py lists, once its change has been read")


def check(ev):
    return list(ev.signer)


def fetch_github(url):
    """One page of a GitHub API listing, and the URL of the next page, which its Link header names."""
    headers = {"User-Agent": "check-door", "Accept": "application/vnd.github+json"}
    if os.environ.get("GH_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GH_TOKEN']}"
    body, reply_headers = read_github(url, headers)
    link = re.search(r'<([^>]+)>;\s*rel="next"', reply_headers.get("Link") or "")
    return body, link and link[1]


def read_listing(url, items=lambda body: body, until=lambda item: False):
    """The items of a GitHub listing from url on, through the first page that holds an item until accepts."""
    out = []
    while url:
        if not url.startswith(GITHUB_API):
            raise ValueError(f"the listing's next page is {url}, not on {GITHUB_API}")
        body, url = fetch_github(url)
        page = items(json.loads(body))
        out += page
        if any(until(item) for item in page):
            break
    return out


def github_time(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def read_pushes(last, now, added):
    """The events on morse-pins main from last, the event this watcher last judged, on, oldest first, read newest
    first until it, or None when the listing no longer holds it. With no last, from the newest event that is older
    than FIRST_LOOKBACK or ends at added, the commit that added sign.yml, or None when none is listed."""
    if last:
        start = lambda e: e.get("id") == last["id"]
        until = lambda e: start(e) or github_time(e["timestamp"]) < github_time(last["timestamp"])
    else:
        start = until = lambda e: github_time(e["timestamp"]) < now - FIRST_LOOKBACK or e.get("after") == added
    events = read_listing(PUSHES_URL, until=until)[::-1]
    at = [i for i, e in enumerate(events) if start(e)]
    return events[at[-1]:] if at else None


def changed_paths(pins_dir, before, after):
    r = subprocess.run(["git", "-C", str(pins_dir), "diff", "--no-renames", "--name-only", before, after], capture_output=True, text=True)
    return r.stdout.split() if r.returncode == 0 else None


def push_refusal(pins_dir, event):
    actor, kind = (event.get("actor") or {}).get("login"), event.get("activity_type")
    what = f"the {kind} by {actor} at {event.get('timestamp')}, from {event['before']} to {event['after']},"
    if kind == "push" and actor == PUBLISHER:
        allowed, why = (lambda path: not path.startswith(".github/")), "the signer's code, which only an admin's merged pull request may change"
    elif kind == "pr_merge" and actor in ADMINS:
        allowed, why = (lambda path: path not in signer.SIGNED_FILES), f"a file the signer signs, which only {PUBLISHER} pushes"
    else:
        return f"morse-pins main had a {kind} by {actor} at {event.get('timestamp')}, and only a push by {PUBLISHER} or a pull request an admin merged may move it"
    changed = changed_paths(pins_dir, event["before"], event["after"])
    if changed is None:
        return f"{what} cannot be compared in this checkout"
    if any(not allowed(path) for path in changed):
        return f"{what} changes {', '.join(p for p in changed if not allowed(p))}: {why}"
    return None


def check_pushes(pins_dir, head, last, added, unlisted_since, now):
    """The failures of the pushes to morse-pins main since last, the event this watcher last judged, through the last
    one that ends at head, each starting where the one before it ended, the refused pushes by the commit each ends at,
    the event the next run starts from, and since when this watcher has seen head unlisted, if it is."""
    events = read_pushes(last, now, added)
    if events is not None and not any(e.get("after") == head for e in events):
        time.sleep(ACTIVITY_LAG)
        events = read_pushes(last, now, added)
    if events is None:
        if last:
            message = f"the activity API no longer lists event {last['id']} on morse-pins main, at {last['timestamp']}, the last this watcher judged, so the pushes since cannot be checked"
        else:
            message = f"the activity API lists no event on morse-pins main that ends at {added}, which added {SIGNER_WORKFLOW}, and none is {FIRST_LOOKBACK.days} days old, so the pushes since cannot be checked"
        return [message], {}, last, unlisted_since
    ends = [i for i, e in enumerate(events) if e.get("after") == head]
    if not ends:
        since = unlisted_since or now
        message = (f"the activity API lists no push that ends at the checkout's morse-pins main {head}, so a push that moved it is missing, "
                   f"and this watcher has seen main unlisted since {since.isoformat(timespec='seconds')}")
        return [Note(message) if now - since < SIGNER_LATE else message], {}, last, since
    refused, tip = {}, events[0]["after"]
    for event in events[1:ends[-1] + 1]:
        found = [] if event.get("before") == tip else [f"morse-pins main moved from {tip} to {event.get('before')} with no push listed"]
        found += [r for r in [push_refusal(pins_dir, event)] if r]
        if found:
            refused[event["after"]] = found
        tip = event["after"]
    return [], refused, {"id": events[ends[-1]]["id"], "timestamp": events[ends[-1]]["timestamp"]}, None


def check_trees(pins_dir, trees):
    commits = git(pins_dir, "rev-list", "--first-parent", "HEAD").split()
    found = subprocess.run(["git", "-C", str(pins_dir), "cat-file", "--batch-check"], input="".join(f"{c}:.github\n" for c in commits),
                           check=True, capture_output=True, text=True).stdout.splitlines()
    off = {}
    for commit, line in zip(commits, found):
        tree = None if line.endswith(" missing") else line.split()[0]
        if tree is not None and tree not in trees:
            off.setdefault(tree, []).append(commit)
    return [f"morse-pins main has a .github tree {tree} that the allowlist does not name, in {len(listed)} commits from {listed[-1]} on"
            for tree, listed in sorted(off.items())]


def git_bytes(directory, *args):
    return subprocess.run(["git", "-C", str(directory), *args], check=True, capture_output=True).stdout


def read_added(pins_dir, ref, *patterns):
    """(commit, path) for each file matching patterns that a commit on ref added."""
    added = []
    for chunk in git(pins_dir, "log", "--no-renames", "--diff-filter=A", "--name-only", "--format=%x00%H", ref, "--", *patterns).split("\0")[1:]:
        commit, *paths = chunk.split()
        added += [(commit, path) for path in paths]
    return added


def statement_refusals(pins_dir, path, raw, signed):
    statement = json.loads(raw)
    commit = statement.get("pins_commit")
    if signed.commit != commit:
        return [f"{path} names pins_commit {commit}, and its certificate was issued to a run at {signed.commit}"]
    if not descends(pins_dir, commit):
        return [f"{path} names {commit}, which is not on morse-pins main"]
    expected = signer.expected_statement(statement, lambda name: git_bytes(pins_dir, "show", f"{commit}:{name}"),
                                         lambda: int(git(pins_dir, "rev-list", "--count", commit)))
    failures = []
    for key in sorted(statement.keys() | expected.keys()):
        if statement.get(key) == expected.get(key):
            continue
        if key == "sequence":
            failures.append(f"{path} has sequence {statement.get(key)}, not the commit count {expected.get(key)} of {commit}")
        elif key in ("images", "files"):
            failures.append(f"{path} lists other {key} than {'enclave_pins.json' if key == 'images' else 'the vendor pins files'} at {commit} give it")
        else:
            failures.append(f"{path} has {key} {statement.get(key)!r}, not {expected.get(key)!r}")
    return failures


def check_statements(pins_dir, ref, verified, verify):
    """The failures of every statement ever added to the statements branch and not verified by an earlier run, which
    adds each one that passes to verified. A statement deleted at the tip is still read from the commit that added it."""
    if subprocess.run(["git", "-C", str(pins_dir), "rev-parse", "-q", "--verify", f"{ref}^{{commit}}"], capture_output=True).returncode:
        return [f"the morse-pins checkout has no {ref}, so the statements the signer made cannot be read: clone it with every branch"]
    failures = [f"{path} was changed after it was added, and the signer only adds statements"
                for path in sorted(set(git(pins_dir, "log", "--no-renames", "--diff-filter=MT", "--name-only", "--format=", ref, "--", "*.statement.json", "*.sigstore.json").split()))]
    added = read_added(pins_dir, ref, "*.statement.json")
    paths = [path for _, path in added]
    failures += [f"{path} was added more than once" for path in sorted({p for p in paths if paths.count(p) > 1})]
    for commit, path in sorted(added, key=lambda a: a[1]):
        if path in verified or paths.count(path) > 1:
            continue
        try:
            raw = git_bytes(pins_dir, "show", f"{commit}:{path}")
            signed = verify(raw, git_bytes(pins_dir, "show", f"{commit}:{path.removesuffix('.statement.json')}.sigstore.json"))
            refusals = statement_refusals(pins_dir, path, raw, signed)
        except signer.Unsigned as e:
            refusals = [f"{path} is not signed by sign.yml on main of trymorse/morse-pins: {e}"]
        except (subprocess.CalledProcessError, ValueError, KeyError, TypeError, AttributeError) as e:
            refusals = [f"{path} or its bundle cannot be read: {e!r}"]
        failures += refusals
        if not refusals:
            verified.add(path)
    return failures


def judge_run(pins_dir, r, now):
    """Why a completed sign.yml run is refused, a Note while its commit may still reach this checkout, or None."""
    if r.get("conclusion") != "success":
        return None
    where = f"sign.yml run {r['run_number']} succeeded from a {r.get('event')} on {r.get('head_branch')} at {r.get('head_sha')}"
    known = subprocess.run(["git", "-C", str(pins_dir), "cat-file", "-e", f"{r.get('head_sha')}^{{commit}}"], capture_output=True).returncode == 0
    if r.get("head_branch") != "main" or r.get("event") not in signer.TRIGGERS:
        return f"{where}, which is not a push or schedule run on main"
    if known and not descends(pins_dir, r["head_sha"]):
        return f"{where}, which is not on morse-pins main"
    if not known:
        message = f"{where}, which this checkout does not hold, and it fails once the run is {SIGNER_LATE // timedelta(minutes=1)} minutes old"
        young = now - github_time(r["created_at"]) < SIGNER_LATE
        return Note(message) if young else message
    return None


def check_runs(pins_dir, runs, seen_through, pending, now):
    """The refused sign.yml runs by number, the notes, the runs left pending by number with their ids, and the new
    seen_through, below which every number is judged, refused or pending. runs holds the runs listed and each pending
    one. GitHub numbers a workflow's runs in order, and a deleted run leaves its number missing."""
    listed = {r["run_number"]: r for r in runs}
    top = max([seen_through, *listed])
    refused = {n: [f"sign.yml run {n} is missing, so it was deleted"] for n in range(seen_through + 1, top + 1) if n not in listed}
    notes, waiting = [], {}
    for n, r in sorted(listed.items()):
        if n <= seen_through and n not in pending:
            continue
        verdict = None if r.get("status") != "completed" else judge_run(pins_dir, r, now)
        if r.get("status") != "completed" or isinstance(verdict, Note):
            waiting[n] = int(r["id"])
            notes += [verdict] if verdict else []
        elif verdict:
            refused[n] = [verdict]
    return refused, notes, waiting, top


@dataclass
class SignerState:
    """What check 7 keeps between runs. last is the id and timestamp of the push event on main this watcher last
    judged, and a run with none is a first run. runs_read_at is when sign.yml's runs were last read, pending_runs
    holds the id of each run not yet judged by its number, and refused_runs each refused or missing run's failures by
    its number until --ack-run names it. refused holds each
    refused push's failures by the commit it ends at until --ack-refused names it, and unlisted_since is when this
    watcher first saw main unlisted."""
    last: dict | None
    runs_seen_through: int
    runs_read_at: datetime | None
    pending_runs: dict
    refused_runs: dict
    verified: set
    refused: dict
    unlisted_since: datetime | None

    @classmethod
    def read(cls, saved):
        """The state check-door.py's --sequence-state saved, where saved is its JSON, or a first run's from {}."""
        when = {k: None if saved.get(k) is None else datetime.fromisoformat(saved[k]) for k in ("runs_read_at", "unlisted_since")}
        return cls(saved.get("last_push"), saved.get("runs_seen_through") or 0, when["runs_read_at"],
                   {int(n): i for n, i in (saved.get("pending_runs") or {}).items()}, {int(n): found for n, found in (saved.get("refused_runs") or {}).items()},
                   set(saved.get("verified_statements") or []), saved.get("refused_pushes") or {}, when["unlisted_since"])

    def saved(self):
        """The keys this state adds to the --sequence-state JSON, which read reads back."""
        return {"last_push": self.last, "runs_seen_through": self.runs_seen_through, "runs_read_at": self.runs_read_at and self.runs_read_at.isoformat(),
                "pending_runs": self.pending_runs, "refused_runs": self.refused_runs, "verified_statements": sorted(self.verified),
                "refused_pushes": self.refused, "unlisted_since": self.unlisted_since and self.unlisted_since.isoformat()}


def read_signer(pins_dir, ref, trees, kept, acked, acked_runs, now, verify):
    """Check 7's failures and the state the next run starts from. A read of GitHub that fails leaves its part
    unenforced and its state where it was. A refused push fails every run until acked names the commit it ends at,
    and a refused or missing run until acked_runs names its number."""
    failures = [Note(f"--ack-refused {sha} names no refused push this watcher keeps") for sha in acked if sha not in kept.refused]
    failures += [Note(f"--ack-run {n} names no refused run this watcher keeps") for n in acked_runs if n not in kept.refused_runs]
    state = SignerState(kept.last, kept.runs_seen_through, kept.runs_read_at, dict(kept.pending_runs),
                        {n: found for n, found in kept.refused_runs.items() if n not in acked_runs}, set(kept.verified),
                        {sha: found for sha, found in kept.refused.items() if sha not in acked}, kept.unlisted_since)
    head = git(pins_dir, "rev-parse", "HEAD").strip()
    added = git(pins_dir, "log", "--first-parent", "--diff-filter=A", "--format=%H", "HEAD", "--", SIGNER_WORKFLOW).split()
    if state.last is None and not added:
        failures.append(f"morse-pins main never held {SIGNER_WORKFLOW}, so the pushes since it was added cannot be checked")
    else:
        try:
            pushed, refused, state.last, state.unlisted_since = check_pushes(pins_dir, head, state.last, added[-1] if added else None, state.unlisted_since, now)
            failures += pushed
            state.refused |= refused
        except (OSError, ValueError, KeyError, TypeError) as e:
            failures.append(Unenforced(f"check 7 not enforced on this run: the activity of morse-pins main could not be read: {e!r}"))
    failures += [f"{failure}, and this fails every run until --ack-refused {sha}" for sha, found in state.refused.items() for failure in found]
    failures += check_trees(pins_dir, trees)
    failures += check_statements(pins_dir, ref, state.verified, verify)
    since = state.runs_read_at - RUNS_OVERLAP if state.runs_read_at else now - FIRST_LOOKBACK
    try:
        runs, deleted = read_listing(f"{RUNS_URL}&created=%3E%3D{since.strftime('%Y-%m-%dT%H:%M:%SZ')}", lambda body: body["workflow_runs"]), []
        for n, run_id in sorted(state.pending_runs.items()):
            if n in {r["run_number"] for r in runs}:
                continue
            try:
                runs.append(json.loads(fetch_github(f"{RUN_URL}{int(run_id)}")[0]))
            except urllib.error.HTTPError as e:
                if e.code != 404:
                    raise
                deleted.append(n)
    except (OSError, ValueError, KeyError, TypeError) as e:
        failures.append(Unenforced(f"check 7 not enforced on this run: sign.yml's runs could not be read: {e!r}"))
    else:
        seen_through = state.runs_seen_through if state.runs_read_at else max([state.runs_seen_through, min([r["run_number"] for r in runs], default=1) - 1])
        refused, notes, state.pending_runs, state.runs_seen_through = check_runs(pins_dir, runs, seen_through, state.pending_runs, now)
        state.refused_runs |= refused | {n: [f"sign.yml run {n} is missing, so it was deleted"] for n in deleted}
        state.runs_read_at = now if state.runs_read_at or runs else None
        failures += notes
    failures += [f"{failure}, and this fails every run until --ack-run {n}" for n, found in sorted(state.refused_runs.items()) for failure in found]
    return failures, state


def watch(pins_dir, args, kept, now, trusted_root, shards, policy):
    """Check 7's failures and the state the next run starts from, under check-door.py's --statements, --signer-tree,
    --ack-refused and --ack-run, verifying each statement against trusted_root's authorities and Rekor shards."""
    authorities = []

    def verify(statement, bundle):
        if trusted_root is None:
            raise signer.Unsigned("Sigstore's trusted root could not be read through TUF")
        authorities[:] = authorities or signer.read_authorities(trusted_root, rekor.rfc3339)
        return signer.verify_statement(statement, bundle, shards, authorities, policy, rekor)

    try:
        return read_signer(pins_dir, args.statements, SIGNER_TREES | set(args.signer_tree), kept, set(args.ack_refused), set(args.ack_run), now, verify)
    except (subprocess.CalledProcessError, OSError, ValueError) as e:
        return [f"check 7 could not read the morse-pins checkout: {e!r}"], kept
