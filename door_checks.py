import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta

import door_records as records
import rekor
from revocation import Revocation

RECORDS_REPO_URL = "https://api.github.com/repos/trymorse/morse-records"
LIVE_GRACE = timedelta(hours=2)
RUN_GAP = timedelta(minutes=7)
MAX_KEY_AGE = timedelta(days=60)
POINTER_LATE = timedelta(minutes=20)
WITNESS_LAPSE = timedelta(hours=24)


class Unenforced(str):
    pass


class Note(str):
    pass


UNENFORCED = Unenforced("check 6 not enforced: needs --sequence-state from this watcher's earlier runs, which keeps every boot it has seen live and when it last ran, and this file has no last_run, so a boot that served before this run without a record cannot show")


def level(failure):
    return "NOT ENFORCED" if isinstance(failure, Unenforced) else "NOTE" if isinstance(failure, Note) else "FAIL"


@dataclass(frozen=True)
class Boot:
    first_seen: datetime | None
    spkis: dict[str, datetime | None]

    def young(self, now):
        return self.first_seen is not None and now - self.first_seen < LIVE_GRACE

    def seen(self):
        if self.first_seen is None:
            return "this watcher cannot date when it first saw it live, so how long it served is unknown"
        return f"this watcher first saw it live at {self.first_seen.isoformat(timespec='seconds')}"

    def showed_first(self, spki, handed):
        if handed not in self.spkis:
            return False
        a, b = self.spkis[spki], self.spkis[handed]
        return a is None or b is not None and a <= b


@dataclass
class Evidence:
    name: str
    environment: str
    certificates: list
    ct_counts: dict
    pointers: list
    verified: list
    notes: list
    shard_failures: list
    caa_history: list
    caa_accounts: set
    live: list
    tips: dict
    rewound: dict
    witnesses: dict
    trust: object
    records_visibility: str | None
    policy: object
    now: datetime
    boots: dict = field(default_factory=dict)
    last_run: datetime | None = None
    revocations: dict = field(default_factory=dict)
    ct_unread: dict = field(default_factory=dict)
    checkpoints: dict = field(default_factory=dict)
    signer: list = field(default_factory=list)
    signer_state: object = None

    def recorded(self):
        return {v.spki_sha256 for v in self.verified}

    def born(self):
        born = {}
        for v in self.verified:
            t = rekor.rfc3339(v.born, "origin.born")[0]
            born[v.spki_sha256] = min(born.get(v.spki_sha256, t), t)
        return born

    def pairs(self):
        pairs = {}
        for v in self.verified:
            pairs.setdefault(v.pair, []).append(v)
        return pairs


def unattested(c, recorded, born, now):
    if c.spki_sha256 not in recorded:
        if now - c.logged < POINTER_LATE:
            return Note(f"{c.source} names {', '.join(c.names)} with SPKI {c.spki_sha256}, which no verified record attests yet. CT made it public at {c.logged.isoformat(timespec='seconds')}, and it fails once {POINTER_LATE // timedelta(minutes=1)} minutes have passed without a pointer")
        return f"{c.source} names {', '.join(c.names)} with SPKI {c.spki_sha256}, which no verified record attests, and CT made it public at {c.logged.isoformat(timespec='seconds')}"
    if c.not_before > born[c.spki_sha256] + MAX_KEY_AGE:
        return f"{c.source} names {', '.join(c.names)} with SPKI {c.spki_sha256} from {c.not_before.isoformat(timespec='seconds')}, after the key, born at {born[c.spki_sha256].isoformat(timespec='seconds')}, was {MAX_KEY_AGE.days} days old"
    return None


def findings(ev):
    recorded, born = ev.recorded(), ev.born()
    return [(c, why) for c in ev.certificates if (why := unattested(c, recorded, born, ev.now))]


def failing(ev):
    return [c for c, why in findings(ev) if not isinstance(why, Note)]


def check_certificates(ev):
    recorded = ev.recorded()
    failures = [Note(f"{source} could not be read, so this run judges check 1 from {', '.join(ev.ct_counts)} alone: {e!r}") for source, e in ev.ct_unread.items()]
    for source, count in ev.ct_counts.items():
        others = {other: n for other, n in ev.ct_counts.items() if n}
        if count == 0 and (others or recorded):
            failures.append(f"{source} returned no certificate covering {ev.name}, though " + (", ".join(f"{o} returned {n}" for o, n in others.items()) if others else f"{len(recorded)} SPKIs have verified records"))
    for c, why in findings(ev):
        if isinstance(why, Note):
            failures.append(why)
            continue
        answer = ev.revocations.get(c.der, Revocation(None, "this run did not ask its CA"))
        if answer.revoked:
            failures.append(Note(f"revoked, skipped: {why}. Its CA revoked it, {answer.how}"))
        elif answer.revoked is False:
            failures.append(f"{why}. Its CA has not revoked it, {answer.how}")
        else:
            failures.append(f"{why}. Whether its CA revoked it is unknown, so it counts: {answer.how}")
    return failures


def check_records(ev):
    failures = list(ev.notes)
    for repo, (seen, tip) in sorted(ev.rewound.items()):
        failures.append(f"{repo} at {tip} does not descend from {seen}, which an earlier run saw, so its history was rewritten")
    return failures


def label(pair):
    return f"boot {pair[0]} with SPKI {pair[1]}"


def check_custody(ev):
    pairs, failures = ev.pairs(), []
    for pair, entries in sorted(pairs.items()):
        origins = sorted({v.origin for v in entries}, key=repr)
        if len(origins) > 1:
            failures.append(f"{label(pair)} has entries with {len(origins)} origins ({', '.join(v.name() for v in entries)}), and a boot fixes one origin per key")
            continue
        link, seen = pair, set()
        while True:
            _, sender, floor = pairs[link][0].origin
            if sender is None:
                break
            source = (sender, pair[1])
            if source not in pairs:
                failures.append(f"{label(pair)}: {label(link)} names sender {sender}, which has no verified record of that SPKI")
                break
            if pairs[source][0].floor > floor:
                failures.append(f"{label(pair)}: the floor falls from {pairs[source][0].floor} at {label(source)} to {floor} at {label(link)}")
                break
            if source in seen or source == pair:
                failures.append(f"{label(pair)}: custody loops at {label(source)}")
                break
            seen.add(link)
            link = source
    return failures


def check_logs(ev):
    return list(ev.shard_failures)


def caa_refusal(entry, accounts):
    match = re.fullmatch(r'\s*\d+\s+(\S+)\s+"(.*)"\s*', entry)
    if not match:
        return f"{entry!r} does not parse"
    tag, value = match.group(1).lower(), match.group(2)
    if tag == "iodef" or (tag in ("issue", "issuewild") and value.strip() == ";"):
        return None
    if tag not in ("issue", "issuewild"):
        return f"{entry} is a {tag} property this check does not allow"
    ca, *params = [p.strip() for p in value.split(";")]
    params = dict(p.split("=", 1) for p in params if "=" in p)
    if params.keys() != {"accounturi", "validationmethods"} or params["validationmethods"] != "dns-01" or (ca, params["accounturi"]) not in accounts:
        return f"{entry} is not one of Morse's ACME accounts with dns-01 only"
    return None


def check_caa(ev):
    if not ev.caa_history:
        return ["the CAA history has no samples"]
    failures = []
    for sample in ev.caa_history:
        if not any(re.match(r"\s*\d+\s+issue\s", e, re.I) for e in sample["caa"]):
            failures.append(f"at {sample['time']} no CAA issue property restricted who may issue")
        failures += [f"at {sample['time']}: {r}" for r in (caa_refusal(e, ev.caa_accounts) for e in sample["caa"]) if r]
    return failures


def check_live(ev):
    pairs, failures, held = ev.pairs(), [], set()
    if ev.last_run is not None and ev.now < ev.last_run - records.MAX_AHEAD:
        failures.append(f"this run's clock reads {ev.now.isoformat(timespec='seconds')}, before {ev.last_run.isoformat(timespec='seconds')}, when the last run wrote --sequence-state, and a clock that goes backwards stretches a boot's 2 hours")
    for n, seen in enumerate(ev.live, 1):
        if not isinstance(seen, records.Live):
            failures.append(f"live document {n}: {seen}")
            continue
        held.add((seen.key_id, seen.spki_sha256))
        if seen.unpinned:
            failures.append(f"live document {n} is from an image no record can admit: {seen.unpinned}")
        elif (seen.key_id, seen.spki_sha256) not in pairs and not ev.boots[seen.key_id].young(ev.now):
            failures.append(f"live document {n}: the boot with HPKE key {seen.key_id} holds SPKI {seen.spki_sha256}, which no verified record of that boot attests, and {ev.boots[seen.key_id].seen()}")
    took = {}
    for v in ev.verified:
        if v.sender is not None:
            took.setdefault(v.boot, {})[v.spki_sha256] = v.sender
    for key_id, boot in sorted(ev.boots.items()):
        if boot.young(ev.now):
            continue
        unrecorded = [spki for spki in boot.spkis if (key_id, spki) not in pairs]
        for spki in unrecorded:
            if (key_id, spki) in held:
                continue
            handed = [(h, sender) for h, sender in sorted(took.get(key_id, {}).items()) if h != spki and boot.showed_first(spki, h)]
            if len(unrecorded) == 1 and handed:
                h, sender = handed[0]
                when = f"before it took SPKI {h} from boot {sender}" if None not in (boot.spkis[spki], boot.spkis[h]) else f"beside SPKI {h} it took from boot {sender}, though this watcher's older state did not record when it saw each key"
                failures.append(Note(f"the boot with HPKE key {key_id} has no verified record of SPKI {spki}, which it held live {when}, so {spki} is taken as the key it was born with, which the door drops unlogged when it takes a key; check 1 still fails any certificate for it"))
            else:
                failures.append(f"the boot with HPKE key {key_id} has no verified record of SPKI {spki}, which it held live, and {boot.seen()}")
    if ev.last_run is None:
        return failures + [UNENFORCED]
    if ev.now - ev.last_run > RUN_GAP:
        return failures + [Unenforced(f"check 6 not enforced on this run: the last run was at {ev.last_run.isoformat(timespec='seconds')}, more than {RUN_GAP.seconds // 60} minutes before this one, so a boot that served only in between cannot show, and a state file restored from an older copy shows this way too")]
    return failures


def check_witnesses(ev):
    failures = []
    if isinstance(ev.trust, Exception):
        failures.append(f"the newest pinned image's trust.go could not be read: {ev.trust}")
        trust_names = set()
    else:
        tag, k, listed = ev.trust
        trust_names = {w.name for w in listed}
        if k < ev.policy.k:
            failures.append(f"trust.go in {tag} needs {k} cosignatures, fewer than this watcher's {ev.policy.k}")
        mine = {(w.name, w.key): w.operator for w in ev.policy.witnesses}
        for w in listed:
            if (w.name, w.key) not in mine:
                failures.append(f"trust.go in {tag} lists the witness key {w.name}+{w.hash.hex()}, which this watcher's policy does not")
            elif mine[(w.name, w.key)] != w.operator:
                failures.append(f"trust.go in {tag} lists {w.name} under {w.operator}, and this watcher under {mine[(w.name, w.key)]}")
    for origin, (lines, last_seen) in sorted(ev.witnesses.items()):
        for name in sorted(set(lines) - ev.policy.names() - trust_names - {origin}):
            failures.append(f"{origin}'s newest checkpoint carries a cosignature by {name}, which neither this watcher's policy nor the image's trust.go names")
        for name in sorted(ev.policy.names()):
            if ev.now - last_seen[name] > WITNESS_LAPSE:
                failures.append(f"{name} has not cosigned a checkpoint of {origin} that this watcher read since {last_seen[name].isoformat(timespec='seconds')}, and with k = {ev.policy.k} of {len(ev.policy.names())} a missing witness leaves no margin")
    return failures


def check_records_public(ev):
    if ev.records_visibility == "public":
        return []
    if isinstance(ev.records_visibility, Note):
        return [Note(f"{RECORDS_REPO_URL}, read with no token, {ev.records_visibility}, so this run does not judge check 9")]
    return [f"{RECORDS_REPO_URL}, read with no token, {ev.records_visibility}, so an outside watcher cannot read the pointers or the leaf archive"]
