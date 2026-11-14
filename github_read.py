"""Reads of GitHub's API, for check_door.py and signer_watch.py. This is the only place the watcher retries GitHub:
door_watch.py reruns a check only when its reads of CT, Rekor, TUF and DNS raised, and every GitHub read here ends in a
check 7 or check 9 result instead of an exception."""

import time
import urllib.error
import urllib.request

# .github/scripts/gh-retry.sh holds the same delays and failures for gh calls; ci_public_scripts_test.go keeps them equal.
GITHUB_RETRY_DELAYS = (2, 5)


def read_github(url, headers):
    """GitHub's answer to url and its headers. A 5xx, a 429 or a reset or refused connection is tried again after
    each of GITHUB_RETRY_DELAYS, since GitHub answers one now and then; any other failure, a timeout among them, is
    raised at once."""
    for delay in (*GITHUB_RETRY_DELAYS, None):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as reply:
                return reply.read(), reply.headers
        except urllib.error.HTTPError as e:
            if delay is None or (e.code < 500 and e.code != 429):
                raise
        except OSError as e:
            if delay is None or not isinstance(getattr(e, "reason", e), ConnectionError):
                raise
        time.sleep(delay)


def rate_limited(e):
    """Whether GitHub refused with e for a rate limit rather than for the request: a 429, or a 403 that says so in
    x-ratelimit-remaining: 0, a retry-after or its message. A runner that shares its address uses up the 60 reads an
    hour GitHub allows with no token, and a 403 then says nothing about the repository."""
    headers = e.headers or {}
    return e.code == 429 or e.code == 403 and (headers.get("x-ratelimit-remaining") == "0" or headers.get("retry-after") is not None or b"rate limit" in e.read().lower())
