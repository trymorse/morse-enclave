"""Reads of a local git checkout, for check_door.py and signer_watch.py."""

import subprocess


def git(directory, *args):
    return subprocess.run(["git", "-C", str(directory), *args], check=True, capture_output=True, text=True).stdout


def descends(directory, seen):
    return subprocess.run(["git", "-C", str(directory), "merge-base", "--is-ancestor", seen, "HEAD"], capture_output=True).returncode == 0
