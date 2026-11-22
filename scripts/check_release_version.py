"""Check that a pending stable version covers all unreleased conventional commits."""

import re
import subprocess
import sys
import tomllib


STABLE = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
SUBJECT = re.compile(r"([A-Za-z][A-Za-z0-9-]*)(?:\([^)]+\))?(!)?:\s?.+")
BREAKING = re.compile(r"^BREAKING[- ]CHANGE\b", re.MULTILINE)


def stable_version(value):
    match = STABLE.fullmatch(value)
    return tuple(map(int, match.groups())) if match else None


def required_version(released, messages):
    major, minor, patch = released
    required = released
    for message in messages:
        if not message.strip():
            continue
        subject = SUBJECT.fullmatch(message.splitlines()[0].strip())
        if BREAKING.search(message) or (subject and subject[2]):
            return major + 1, 0, 0
        if subject and subject[1] == "feat":
            required = max(required, (major, minor + 1, 0))
        if subject and subject[1] == "fix":
            required = max(required, (major, minor, patch + 1))
    return required


def git(*args):
    return subprocess.check_output(["git", *args], encoding="utf-8")


def check_release(target):
    if not re.fullmatch(r"[0-9a-f]{40}", target):
        raise ValueError("Expected an exact 40-character Git commit SHA")
    manifest = tomllib.loads(git("show", f"{target}:Cargo.toml"))
    version = manifest["package"]["version"]
    current = stable_version(version)
    if current is None:
        raise ValueError(f"Automatic release requires a stable manifest version, got {version}")

    stable_tags = [
        (parsed, tag)
        for tag in git("tag", "--list", "v*").splitlines()
        if (parsed := stable_version(tag[1:])) is not None
    ]
    if not stable_tags:
        raise ValueError("Automatic release requires an existing stable release tag")
    released, tag = max(stable_tags)
    if current < released:
        raise ValueError(f"Manifest version {version} is behind stable release {tag}")
    if current == released:
        return  # The reusable workflow may propose a bump, but cannot tag this version again.

    # Refuse a divergent baseline, and use the same non-merge commit history as auto-release.
    git("merge-base", "--is-ancestor", tag, target)
    messages = git("log", "--no-merges", "-z", "--format=%B", f"{tag}..{target}").split("\0")
    floor = required_version(released, messages)
    if current < floor:
        needed = ".".join(map(str, floor))
        raise ValueError(
            f"Manifest version {version} at {target} is below required version {needed} "
            f"for changes since {tag}. Merge a reviewed version correction before releasing."
        )


if __name__ == "__main__":
    try:
        check_release(sys.argv[1])
    except (IndexError, KeyError, ValueError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
