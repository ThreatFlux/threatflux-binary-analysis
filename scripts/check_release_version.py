"""Check that a pending stable version covers all unreleased conventional commits."""

import re
import sys
import tomllib
from pathlib import Path


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
        subject = SUBJECT.fullmatch(message.partition("\n")[0].strip())
        if BREAKING.search(message) or (subject and subject[2]):
            return major + 1, 0, 0
        if subject and subject[1] == "feat":
            required = max(required, (major, minor + 1, 0))
        if subject and subject[1] == "fix":
            required = max(required, (major, minor, patch + 1))
    return required


def check_release(tag, version, messages):
    released = stable_version(tag.removeprefix("v"))
    current = stable_version(version)
    if released is None or current is None:
        raise ValueError(f"Automatic release requires stable versions, got {tag} and {version}")
    if current < released:
        raise ValueError(f"Manifest version {version} is behind stable release {tag}")
    if current == released:
        return  # The reusable workflow may propose a bump, but cannot tag this version again.

    floor = required_version(released, messages)
    if current < floor:
        needed = ".".join(map(str, floor))
        raise ValueError(
            f"Manifest version {version} is below required version {needed} "
            f"for changes since {tag}. Merge a reviewed version correction before releasing."
        )


if __name__ == "__main__":
    try:
        tag, manifest_path, commits_path = sys.argv[1:]
        manifest = tomllib.loads(Path(manifest_path).read_text(encoding="utf-8"))
        commits = Path(commits_path).read_text(encoding="utf-8").split("\0")
        check_release(tag, manifest["package"]["version"], commits)
    except (KeyError, OSError, ValueError) as error:
        sys.exit(str(error))
