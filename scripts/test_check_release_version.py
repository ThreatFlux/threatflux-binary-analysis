import unittest
from unittest import mock

import check_release_version as guard


class ReleaseVersionTest(unittest.TestCase):
    def test_pending_patch_requires_a_new_review_when_main_gains_a_feature(self):
        target = "a" * 40
        with mock.patch.object(
            guard,
            "git",
            side_effect=[
                '[package]\nversion = "0.4.2"\n',
                "v0.4.1\nv0.5.0-rc.1\n",
                "",
                "fix: initial patch\0chore: reviewed version bump\0feat(api): later feature\0",
            ],
        ) as git:
            with self.assertRaisesRegex(ValueError, "below required version 0.5.0"):
                guard.check_release(target)
            git.assert_any_call("merge-base", "--is-ancestor", "v0.4.1", target)
            git.assert_any_call(
                "log", "--no-merges", "-z", "--format=%B", f"v0.4.1..{target}"
            )

    def test_reviewed_version_that_covers_all_changes_can_release(self):
        with mock.patch.object(
            guard,
            "git",
            side_effect=[
                '[package]\nversion = "0.5.0"\n',
                "v0.4.1\n",
                "",
                "fix: initial patch\0feat: later feature\0",
            ],
        ):
            guard.check_release("a" * 40)

    def test_an_already_released_manifest_can_propose_the_next_version(self):
        with mock.patch.object(
            guard, "git", side_effect=['[package]\nversion = "0.4.1"\n', "v0.4.1\n"]
        ) as git:
            guard.check_release("a" * 40)
            self.assertEqual(git.call_count, 2)

    def test_breaking_footer_and_subject_require_a_major_bump(self):
        for message in ("docs: notes\n\nBREAKING CHANGE: incompatible", "feat(api)!: incompatible"):
            with self.subTest(message=message):
                self.assertEqual(guard.required_version((0, 4, 1), [message]), (1, 0, 0))
