import unittest

import check_release_version as guard


class ReleaseVersionTest(unittest.TestCase):
    def test_pending_patch_requires_a_new_review_when_main_gains_a_feature(self):
        commits = ["fix: initial patch", "chore: reviewed version bump", "feat(api): later feature"]
        with self.assertRaisesRegex(ValueError, "below required version 0.5.0"):
            guard.check_release("v0.4.1", "0.4.2", commits)

    def test_reviewed_version_that_covers_all_changes_can_release(self):
        guard.check_release("v0.4.1", "0.5.0", ["fix: initial patch", "feat: later feature"])

    def test_an_already_released_manifest_can_propose_the_next_version(self):
        guard.check_release("v0.4.1", "0.4.1", ["feat: pending proposal"])

    def test_breaking_footer_and_subject_require_a_major_bump(self):
        for message in ("docs: notes\n\nBREAKING CHANGE: incompatible", "feat(api)!: incompatible"):
            with self.subTest(message=message):
                self.assertEqual(guard.required_version((0, 4, 1), [message]), (1, 0, 0))
