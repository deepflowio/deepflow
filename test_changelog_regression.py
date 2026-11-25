from pathlib import Path
import tempfile
import unittest
from update_changelog import update_changelog


class ChangelogIdempotenceTest(unittest.TestCase):
    def test_existing_entries_leave_file_unchanged(self):
        pr = {"title": "fix: example", "number": 1,
              "url": "https://example.com/1", "author": {"login": "tester"}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "CHANGELOG.md"
            update_changelog(path, {"Bug Fix": [pr]}, "main")
            first = path.read_bytes()
            update_changelog(path, {"Bug Fix": [pr]}, "main")
            self.assertEqual(path.read_bytes(), first)
            newer = dict(pr, number=2, url="https://example.com/2")
            update_changelog(path, {"Bug Fix": [newer, pr]}, "main")
            self.assertIn("[#2]", path.read_text(encoding="utf-8"))
            self.assertEqual(path.read_text(encoding="utf-8").count("[#1]"), 1)
