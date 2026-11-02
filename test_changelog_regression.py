import subprocess
import unittest
from unittest.mock import patch
from update_changelog import get_recent_prs, main


class FetchFailureTest(unittest.TestCase):
    @patch("update_changelog.subprocess.run")
    def test_query_failure_propagates(self, run):
        run.return_value = subprocess.CompletedProcess([], 1, "", "denied")
        with self.assertRaises(RuntimeError):
            main("main", "unused")

    @patch("update_changelog.subprocess.run")
    def test_empty_success_is_valid(self, run):
        run.return_value = subprocess.CompletedProcess([], 0, "[]", "")
        self.assertEqual(get_recent_prs("main"), [])
