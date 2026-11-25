from pathlib import Path
import tempfile
import unittest
from update_changelog import update_changelog, PR_TYPE_MAPPING


class InitialHeadingTest(unittest.TestCase):
    def test_new_file_has_single_feature_heading(self):
        pr = {'title': 'feat: example', 'number': 1,
              'url': 'https://example.com/1', 'author': {'login': 'tester'}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'CHANGELOG.md'
            update_changelog(path, {PR_TYPE_MAPPING['feat']: [pr]}, 'main')
            text = path.read_text(encoding='utf-8')
            self.assertEqual(text.lower().count('#### new feature'), 1)
            self.assertIn('[#1]', text)
