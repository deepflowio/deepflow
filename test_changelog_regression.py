import unittest
from update_changelog import format_pr_list


class MissingAuthorTest(unittest.TestCase):
    def test_missing_author_preserves_entry(self):
        for author in (None, {}, {"login": ""}):
            with self.subTest(author=author):
                pr = {"title": "fix: example", "number": 1,
                      "url": "https://example.com/1", "author": author}
                self.assertEqual(format_pr_list([pr]),
                                 ["* fix: example [#1](https://example.com/1)"])

    def test_existing_author_preserves_attribution(self):
        pr = {"title": "fix: example", "number": 1,
              "url": "https://example.com/1", "author": {"login": "tester"}}
        self.assertEqual(format_pr_list([pr]), [
            "* fix: example [#1](https://example.com/1) by [tester](https://github.com/tester)"])
