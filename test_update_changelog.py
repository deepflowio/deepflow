import unittest

from update_changelog import PR_TYPE_MAPPING, categorize_prs


class CategorizePrsTest(unittest.TestCase):
    def test_conventional_types(self):
        for pr_type, category in PR_TYPE_MAPPING.items():
            for prefix in (pr_type, f"{pr_type}(server)", f"{pr_type}!", f"{pr_type}(server)!"):
                with self.subTest(prefix=prefix):
                    pr = {"title": f"{prefix}: update behavior"}
                    result = categorize_prs([pr])
                    self.assertEqual(result[category], [pr])
                    self.assertEqual(sum(map(len, result.values())), 1)

    def test_description_does_not_override_type(self):
        cases = [
            ("feat: Add fixed id for remote execution commands", "NEW FEATURE"),
            ("feat: support prefix matching", "NEW FEATURE"),
            ("perf: optimize prefix lookup", "Performance"),
            ("docs: describe new features", "Documentation"),
            ("test: cover fix and feature behavior", "Testing"),
        ]
        for title, category in cases:
            with self.subTest(title=title):
                pr = {"title": title}
                self.assertEqual(categorize_prs([pr])[category], [pr])

    def test_unrecognized_titles_use_other(self):
        for title in ("support prefix matching", "feature: add parser", "Revert fix: parser", "fixup: parser"):
            with self.subTest(title=title):
                pr = {"title": title}
                self.assertEqual(categorize_prs([pr])["OTHER"], [pr])

    def test_case_insensitive_type(self):
        pr = {"title": "FIX(agent): handle empty input"}
        self.assertEqual(categorize_prs([pr])["Bug Fix"], [pr])

    def test_generated_changelog_prs_are_excluded(self):
        prs = [{"title": "chore: Update changelog for main"}]
        self.assertTrue(all(not prs for prs in categorize_prs(prs).values()))


if __name__ == "__main__":
    unittest.main()
