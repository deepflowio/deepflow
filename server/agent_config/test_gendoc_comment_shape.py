import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

class CommentShapeTest(unittest.TestCase):
    def run_generator(self, comment):
        script = Path(__file__).with_name('gendoc.py')
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, 'template.yaml').write_text(comment + '\noption: {}\n', encoding='utf-8')
            result = subprocess.run([sys.executable, str(script)], cwd=directory,
                env=dict(os.environ, PYTHONUTF8='1'), capture_output=True,
                text=True, encoding='utf-8', timeout=10)
            docs = [Path(directory, name).read_text(encoding='utf-8')
                    for name in ('README.md', 'README-CH.md') if Path(directory, name).exists()]
            return result, docs

    def test_invalid_comment_shapes(self):
        for comment in ('# scalar', '# []', '# type: section\n# ---\n# type: dict'):
            with self.subTest(comment=comment):
                result, docs = self.run_generator(comment)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('ERROR: invalid YAML comment structure at option', result.stderr)
                self.assertEqual(docs, ['', ''])

    def test_valid_section(self):
        result, docs = self.run_generator('# type: section\n# name: Example')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        self.assertEqual(len(docs), 2)
        self.assertTrue(all('Example' in doc for doc in docs))

if __name__ == '__main__':
    unittest.main()
