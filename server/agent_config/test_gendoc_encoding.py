import builtins
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch
import os


class DocumentationEncodingTest(unittest.TestCase):
    def test_non_utf8_default_still_writes_utf8(self):
        script = Path(__file__).with_name('gendoc.py').resolve()
        original_open = builtins.open

        def non_utf8_open(file, mode='r', *args, **kwargs):
            if 'b' not in mode and not args and 'encoding' not in kwargs:
                kwargs['encoding'] = 'ascii'
            return original_open(file, mode, *args, **kwargs)

        previous = Path.cwd()
        with tempfile.TemporaryDirectory() as directory:
            try:
                os.chdir(directory)
                Path('template.yaml').write_text(
                    '# type: section\n# name: 中文标题\nsection: {}\n',
                    encoding='utf-8')
                with patch('builtins.open', non_utf8_open):
                    runpy.run_path(str(script))
                for filename in ('README.md', 'README-CH.md'):
                    self.assertIn('中文标题', Path(filename).read_text(encoding='utf-8'))
            finally:
                os.chdir(previous)
