import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


class GeneratedNamesTest(unittest.TestCase):
    def test_special_names_are_escaped_in_arrays_and_maps(self):
        path = Path(__file__).with_name('ip_info.py')
        spec = importlib.util.spec_from_file_location('ip_info', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        names = ['A"B', 'R\\D', 'line\nbreak', '中文', '\x00']
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'input.json'
            source.write_text('\n'.join(json.dumps({
                'ip_start': i, 'ip_end': i, 'country': name,
                'region': name, 'isp': name,
            }) for i, name in enumerate(names)), encoding='utf-8')
            module.FILE_NAME = str(Path(directory) / 'ip_info.go')
            module.gen_code(source)
            output = Path(module.FILE_NAME).read_text(encoding='utf-8')
            for name in names:
                literal = json.dumps(name, ensure_ascii=False)
                self.assertEqual(output.count(literal), 6)
