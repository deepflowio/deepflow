import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


class UnknownNameTest(unittest.TestCase):
    def test_unknown_reuses_reserved_zero_index(self):
        spec = importlib.util.spec_from_file_location('ip_info', Path(__file__).with_name('ip_info.py'))
        module = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {'ujson': json}):
            spec.loader.exec_module(module)
        encoder = module.Encoder()
        self.assertEqual(encoder.encode('未知'), 0)
        self.assertEqual(encoder.encode('known'), 1)
        self.assertEqual(encoder.encode('未知'), 0)
        self.assertEqual(encoder.items, ['未知', 'known'])
