import importlib.util
import sys
import types
import unittest
from pathlib import Path


def _load_kafka_apis():
    lxml = types.ModuleType("lxml")
    lxml.html = types.ModuleType("lxml.html")
    sys.modules["lxml"] = lxml
    sys.modules["lxml.html"] = lxml.html
    sys.modules["requests"] = types.ModuleType("requests")

    path = Path(__file__).with_name("kafka-apis.py")
    spec = importlib.util.spec_from_file_location("kafka_apis", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FindHeaderVersionTest(unittest.TestCase):
    def test_missing_header_metadata_is_reported_as_unknown(self):
        kafka_apis = _load_kafka_apis()

        self.assertIsNone(kafka_apis.find_header_version([], 0))

    def test_nearest_header_version_is_preserved(self):
        kafka_apis = _load_kafka_apis()
        header_versions = [(0, "1"), (3, "2")]

        self.assertEqual(kafka_apis.find_header_version(header_versions, 1), "2")
        self.assertEqual(kafka_apis.find_header_version(header_versions, 4), "2")


if __name__ == "__main__":
    unittest.main()
