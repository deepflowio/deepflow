import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


class RegionAliasTest(unittest.TestCase):
    def test_region_aliases_share_an_index(self):
        spec = importlib.util.spec_from_file_location(
            "ip_info", Path(__file__).with_name("ip_info.py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.jsonl"
            rows = [
                {"ip_start": i, "ip_end": i, "region": region}
                for i, region in enumerate(["黑龙", "黑龙江", "内蒙", "内蒙古"], 1)
            ]
            source.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
            module.FILE_NAME = str(Path(directory) / "ip_info.go")
            module.gen_code(str(source))
            generated = Path(module.FILE_NAME).read_text(encoding="utf-8")
            entries = [line for line in generated.splitlines() if "IPStart:" in line]
            self.assertIn("Region: 1,", entries[0])
            self.assertIn("Region: 1,", entries[1])
            self.assertIn("Region: 2,", entries[2])
            self.assertIn("Region: 2,", entries[3])
            self.assertIn('var REGION_NAMES = [...]string{"未知", "黑龙江", "内蒙古"}', generated)
            self.assertIn('"黑龙江":1, "内蒙古":2}', generated)


if __name__ == "__main__":
    unittest.main()
