import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class GenerateDocTest(unittest.TestCase):
    def test_invalid_yaml_comment_reports_error_without_crashing(self):
        script = Path(__file__).with_name("gendoc.py")
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temp_dir:
            Path(temp_dir, "template.yaml").write_text(
                "# [invalid\nkey: value\n", encoding="utf-8"
            )
            Path(temp_dir, "yaml.py").write_text(
                "class YAMLError(Exception):\n"
                "    pass\n\n"
                "class SafeLoader:\n"
                "    pass\n\n"
                "def load_all(_comment, Loader=None):\n"
                "    raise YAMLError('invalid test comment')\n\n"
                "def safe_load(_content):\n"
                "    return {'key': 'value'}\n",
                encoding="utf-8",
            )
            env = os.environ.copy()
            env["PYTHONPATH"] = temp_dir

            result = subprocess.run(
                [sys.executable, str(script)],
                cwd=temp_dir,
                capture_output=True,
                env=env,
                text=True,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ERROR: parsing YAML comment at key", result.stderr)
        self.assertNotIn("UnboundLocalError", result.stderr)


if __name__ == "__main__":
    unittest.main()
