import importlib.util
import sys
import types
import unittest
from pathlib import Path


class _SocketIOClient:
    def on(self, _event):
        return lambda func: func


def _load_ws_client():
    socketio = types.ModuleType("socketio")
    socketio.Client = _SocketIOClient
    sys.modules["socketio"] = socketio

    path = Path(__file__).with_name("ws_client.py")
    spec = importlib.util.spec_from_file_location("ws_client", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CheckVariablesTest(unittest.TestCase):
    def test_default_test_case_is_supported(self):
        ws_client = _load_ws_client()
        params = ws_client.params_default.copy()

        ws_client.check_variables(params)

        self.assertEqual(params["TEST_CASE"], "all")


if __name__ == "__main__":
    unittest.main()
