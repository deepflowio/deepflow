# -*- coding: UTF-8 -*-
import socketio
import uuid
import json
import time
import sys
import getopt
import os

UUID = ""
execed = False
sio = socketio.Client()
keys = [
    "worker_number", "df_env_number", "test_case", "df_server_image_tag",
    "df_agent_image_tag", "df_env_fixed", "no_report", "feishu_robots",
    "branch", "uuid", "timestamp", "user", "debug"
]
params_default = {
    "WORKER_NUMBER": 3,
    "DF_ENV_NUMBER": 1,
    "TEST_CASE": "all",
    "DF_SERVER_IMAGE_TAG": "latest",
    "DF_AGENT_IMAGE_TAG": "latest",
    "DF_ENV_FIXED": 0,
    "NO_REPORT": 0,
    "FEISHU_ROBOTS": "",
    "BRANCH": "master",
    "UUID": "",
    "TIMESTAMP": int(time.time()) // 60 * 60,
    "USER": "",
    "DEBUG": 0,
}
params_env_key = {
    "WORKER_NUMBER": "PYTEST_XDIST_WORKER_NUMBER",
    "DF_ENV_NUMBER": "PYTEST_DF_ENV_NUMBER",
    "TEST_CASE": "TEST_CASE",
    "DF_SERVER_IMAGE_TAG": "DEEPFLOW_SERVER_IMAGE_TAG",
    "DF_AGENT_IMAGE_TAG": "DEEPFLOW_AGENT_IMAGE_TAG",
    "DF_ENV_FIXED": "DF_ENVS_FIXED",
    "NO_REPORT": "NO_REPORT",
    "FEISHU_ROBOTS": "FEISHU_ROBOTS",
    "BRANCH": "DF_TEST_BRANCH",
    "UUID": "TEST_EXEC_UUID",
    "TIMESTAMP": "TEST_EXEC_TIMESTAMP",
    "USER": "GITHUB_ACTOR",
    "DEBUG": "DEBUG"
}
for _, key in params_env_key.items():
    print(f"{key}: {os.environ.get(key)}")
params = {}
token = ""


@sio.on('connect')
def on_connect():
    print("client connect")
    global execed
    global params
    global token
    sio.emit("authentication", token)
    time.sleep(1)
    if not execed:
        data = json.dumps(params)
        sio.emit("exec", data)
        execed = True


@sio.on('runner-logs')
def logs(data):
    print("".join(data))


@sio.on('runner-logs-error')
def error(data):
    print(data)
    sio.disconnect()
    assert False


@sio.on('runner-logs-finished')
def finished(data):
    print('client receive:', data)
    sio.disconnect()


if __name__ == '__main__':
    opts, args = getopt.getopt(sys.argv[1:], '', [f"{key}=" for key in keys])
    UUID = str(uuid.uuid4())[:7]
    print(opts, args)
    for opt_name, opt_values in opts:
        if opt_values:
            params[opt_name.upper().replace("--", "")] = opt_values
    url = os.environ.get("AUTOMATION_TEST_PUBLIC_URL", "")
    token = os.environ.get("AUTOMATION_TEST_TOKEN", "")
    if not url or not token:
        sys.exit(1)
    if not params.get("UUID"):
        params["UUID"] = UUID
    for key in keys:
        key = key.upper()
        if params.get(key, None) is None:
            env_key = params_env_key[key]
            if os.environ.get(env_key) is not None:
                params[key] = os.environ.get(env_key)
            else:
                params[key] = params_default[key]
    print(params)
    params["AUTOMATION_TEST_TOKEN"] = token
    sio.connect(f'ws://{url}',  wait_timeout = 10)
    sio.wait()
