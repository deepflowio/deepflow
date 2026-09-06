#!/usr/bin/env python3
import argparse
import ctypes
import json
import os
import socket
import sys
import time
from typing import Tuple


DEFAULT_HOST = "10.50.120.81"
DEFAULT_PORT = 18081
DEFAULT_PATH = "/v1/chat/completions"
DEFAULT_SYSCALL_ID = 169  # x86_64 SYS_reboot


def send_ai_request(host: str, port: int, path: str, timeout: float) -> Tuple[str, bytes]:
    body = json.dumps({"model": "x", "messages": []}, separators=(",", ":")).encode()
    request = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode() + body

    with socket.create_connection((host, port), timeout=timeout) as conn:
        conn.sendall(request)
        response = conn.recv(4096)

    status_line = response.splitlines()[0].decode(errors="replace") if response else ""
    return status_line, response


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Trigger AI-agent scope, then verify direct reboot syscall is blocked with EPERM."
    )
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--path", default=DEFAULT_PATH)
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--tries", type=int, default=30)
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--syscall-id", type=int, default=DEFAULT_SYSCALL_ID)
    args = parser.parse_args()

    status_line, _ = send_ai_request(args.host, args.port, args.path, args.timeout)
    print(status_line, flush=True)
    print(f"AI_HTTP_SENT pid={os.getpid()}", flush=True)

    libc = ctypes.CDLL(None, use_errno=True)
    for attempt in range(1, args.tries + 1):
        time.sleep(args.interval)
        ctypes.set_errno(0)
        rc = libc.syscall(args.syscall_id, 0, 0, 0, 0)
        err = ctypes.get_errno()
        print(f"TRY {attempt}: rc={rc} errno={err}", flush=True)
        if err == 1:
            return 0

    print("REBOOT_SYSCALL_NOT_BLOCKED", flush=True)
    return 2


if __name__ == "__main__":
    sys.exit(main())
