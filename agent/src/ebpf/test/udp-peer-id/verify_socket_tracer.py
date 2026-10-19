#!/usr/bin/env python3

import re
import sys
from collections import defaultdict
from pathlib import Path


EVENT_PATTERN = re.compile(
    r"UDP_PEER .*?process=(?P<process>\S+) .*?fd=(?P<fd>\d+) "
    r"direction=(?P<direction>in|out) socket_id=(?P<socket_id>\d+) "
    r"cap_seq=(?P<cap_seq>\d+) local=(?P<local_ip>[^: ]+):(?P<local_port>\d+) "
    r"remote=(?P<remote_ip>[^: ]+):(?P<remote_port>\d+)"
)
EXPECTED_REMOTE_IPS = {"127.0.0.2", "127.0.0.3"}


def fail(message):
    print(f"[FAIL] {message}", file=sys.stderr)
    return 1


def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} SOCKET_TRACER_LOG", file=sys.stderr)
        return 2

    events = defaultdict(list)
    for line in Path(sys.argv[1]).read_text(errors="replace").splitlines():
        match = EVENT_PATTERN.search(line)
        if match is None or match.group("process") != "udp_peer_server":
            continue
        event = match.groupdict()
        if event["remote_ip"] in EXPECTED_REMOTE_IPS:
            events[event["remote_ip"]].append(event)

    missing = EXPECTED_REMOTE_IPS - events.keys()
    if missing:
        return fail(f"missing server events for peers: {sorted(missing)}")

    peer_socket_ids = {}
    for remote_ip in sorted(EXPECTED_REMOTE_IPS):
        peer_events = events[remote_ip]
        socket_ids = {event["socket_id"] for event in peer_events}
        directions = {event["direction"] for event in peer_events}
        sequences = sorted(int(event["cap_seq"]) for event in peer_events)
        fds = {event["fd"] for event in peer_events}

        if len(socket_ids) != 1:
            return fail(f"peer {remote_ip} has multiple socket IDs: {socket_ids}")
        if directions != {"in", "out"}:
            return fail(f"peer {remote_ip} directions are {directions}, expected in/out")
        if sequences != [0, 1]:
            return fail(f"peer {remote_ip} cap_seq is {sequences}, expected [0, 1]")
        if len(fds) != 1:
            return fail(f"peer {remote_ip} uses multiple server FDs: {fds}")
        peer_socket_ids[remote_ip] = next(iter(socket_ids))

    if len(set(peer_socket_ids.values())) != len(EXPECTED_REMOTE_IPS):
        return fail(f"different peers share socket ID: {peer_socket_ids}")

    all_fds = {event["fd"] for peer_events in events.values() for event in peer_events}
    if len(all_fds) != 1:
        return fail(f"server peers do not share one physical FD: {all_fds}")

    print("[OK] UDP peer socket ID isolation")
    for remote_ip in sorted(EXPECTED_REMOTE_IPS):
        print(
            f"  peer={remote_ip} fd={next(iter(all_fds))} "
            f"socket_id={peer_socket_ids[remote_ip]} cap_seq=0,1"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
