#!/usr/bin/env python3
"""Generate split DNS batches and verify an instrumented tracer's UDP_IOV records.

The tracer must print pid, fd, direction, socket_id, cap_seq, cap_len,
syscall_len and hex (the captured payload) in each UDP_IOV record.
"""
import argparse
import ctypes
import json
import os
import re
import socket
import struct
import time


class Iovec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("length", ctypes.c_size_t)]


class Msghdr(ctypes.Structure):
    _fields_ = [("name", ctypes.c_void_p), ("namelen", ctypes.c_uint),
                ("iov", ctypes.POINTER(Iovec)), ("iovlen", ctypes.c_size_t),
                ("control", ctypes.c_void_p), ("controllen", ctypes.c_size_t),
                ("flags", ctypes.c_int)]


class Mmsghdr(ctypes.Structure):
    _fields_ = [("header", Msghdr), ("length", ctypes.c_uint)]


def dns_packet(txid, qtype):
    name = b"\x05batch\x03iov\x07example\x03com\x00"
    return struct.pack("!6H", txid, 0x100, 1, 0, 0, 0) + name + struct.pack("!HH", qtype, 1)


def split_packet(packet, count, empty_index=None):
    nonempty = count - (empty_index is not None)
    parts = [packet[i * len(packet) // nonempty:(i + 1) * len(packet) // nonempty]
             for i in range(nonempty)]
    if empty_index is not None:
        parts.insert(empty_index, b"")
    return parts


def generate(args):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.sendmmsg.argtypes = [ctypes.c_int, ctypes.POINTER(Mmsghdr), ctypes.c_uint, ctypes.c_int]
    libc.sendmmsg.restype = ctypes.c_int
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    records = []
    cases = [("single", 1, None, 1), ("split_2", 2, None, 1),
             ("leading_empty_2", 2, 0, 1), ("split_4", 4, None, 1),
             ("leading_empty_4", 4, 0, 1), ("split_8", 8, None, 1),
             ("leading_empty_8", 8, 0, 1), ("middle_empty_8", 8, 3, 1),
             ("first_split_4", 8, None, 4),
             ("over_limit", args.limit + 1, None, 1)]
    if args.limit > 8:
        for count in (12, 16, 18):
            if count <= args.limit:
                cases[-1:-1] = [("split_{}".format(count), count, None, 1),
                                ("leading_empty_{}".format(count), count, 0, 1)]
        cases[-1:-1] = [("middle_empty_limit", args.limit, args.limit // 2, 1),
                        ("first_split_4_at_limit", args.limit, None, 4)]
    try:
        server.bind(("127.0.0.1", args.port))
        client.bind(("127.0.0.2", 0))
        server.settimeout(3)
        address = ctypes.create_string_buffer(
            struct.pack("=H", socket.AF_INET) + struct.pack("!H", args.port)
            + socket.inet_aton("127.0.0.1") + b"\0" * 8)
        for case_index, (name, count, empty_index, first_count) in enumerate(cases):
            packets = [dns_packet(0x5000 + case_index * 2, 1),
                       dns_packet(0x5001 + case_index * 2, 28)]
            fragments = [split_packet(packets[0], first_count),
                         split_packet(packets[1], count, empty_index)]
            messages = (Mmsghdr * 2)()
            keepalive = []
            for index, parts in enumerate(fragments):
                buffers = [ctypes.create_string_buffer(part) for part in parts]
                vector = (Iovec * len(parts))(*[
                    Iovec(ctypes.cast(buffer, ctypes.c_void_p), len(part))
                    for part, buffer in zip(parts, buffers)])
                keepalive.extend([buffers, vector])
                messages[index].header = Msghdr(
                    ctypes.cast(address, ctypes.c_void_p), 16, vector, len(parts), None, 0, 0)
            sent = libc.sendmmsg(client.fileno(), messages, 2, 0)
            if sent != 2:
                raise OSError(ctypes.get_errno(), "sendmmsg returned {}".format(sent))
            received = [server.recvfrom(2048)[0] for unused in range(2)]
            if received != packets:
                raise AssertionError("wire payload mismatch: " + name)
            for index, packet in enumerate(packets):
                captured = packet if index == 0 else b"".join(fragments[index][:args.limit])
                records.append(dict(case=name, message=index + 1, pid=os.getpid(),
                                    fd=client.fileno(), txid=struct.unpack("!H", packet[:2])[0],
                                    iov_count=len(fragments[index]), length=len(packet),
                                    captured_hex=captured.hex(), wire_hex=packet.hex()))
            print("[WIRE OK] {} second_iov_count={}".format(name, count), flush=True)
            time.sleep(0.05)
    finally:
        client.close()
        server.close()
    with open(args.expectations, "w") as output:
        json.dump(dict(limit=args.limit, records=records), output, indent=2)


def verify(args):
    expected = json.load(open(args.expectations))
    with open(args.tracer_log, errors="replace") as source:
        lines = source.read().splitlines()
    events = {}
    for line in lines:
        if not line.startswith("UDP_IOV "):
            continue
        fields = dict(re.findall(r"(\w+)=([^ ]*)", line))
        if fields.get("direction") != "out":
            continue
        payload = bytes.fromhex(fields["hex"])
        if len(payload) < 2:
            continue
        key = (int(fields["pid"]), int(fields["fd"]), struct.unpack("!H", payload[:2])[0])
        events.setdefault(key, []).append(fields)
    peer_ids = set()
    sequences = []
    for record in expected["records"]:
        key = (record["pid"], record["fd"], record["txid"])
        found = events.get(key, [])
        if len(found) != 1:
            raise AssertionError("{} message {}: {} callbacks".format(
                record["case"], record["message"], len(found)))
        event = found[0]
        if (event["hex"] != record["captured_hex"]
                or int(event["cap_len"]) != len(bytes.fromhex(record["captured_hex"]))
                or int(event["syscall_len"]) != record["length"]):
            raise AssertionError("payload/length mismatch: {} message {}: {}".format(
                record["case"], record["message"], event))
        peer_ids.add(event["socket_id"])
        sequences.append(int(event["cap_seq"]))
    if len(peer_ids) != 1:
        raise AssertionError("inconsistent same-peer identity: {}".format(peer_ids))
    if any(sequences[i + 1] != sequences[i] + 1 for i in range(0, len(sequences), 2)):
        raise AssertionError("nonconsecutive batch sequences: {}".format(sequences))
    if args.peer_id_enabled and sorted(sequences) != list(range(len(sequences))):
        raise AssertionError("nonconsecutive peer sequences: {}".format(sequences))
    print("[OK] {} callbacks: exact payloads, lengths, stable ID and {} sequences".format(
        len(expected["records"]), "peer" if args.peer_id_enabled else "batch"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("expectations")
    parser.add_argument("--limit", type=int, default=8)
    parser.add_argument("--port", type=int, default=53053)
    parser.add_argument("--tracer-log", help="verify a completed run instead of generating traffic")
    parser.add_argument("--peer-id-enabled", action="store_true",
                        help="also require contiguous peer sequences across batches")
    arguments = parser.parse_args()
    if arguments.tracer_log:
        verify(arguments)
    else:
        generate(arguments)
