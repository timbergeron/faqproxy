#!/usr/bin/env python3
"""Black-box tests for the NetQuake handshake and byte-exact relay."""

from __future__ import annotations

import argparse
import os
import pathlib
import signal
import socket
import stat
import struct
import subprocess
import tempfile
import time
from dataclasses import dataclass

NETFLAG_DATA = 0x00010000
NETFLAG_ACK = 0x00020000
NETFLAG_EOM = 0x00080000
NETFLAG_UNRELIABLE = 0x00100000
NETFLAG_CTL = 0x80000000
PEXT2_PREDINFO = 0x00000020
PRFL_FLOATANGLE = 1 << 2


@dataclass(frozen=True)
class ProtocolCase:
    case_id: int
    protocol: int
    angle_mode: str
    proquake: bool = False
    predinfo: bool = False


def control(command: int, payload: bytes) -> bytes:
    length = 5 + len(payload)
    return struct.pack("!I", NETFLAG_CTL | length) + bytes([command]) + payload


def connected(flags: int, sequence: int, payload: bytes = b"") -> bytes:
    length = 8 + len(payload)
    return struct.pack("!II", flags | length, sequence) + payload


def free_udp_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def receive(sock: socket.socket) -> tuple[bytes, tuple[str, int]]:
    data, address = sock.recvfrom(65535)
    return data, (address[0], address[1])


def connect_request(proquake: bool = False) -> bytes:
    payload = b"QUAKE\x00\x03"
    if proquake:
        payload += bytes([1, 35, 0]) + struct.pack("<I", 0)
    return control(0x01, payload)


def movement_message(case: ProtocolCase, angles: tuple[float, float, float]) -> bytes:
    payload = bytearray()
    if case.predinfo:
        payload += bytes([50]) + struct.pack("<I", 1234)
    payload += bytes([3])
    if case.predinfo:
        payload += struct.pack("<Hf", 7, 1.25)
    else:
        payload += struct.pack("<f", 1.25)
    if case.angle_mode == "byte":
        payload += bytes(round(angle * 256.0 / 360.0) & 0xFF for angle in angles)
    elif case.angle_mode == "short":
        for angle in angles:
            payload += struct.pack("<H", round(angle * 65536.0 / 360.0) & 0xFFFF)
    elif case.angle_mode == "float":
        payload += struct.pack("<fff", *angles)
    else:
        raise AssertionError(case.angle_mode)
    payload += struct.pack("<hhhBB", 100, -50, 0, 1, 0)
    return bytes(payload)


def exercise_protocol(
    case: ProtocolCase,
    proxy_port: int,
    control_server: socket.socket,
) -> tuple[bytes, tuple[float, float, float]]:
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(("127.0.0.1", 0))
    client.settimeout(3)

    request = connect_request(case.proquake)
    client.sendto(request, ("127.0.0.1", proxy_port))
    forwarded, upstream = receive(control_server)
    assert forwarded == request

    game_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    game_server.bind(("127.0.0.1", 0))
    game_server.settimeout(3)
    accept_payload = struct.pack("<I", game_server.getsockname()[1])
    if case.proquake:
        accept_payload += bytes([1, 30, 0])
    accept = control(0x81, accept_payload)
    control_server.sendto(accept, upstream)
    rewritten, _ = receive(client)
    assert rewritten[4] == 0x81
    assert struct.unpack_from("<I", rewritten, 5)[0] == proxy_port

    protocol_payload = bytes([11])
    if case.predinfo:
        protocol_payload += b"FTE2" + struct.pack("<I", PEXT2_PREDINFO)
    protocol_payload += struct.pack("<I", case.protocol)
    if case.protocol == 999:
        protocol_payload += struct.pack("<I", PRFL_FLOATANGLE)
    split = max(1, len(protocol_payload) // 2)
    first = connected(NETFLAG_DATA, 0, protocol_payload[:split])
    second = connected(NETFLAG_DATA | NETFLAG_EOM, 1, protocol_payload[split:])
    game_server.sendto(first, upstream)
    assert receive(client)[0] == first
    ack = connected(NETFLAG_ACK, 0)
    client.sendto(ack, ("127.0.0.1", proxy_port))
    assert receive(game_server)[0] == ack
    game_server.sendto(second, upstream)
    assert receive(client)[0] == second
    ack = connected(NETFLAG_ACK, 1)
    client.sendto(ack, ("127.0.0.1", proxy_port))
    assert receive(game_server)[0] == ack

    expected_angles = (45.0, 90.0, 270.0)
    client_unreliable = connected(
        NETFLAG_UNRELIABLE, 0, movement_message(case, expected_angles)
    )
    client.sendto(client_unreliable, ("127.0.0.1", proxy_port))
    assert receive(game_server)[0] == client_unreliable

    marker = bytes([1, case.case_id, 0xA5])
    server_unreliable = connected(NETFLAG_UNRELIABLE, 0, marker)
    game_server.sendto(server_unreliable, upstream)
    assert receive(client)[0] == server_unreliable
    game_server.sendto(server_unreliable, upstream)
    assert receive(client)[0] == server_unreliable
    client.close()
    game_server.close()
    return marker, expected_angles


def demo_records(path: pathlib.Path) -> list[tuple[tuple[float, float, float], bytes]]:
    data = path.read_bytes()
    offset = data.index(b"\n") + 1
    records = []
    while offset < len(data):
        assert offset + 16 <= len(data), path
        length = struct.unpack_from("<I", data, offset)[0]
        angles = struct.unpack_from("<fff", data, offset + 4)
        offset += 16
        assert offset + length <= len(data), path
        records.append((angles, data[offset : offset + length]))
        offset += length
    return records


def verify_demos(
    record_dir: pathlib.Path,
    expected: list[tuple[bytes, tuple[float, float, float]]],
) -> None:
    demos = sorted(record_dir.glob("*.dem"))
    recorded: dict[bytes, tuple[float, float, float]] = {}
    record_counts: dict[bytes, int] = {}
    for demo in demos:
        for angles, payload in demo_records(demo):
            recorded[payload] = angles
            record_counts[payload] = record_counts.get(payload, 0) + 1
    for marker, expected_angles in expected:
        actual_angles = recorded[marker]
        for actual, wanted in zip(actual_angles, expected_angles):
            assert abs(actual - wanted) < 0.01, (marker, actual_angles, expected_angles)
        assert record_counts[marker] == 1, (marker, record_counts[marker])


def verify_reconnect(proxy_port: int, control_server: socket.socket) -> None:
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(("127.0.0.1", 0))
    client.settimeout(3)
    request = connect_request()

    client.sendto(request, ("127.0.0.1", proxy_port))
    forwarded, upstream = receive(control_server)
    assert forwarded == request
    game_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    game_server.bind(("127.0.0.1", 0))
    accept = control(0x81, struct.pack("<I", game_server.getsockname()[1]))
    control_server.sendto(accept, upstream)
    assert receive(client)[0][4] == 0x81

    client.sendto(request, ("127.0.0.1", proxy_port))
    assert receive(client)[0][4] == 0x81
    control_server.settimeout(0.2)
    try:
        receive(control_server)
        raise AssertionError("duplicate connect was forwarded upstream")
    except socket.timeout:
        pass
    finally:
        control_server.settimeout(3)

    time.sleep(2.05)
    client.sendto(request, ("127.0.0.1", proxy_port))
    forwarded, reconnect_upstream = receive(control_server)
    assert forwarded == request
    assert reconnect_upstream == upstream
    control_server.sendto(accept, reconnect_upstream)
    assert receive(client)[0][4] == 0x81
    client.close()
    game_server.close()


def verify_control_query(proxy_port: int, control_server: socket.socket) -> None:
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(("127.0.0.1", 0))
    client.settimeout(3)
    request = control(0x02, b"QUAKE\x00\x03")
    response = control(0x83, b"192.0.2.10:26000\x00mock server\x00")

    client.sendto(request, ("127.0.0.1", proxy_port))
    forwarded, upstream = receive(control_server)
    assert forwarded == request
    control_server.sendto(response, upstream)
    rewritten = receive(client)[0]
    assert rewritten[4] == 0x83
    assert rewritten[5:].split(b"\x00", 1)[0] == f"127.0.0.1:{proxy_port}".encode()

    control_server.sendto(response, upstream)
    client.settimeout(0.2)
    try:
        receive(client)
        raise AssertionError("query session relayed more than one response")
    except socket.timeout:
        pass
    finally:
        client.settimeout(3)

    client.sendto(control(0x03, b"\x00"), ("127.0.0.1", proxy_port))
    client.sendto(control(0x05, b"password\x00status\x00"), ("127.0.0.1", proxy_port))

    client.sendto(control(0x80, b"ignored"), ("127.0.0.1", proxy_port))
    control_server.settimeout(0.2)
    try:
        receive(control_server)
        raise AssertionError("unsupported control request was forwarded")
    except socket.timeout:
        pass
    finally:
        control_server.settimeout(3)
    client.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=pathlib.Path)
    arguments = parser.parse_args()

    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    server.settimeout(3)
    proxy_port = free_udp_port()

    with tempfile.TemporaryDirectory(prefix="faqproxy-test-") as temp:
        record_dir = pathlib.Path(temp) / "private" / "nested" / "demos"
        process = subprocess.Popen(
            [
                str(arguments.binary.resolve()),
                "--listen",
                f"127.0.0.1:{proxy_port}",
                "--record-dir",
                str(record_dir),
                f"127.0.0.1:{server.getsockname()[1]}",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=(
                subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
            ),
        )
        try:
            time.sleep(0.15)
            if process.poll() is not None:
                raise RuntimeError(process.stderr.read())
            cases = [
                ProtocolCase(1, 15, "byte"),
                ProtocolCase(2, 15, "short", proquake=True),
                ProtocolCase(3, 15, "short", predinfo=True),
                ProtocolCase(4, 666, "short"),
                ProtocolCase(5, 999, "float"),
            ]
            expected = [exercise_protocol(case, proxy_port, server) for case in cases]
            verify_control_query(proxy_port, server)
            verify_reconnect(proxy_port, server)
        finally:
            if os.name == "nt":
                process.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                process.send_signal(signal.SIGTERM)
            _, stderr = process.communicate(timeout=5)
        assert process.returncode == 0, stderr
        for protocol in (15, 666, 999):
            assert f"protocol {protocol}" in stderr, stderr
        verify_demos(record_dir, expected)
        if os.name != "nt":
            assert stat.S_IMODE(record_dir.stat().st_mode) == 0o700

    server.close()
    print("extended end-to-end protocols 15, 666, and 999 passed")


if __name__ == "__main__":
    main()
