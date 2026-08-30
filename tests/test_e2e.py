#!/usr/bin/env python3
"""Black-box tests for the NetQuake handshake and byte-exact relay."""

from __future__ import annotations

import argparse
import pathlib
import signal
import socket
import struct
import subprocess
import tempfile
import time

NETFLAG_DATA = 0x00010000
NETFLAG_ACK = 0x00020000
NETFLAG_EOM = 0x00080000
NETFLAG_UNRELIABLE = 0x00100000
NETFLAG_CTL = 0x80000000


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


def exercise_protocol(
    protocol: int,
    proxy_port: int,
    control_server: socket.socket,
) -> bytes:
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(("127.0.0.1", 0))
    client.settimeout(3)

    request = control(0x01, b"QUAKE\x00\x03")
    client.sendto(request, ("127.0.0.1", proxy_port))
    forwarded, upstream = receive(control_server)
    assert forwarded == request

    game_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    game_server.bind(("127.0.0.1", 0))
    game_server.settimeout(3)
    accept = control(0x81, struct.pack("<I", game_server.getsockname()[1]))
    control_server.sendto(accept, upstream)
    rewritten, _ = receive(client)
    assert rewritten[4] == 0x81
    assert struct.unpack_from("<I", rewritten, 5)[0] == proxy_port

    protocol_payload = bytes([11]) + struct.pack("<I", protocol)
    if protocol == 999:
        protocol_payload += struct.pack("<I", 1 << 1)
    split = max(1, len(protocol_payload) // 2)
    first = connected(NETFLAG_DATA, 0, protocol_payload[:split])
    second = connected(NETFLAG_DATA | NETFLAG_EOM, 1, protocol_payload[split:])
    game_server.sendto(first, upstream)
    game_server.sendto(second, upstream)
    assert receive(client)[0] == first
    assert receive(client)[0] == second

    ack = connected(NETFLAG_ACK, 1)
    client.sendto(ack, ("127.0.0.1", proxy_port))
    assert receive(game_server)[0] == ack

    client_unreliable = connected(NETFLAG_UNRELIABLE, 0, b"\x01")
    client.sendto(client_unreliable, ("127.0.0.1", proxy_port))
    assert receive(game_server)[0] == client_unreliable

    server_unreliable = connected(NETFLAG_UNRELIABLE, 0, b"\x01\x07")
    game_server.sendto(server_unreliable, upstream)
    assert receive(client)[0] == server_unreliable
    client.close()
    game_server.close()
    return protocol_payload


def verify_demos(record_dir: pathlib.Path, payloads: list[bytes]) -> None:
    demos = sorted(record_dir.glob("*.dem"))
    assert len(demos) == len(payloads), (demos, payloads)
    recorded = []
    for demo in demos:
        data = demo.read_bytes()
        header_end = data.index(b"\n") + 1
        length = struct.unpack_from("<I", data, header_end)[0]
        payload_offset = header_end + 16
        recorded.append(data[payload_offset : payload_offset + length])
    for payload in payloads:
        assert payload in recorded


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=pathlib.Path)
    arguments = parser.parse_args()

    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    server.settimeout(3)
    proxy_port = free_udp_port()

    with tempfile.TemporaryDirectory(prefix="faqproxy-test-") as temp:
        record_dir = pathlib.Path(temp) / "demos"
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
        )
        try:
            time.sleep(0.15)
            if process.poll() is not None:
                raise RuntimeError(process.stderr.read())
            payloads = [
                exercise_protocol(protocol, proxy_port, server)
                for protocol in (15, 666, 999)
            ]
        finally:
            process.send_signal(signal.SIGTERM)
            _, stderr = process.communicate(timeout=5)
        assert process.returncode == 0, stderr
        for protocol in (15, 666, 999):
            assert f"protocol {protocol}" in stderr, stderr
        verify_demos(record_dir, payloads)

    server.close()
    print("end-to-end protocols 15, 666, and 999 passed")


if __name__ == "__main__":
    main()
