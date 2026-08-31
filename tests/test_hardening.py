#!/usr/bin/env python3
"""Black-box abuse and session-lifecycle regression tests."""

from __future__ import annotations

import argparse
import os
import pathlib
import signal
import socket
import struct
import subprocess
import time

NETFLAG_UNRELIABLE = 0x00100000
NETFLAG_ACK = 0x00020000
NETFLAG_DATA = 0x00010000
NETFLAG_EOM = 0x00080000
NETFLAG_CTL = 0x80000000


def control(command: int, payload: bytes = b"") -> bytes:
    length = 5 + len(payload)
    return struct.pack("!I", NETFLAG_CTL | length) + bytes([command]) + payload


def connected(sequence: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    return struct.pack("!II", NETFLAG_UNRELIABLE | length, sequence) + payload


def connect_request(proquake: bool = False) -> bytes:
    payload = b"QUAKE\x00\x03"
    if proquake:
        payload += bytes([1, 35, 0]) + struct.pack("<I", 0)
    return control(0x01, payload)


def receive(sock: socket.socket) -> tuple[bytes, tuple[str, int]]:
    data, address = sock.recvfrom(65535)
    return data, (address[0], address[1])


def free_udp_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def expect_no_packet(sock: socket.socket, timeout: float = 0.25) -> None:
    previous = sock.gettimeout()
    sock.settimeout(timeout)
    try:
        receive(sock)
        raise AssertionError("unexpected datagram")
    except socket.timeout:
        pass
    finally:
        sock.settimeout(previous)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=pathlib.Path)
    arguments = parser.parse_args()

    target = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    target.bind(("127.0.0.1", 0))
    target.settimeout(0.3)
    proxy_port = free_udp_port()
    process = subprocess.Popen(
        [
            str(arguments.binary.resolve()),
            "--listen",
            f"127.0.0.1:{proxy_port}",
            "--max-clients",
            "8",
            "--timeout",
            "0",
            "--connect-rate",
            "2",
            "--query-rate",
            "1",
            f"127.0.0.1:{target.getsockname()[1]}",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
    )

    clients: list[socket.socket] = []
    try:
        time.sleep(0.15)
        if process.poll() is not None:
            raise RuntimeError(process.stderr.read())

        malformed = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        clients.append(malformed)
        malformed.bind(("127.0.0.1", 0))
        malformed.sendto(control(0x01), ("127.0.0.1", proxy_port))
        expect_no_packet(malformed)

        incompatible_clients = []
        incompatible = control(0x01, b"QUAKE\x00\x02")
        for _ in range(20):
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            clients.append(client)
            incompatible_clients.append(client)
            client.bind(("127.0.0.1", 0))
            client.settimeout(0.02)
            client.sendto(incompatible, ("127.0.0.1", proxy_port))
        rejections = 0
        for client in incompatible_clients:
            try:
                packet, _ = receive(client)
                assert packet[4] == 0x82
                rejections += 1
            except socket.timeout:
                pass
        assert rejections <= 8, rejections

        connect_flood = []
        request = connect_request()
        for _ in range(8):
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            clients.append(client)
            connect_flood.append(client)
            client.bind(("127.0.0.1", 0))
            client.sendto(request, ("127.0.0.1", proxy_port))
        connect_upstreams: list[tuple[str, int]] = []
        while True:
            try:
                packet, connect_upstream = receive(target)
            except socket.timeout:
                break
            assert packet == request
            connect_upstreams.append(connect_upstream)
        assert len(connect_upstreams) == 4, connect_upstreams
        connect_flood[0].sendto(request, ("127.0.0.1", proxy_port))
        retry, retry_upstream = receive(target)
        assert retry == request and retry_upstream == connect_upstreams[0]
        rejection = control(0x82, b"test rejection\x00")
        for connect_upstream in connect_upstreams:
            target.sendto(rejection, connect_upstream)
        time.sleep(0.1)

        guarded = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        clients.append(guarded)
        guarded.bind(("127.0.0.1", 0))
        guarded.sendto(control(0x03, b"\x00"), ("127.0.0.1", proxy_port))
        guarded.sendto(
            control(0x05, b"password\x00status\x00"), ("127.0.0.1", proxy_port)
        )
        expect_no_packet(target)

        query_clients = []
        query = control(0x02, b"QUAKE\x00\x03")
        for _ in range(8):
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            clients.append(client)
            query_clients.append(client)
            client.bind(("127.0.0.1", 0))
            client.settimeout(0.05)
            client.sendto(query, ("127.0.0.1", proxy_port))

        query_upstreams: list[tuple[str, int]] = []
        while True:
            try:
                packet, upstream = receive(target)
            except socket.timeout:
                break
            assert packet == query
            query_upstreams.append(upstream)
        assert len(query_upstreams) == 2, query_upstreams
        for client in query_clients:
            client.sendto(query, ("127.0.0.1", proxy_port))
        expect_no_packet(target)

        player = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        clients.append(player)
        player.bind(("127.0.0.1", 0))
        player.settimeout(0.2)
        request = connect_request()
        player.sendto(request, ("127.0.0.1", proxy_port))
        forwarded, upstream = receive(target)
        assert forwarded == request

        game = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        game.bind(("127.0.0.1", 0))
        game.settimeout(0.2)
        accept = control(0x81, struct.pack("<I", game.getsockname()[1]))
        target.sendto(accept, upstream)
        assert receive(player)[0][4] == 0x81

        info = control(0x83, b"192.0.2.1:26000\x00server\x00map\x00\x00\x08\x03")
        for query_upstream in query_upstreams:
            target.sendto(info, query_upstream)
        delivered = 0
        for client in query_clients:
            try:
                packet, _ = receive(client)
                assert packet[4] == 0x83
                delivered += 1
            except socket.timeout:
                pass
        assert delivered == 2, delivered
        for query_upstream in query_upstreams:
            target.sendto(info, query_upstream)
        for client in query_clients:
            expect_no_packet(client, 0.02)

        early_delivery = False
        late_delivery = False
        start = time.monotonic()
        sequence = 0
        while time.monotonic() - start < 5.8:
            packet = connected(sequence, b"heartbeat")
            game.sendto(packet, upstream)
            try:
                received, _ = receive(player)
                assert received == packet
                if time.monotonic() - start < 0.8:
                    early_delivery = True
                if time.monotonic() - start > 5.3:
                    late_delivery = True
            except socket.timeout:
                pass
            sequence += 1
            time.sleep(0.1)
        assert early_delivery
        assert not late_delivery

        limited_player = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        clients.append(limited_player)
        limited_player.bind(("127.0.0.1", 0))
        limited_player.settimeout(0.4)
        request = connect_request()
        limited_player.sendto(request, ("127.0.0.1", proxy_port))
        forwarded, limited_upstream = receive(target)
        assert forwarded == request
        limited_game = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        limited_game.bind(("127.0.0.1", 0))
        limited_game.settimeout(0.4)
        target.sendto(
            control(0x81, struct.pack("<I", limited_game.getsockname()[1])),
            limited_upstream,
        )
        assert receive(limited_player)[0][4] == 0x81
        for sequence in range(4):
            packet = connected(sequence, b"x" * 60000)
            limited_game.sendto(packet, limited_upstream)
            assert receive(limited_player)[0] == packet
        limited_game.sendto(connected(4, b"x" * 60000), limited_upstream)
        expect_no_packet(limited_player, 0.4)

        confirmed_player = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        clients.append(confirmed_player)
        confirmed_player.bind(("127.0.0.1", 0))
        confirmed_player.settimeout(1)
        request = connect_request()
        confirmed_player.sendto(request, ("127.0.0.1", proxy_port))
        forwarded, confirmed_upstream = receive(target)
        assert forwarded == request
        confirmed_game = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        confirmed_game.bind(("127.0.0.1", 0))
        confirmed_game.settimeout(1)
        target.sendto(
            control(0x81, struct.pack("<I", confirmed_game.getsockname()[1])),
            confirmed_upstream,
        )
        assert receive(confirmed_player)[0][4] == 0x81
        confirmed_player.sendto(b"malformed", ("127.0.0.1", proxy_port))
        expect_no_packet(confirmed_game, 0.1)
        signon = struct.pack("!II", NETFLAG_DATA | NETFLAG_EOM | 9, 0) + b"\x01"
        confirmed_game.sendto(signon, confirmed_upstream)
        assert receive(confirmed_player)[0] == signon
        acknowledgement = struct.pack("!II", NETFLAG_ACK | 8, 0)
        confirmed_player.sendto(acknowledgement, ("127.0.0.1", proxy_port))
        assert receive(confirmed_game)[0] == acknowledgement
        time.sleep(5.3)
        still_connected = connected(0, b"confirmed")
        confirmed_game.sendto(still_connected, confirmed_upstream)
        assert receive(confirmed_player)[0] == still_connected

        cheatfree = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        clients.append(cheatfree)
        cheatfree.bind(("127.0.0.1", 0))
        cheatfree.settimeout(1)
        request = connect_request(proquake=True)
        cheatfree.sendto(request, ("127.0.0.1", proxy_port))
        forwarded, cheat_upstream = receive(target)
        assert forwarded == request
        target.sendto(control(0x81, struct.pack("<I", 26001) + bytes([1, 30, 1])), cheat_upstream)
        rejection, _ = receive(cheatfree)
        assert rejection[4] == 0x82 and b"cheat-free" in rejection
    finally:
        for client in clients:
            client.close()
        if "game" in locals():
            game.close()
        if "confirmed_game" in locals():
            confirmed_game.close()
        if "limited_game" in locals():
            limited_game.close()
        if os.name == "nt":
            process.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            process.send_signal(signal.SIGTERM)
        _, stderr = process.communicate(timeout=5)
        target.close()

    assert process.returncode == 0, stderr
    assert "client 1 packets/" in stderr, stderr
    print("connection, query, reflection, liveness, and ProQuake hardening passed")


if __name__ == "__main__":
    main()
