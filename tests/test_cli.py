#!/usr/bin/env python3
"""Command-line validation tests for FAQProxy."""

from __future__ import annotations

import argparse
import os
import pathlib
import subprocess
import tempfile


def run(binary: pathlib.Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(binary.resolve()), *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=3,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=pathlib.Path)
    arguments = parser.parse_args()
    binary = arguments.binary

    result = run(binary, "--version")
    assert result.returncode == 0 and result.stdout.startswith("faqproxy "), result

    result = run(binary, "--help")
    assert result.returncode == 0 and "protocols 15, 666, and 999" in result.stdout, result
    assert "--allow-rcon" in result.stdout and "--connect-rate" in result.stdout, result

    result = run(binary, "-vv", "--help")
    assert result.returncode == 0, result

    invalid_commands = [
        (),
        ("--unknown",),
        ("--listen",),
        ("--version=unexpected",),
        ("--max-clients", "0", "127.0.0.1:26000"),
        ("--max-clients=65", "127.0.0.1:26000"),
        ("--max-clients", "65", "127.0.0.1:26000"),
        ("--timeout", "86401", "127.0.0.1:26000"),
        ("--timeout=", "127.0.0.1:26000"),
        ("--max-demo-mib", "1048577", "127.0.0.1:26000"),
        ("--query-rate", "10001", "127.0.0.1:26000"),
        ("--connect-rate", "10001", "127.0.0.1:26000"),
        ("--record-dir=", "127.0.0.1:26000"),
        ("--advertise", ":26000", "127.0.0.1:26000"),
        ("--listen", "127.0.0.1:bad", "127.0.0.1:26000"),
        (":26000",),
    ]
    for command in invalid_commands:
        result = run(binary, *command)
        assert result.returncode == 2, (command, result)

    with tempfile.NamedTemporaryFile() as not_a_directory:
        result = run(
            binary,
            "--record-dir",
            not_a_directory.name,
            "127.0.0.1:26000",
        )
        assert result.returncode == 2, result
        assert "Cannot create or use record directory" in result.stderr, result.stderr

    if os.name != "nt":
        with tempfile.TemporaryDirectory(prefix="faqproxy-cli-") as temp:
            root = pathlib.Path(temp)
            real_directory = root / "real"
            real_directory.mkdir()
            link = root / "record-link"
            link.symlink_to(real_directory, target_is_directory=True)
            result = run(binary, "--record-dir", str(link), "127.0.0.1:26000")
            assert result.returncode == 2, result
            assert "Cannot create or use record directory" in result.stderr, result.stderr

    print("command-line validation passed")


if __name__ == "__main__":
    main()
