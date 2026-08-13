#!/usr/bin/env python3
"""Process-level smoke and exit-contract tests for the Native CLI."""
from __future__ import annotations
import json
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = bytes.fromhex("000a001c00000001000000000000002a0002000c0100000100080004")
BAD_LENGTH = bytes.fromhex("000a000f000000000000000000000000")

def run(*args: str, stdin: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(["moon", "run", "cmd/moonipfix", "--target", "native", "--", *args], cwd=ROOT, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)

def json_lines(output: bytes) -> list[dict[str, object]]:
    return [json.loads(line) for line in output.decode().splitlines() if line]

def main() -> None:
    assert run("inspect", stdin=b"").returncode == 0
    valid_stdin = run("inspect", "--session", "test:stdin", "-", stdin=TEMPLATE)
    assert valid_stdin.returncode == 0, valid_stdin.stderr.decode()
    records = json_lines(valid_stdin.stdout)
    assert records[0]["record_kind"] == "message"
    assert all(record["schema_version"] == 1 for record in records)
    assert not valid_stdin.stderr
    with tempfile.TemporaryDirectory(prefix="moonipfix-cli-") as temporary:
        path = Path(temporary, "template.ipfix")
        path.write_bytes(TEMPLATE)
        valid_file = run("validate", str(path))
        assert valid_file.returncode == 0, valid_file.stderr.decode()
        assert {r["record_kind"] for r in json_lines(valid_file.stdout)} == {"sequence_audit", "statistics"}
    malformed = run("inspect", "-", stdin=BAD_LENGTH)
    assert malformed.returncode == 4
    assert b"error" in malformed.stderr.lower()
    warning = bytearray.fromhex("000a0014000000000000000000000000")
    warning.extend(bytes.fromhex("00010004"))
    denied = run("validate", "--deny-warnings", "-", stdin=bytes(warning))
    assert denied.returncode == 3
    assert b"warning" in denied.stderr.lower()
    over_diagnostics = bytearray.fromhex("000a0000000000000000000000000000")
    over_diagnostics.extend(bytes.fromhex("00010004") * 1025)
    over_diagnostics[2:4] = len(over_diagnostics).to_bytes(2, "big")
    limited = run("validate", "-", stdin=bytes(over_diagnostics))
    assert limited.returncode == 5
    assert run("unknown-command").returncode == 2
    assert run("inspect", "definitely-missing.ipfix").returncode == 6
    print("CLI integration: all process and exit-contract checks passed")

if __name__ == "__main__":
    main()
