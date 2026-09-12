#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Owned-fixture PTY checks. Never confirms Trash or launches system viewers."""

import argparse
import fcntl
import json
import os
from pathlib import Path
import platform
import pty
import re
import select
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import termios
import time


REPO = Path(__file__).resolve().parent.parent
ANSI = re.compile(rb"\x1b(?:\[[0-?]*[ -/]*[@-~]|\([A-Z])")
BROKER = r"""
import json, os, resource, signal, subprocess, sys, time
status, acknowledge = int(sys.argv[1]), int(sys.argv[2])
started = time.clock_gettime(time.CLOCK_MONOTONIC)
child = subprocess.Popen(sys.argv[3:], close_fds=True)
def forward(signum, _):
    if child.poll() is None:
        child.send_signal(signum)
signal.signal(signal.SIGINT, forward)
signal.signal(signal.SIGTERM, forward)
os.write(status, (json.dumps({"started": started, "pid": child.pid}) + "\n").encode())
code = child.wait()
os.write(status, (json.dumps({"exit": code, "rss": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss}) + "\n").encode())
os.read(acknowledge, 1)
sys.exit(code if code >= 0 else 128 - code)
"""


class Fixture:
    def __init__(self, file_count=1024):
        self.file_count = file_count
        self.base = Path(tempfile.mkdtemp(prefix="sayaka-m7-bench-", dir=REPO / "crates/cli"))
        self.directories = []
        self.files = []
        self.remember_directory(self.base)
        self.write(self.base / "ownership-marker", b"sayaka-m7-owned-benchmark")
        self.root = self.mkdir(self.base / "root")
        self.blocks = self.mkdir(self.root / "blocks")
        self.aliases = self.mkdir(self.root / "aliases")
        self.mkdir(self.root / "empty")
        deep = self.mkdir(self.root / "deep")
        for index in range(8):
            deep = self.mkdir(deep / ("level-%d" % index))
        for index in range(file_count):
            self.write(self.blocks / ("file-%04d.dat" % index), b"x" * 1024)
        for index in range(min(16, file_count)):
            path = self.aliases / ("alias-%04d.dat" % index)
            os.link(self.blocks / ("file-%04d.dat" % index), path)
            self.remember_file(path)
        link = self.root / "skipped-link"
        link.symlink_to("blocks")
        self.remember_file(link)
        for name in ["home", "temp", "cache", "config"]:
            self.mkdir(self.base / name)
        self.state = self.base / "journal"

    @staticmethod
    def identity(path):
        info = path.lstat()
        return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)

    def remember_directory(self, path):
        self.directories.append((path, self.identity(path)))

    def remember_file(self, path):
        self.files.append((path, self.identity(path)))

    def mkdir(self, path):
        path.mkdir(mode=0o700)
        self.remember_directory(path)
        return path

    def write(self, path, contents):
        path.write_bytes(contents)
        self.remember_file(path)

    def env(self):
        return {
            "PATH": "/usr/bin:/bin",
            "TERM": "xterm-256color",
            "NO_COLOR": "1",
            "HOME": str(self.base / "home"),
            "TMPDIR": str(self.base / "temp"),
            "XDG_CACHE_HOME": str(self.base / "cache"),
            "XDG_CONFIG_HOME": str(self.base / "config"),
            "XDG_STATE_HOME": str(self.state),
        }

    def verify_payload(self):
        assert not self.state.exists(), "preview/cancel must not create journal state"
        for index in range(self.file_count):
            assert (self.blocks / ("file-%04d.dat" % index)).read_bytes() == b"x" * 1024
        for path, identity in self.files:
            assert self.identity(path) == identity, "owned fixture identity changed"

    def close(self):
        assert (self.base / "ownership-marker").read_bytes() == b"sayaka-m7-owned-benchmark"
        for path, identity in self.directories:
            assert self.identity(path) == identity, "fixture ancestry changed; refuse cleanup"
        known = {path for path, _ in self.files + self.directories}
        # Foundation may create metadata caches under the redirected test HOME.
        # Register only bounded descendants of our originally empty owned roots.
        discovered = 0
        for auxiliary in ["home", "temp", "cache", "config"]:
            for parent, directories, files in os.walk(self.base / auxiliary, followlinks=False):
                for name in directories + files:
                    path = Path(parent) / name
                    if path in known:
                        continue
                    discovered += 1
                    assert discovered <= 4096, "auxiliary fixture entry budget exceeded"
                    info = path.lstat()
                    assert info.st_uid == os.getuid()
                    assert info.st_dev == self.directories[0][1][0]
                    if stat.S_ISDIR(info.st_mode):
                        self.remember_directory(path)
                    else:
                        self.remember_file(path)
                    known.add(path)
        marker = self.base / "ownership-marker"
        for path, identity in reversed(self.files):
            if path == marker:
                continue
            assert self.identity(path) == identity, "fixture object changed; refuse cleanup"
            path.unlink()
        for path, identity in reversed(self.directories):
            if path == self.base:
                continue
            assert self.identity(path) == identity
            path.rmdir()
        marker.unlink()
        self.base.rmdir()


def controlling_terminal():
    os.setsid()
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)


class TerminalProcess:
    def __init__(self, binary, fixture, columns=100, rows=30, arguments=None):
        self.master, self.slave = pty.openpty()
        self.before = termios.tcgetattr(self.slave)
        self.resize(columns, rows)
        self.transcript = bytearray()
        self.started = None
        self.child_pid = None
        self.child_exit = None
        self.rss = 0
        self.status_buffer = bytearray()
        self.status_read, status_write = os.pipe()
        acknowledge_read, self.acknowledge_write = os.pipe()
        arguments = arguments if arguments is not None else ["browse", str(fixture.root), "--state-dir", str(fixture.state)]
        self.process = subprocess.Popen(
            [sys.executable, "-c", BROKER, str(status_write), str(acknowledge_read),
             str(binary)] + arguments,
            stdin=self.slave, stdout=self.slave, stderr=self.slave,
            cwd=fixture.base, env=fixture.env(), close_fds=True,
            preexec_fn=controlling_terminal, pass_fds=(status_write, acknowledge_read),
        )
        os.close(status_write)
        os.close(acknowledge_read)
        self.closed = False

    def resize(self, columns, rows):
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))

    def read_once(self, delay):
        ready, _, _ = select.select([self.master, self.status_read], [], [], delay)
        if self.master in ready:
            chunk = os.read(self.master, 65536)
            self.transcript.extend(chunk)
            if len(self.transcript) > 4 * 1024 * 1024:
                raise AssertionError("terminal output budget exceeded")
        if self.status_read in ready:
            self.status_buffer.extend(os.read(self.status_read, 4096))
            while b"\n" in self.status_buffer:
                line, _, remaining = self.status_buffer.partition(b"\n")
                self.status_buffer = bytearray(remaining)
                message = json.loads(line)
                if "started" in message:
                    self.started, self.child_pid = message["started"], message["pid"]
                if "exit" in message:
                    self.child_exit, self.rss = message["exit"], message["rss"]

    def wait_for(self, text, start=0, timeout=5):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.started is not None and text in ANSI.sub(b"", bytes(self.transcript[start:])):
                return (time.clock_gettime(time.CLOCK_MONOTONIC) - self.started) * 1000
            if self.child_exit is not None or self.process.poll() is not None:
                self.read_once(0)
                raise AssertionError("CLI exited before expected terminal state: %r; output=%r"
                                     % (text, bytes(self.transcript[-4096:])))
            self.read_once(0.01)
        raise AssertionError("terminal state timed out: %r; output=%r" % (text, bytes(self.transcript[-4096:])))

    def key(self, sequence, expected):
        start = len(self.transcript)
        sent = time.monotonic()
        os.write(self.master, sequence)
        self.wait_for(expected, start)
        return (time.monotonic() - sent) * 1000

    def finish(self, expected):
        code = self.wait_exit(5)
        self.read_once(0)
        assert code == expected, "unexpected CLI exit: %d; output=%r" % (code, bytes(self.transcript[-4096:]))
        assert termios.tcgetattr(self.slave) == self.before, "terminal attributes were not restored"
        assert b"\x1b[?1049h" in self.transcript, "alternate screen was never entered"
        assert b"\x1b[?1049l" in self.transcript, "alternate screen was not restored"
        assert b"\x1b[?25h" in self.transcript, "cursor was not restored"
        assert not re.search(rb"\x1b\[(?:[0-9]+;)*(?:38|48);[0-9;]*m", self.transcript), "NO_COLOR emitted color"

    def close(self):
        if self.closed:
            return
        forced = False
        try:
            if self.child_exit is None and self.process.poll() is None:
                self.process.send_signal(signal.SIGTERM)
                try:
                    self.wait_exit(5)
                except AssertionError:
                    forced = True
                    if self.child_pid is not None:
                        os.kill(self.child_pid, signal.SIGKILL)
                    else:
                        self.process.kill()
                    self.wait_exit(5)
            if self.process.poll() is None:
                os.write(self.acknowledge_write, b"x")
                self.process.wait(timeout=5)
        finally:
            os.close(self.master)
            os.close(self.slave)
            os.close(self.status_read)
            os.close(self.acknowledge_write)
            self.closed = True
        if forced:
            raise AssertionError("owned CLI child required forced termination")

    def wait_exit(self, timeout):
        # A PTY has finite output buffering: keep acting as a terminal reader
        # while waiting, including during alternate-screen restoration.
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.child_exit is not None:
                return self.child_exit
            if self.process.poll() is not None:
                raise AssertionError("terminal broker exited before reporting CLI status")
            self.read_once(0.01)
        raise AssertionError("owned CLI child did not exit; output=%r" % bytes(self.transcript[-4096:]))


def check_plain(binary, fixture, budget):
    result = subprocess.run(
        [str(binary), "browse", str(fixture.root), "--plain"],
        cwd=fixture.base, env=fixture.env(), capture_output=True, timeout=5, check=True,
    )
    text = result.stdout.decode()
    assert "\x1b" not in text
    assert "Status: complete" in text
    assert "Observed regular entries: %d" % budget["file_entries"] in text
    assert "Root unique files: %d" % budget["unique_files"] in text
    assert "Root logical subtotal: %d bytes; unknown files: 0; complete: true" % budget["logical_bytes"] in text
    assert any("(known_bytes=16384)" in line and line.endswith('/aliases"') for line in text.splitlines()), "hardlink aliases must count within their own subtree"
    index_ms = int(re.search(r"Index elapsed: (\d+) ms", text).group(1))
    assert index_ms <= budget["max_index_ms"], "index time exceeds frozen budget"
    return index_ms


def interactive_run(binary, fixture, budget):
    terminal = TerminalProcess(binary, fixture)
    try:
        first = terminal.wait_for(b"Sayaka  /")
        ready = terminal.wait_for(b"complete snapshot:")
        terminal.key(b"\r", b'ROOT / "blocks"')
        responses = []
        for index in range(budget["input_samples_per_run"]):
            responses.append(terminal.key(b"a", b"Allocated" if index % 2 == 0 else b"Logical"))
        terminal.key(b"/file-1023\r", b"file-1023")
        terminal.key(b" ", b"Selected 1 / 32")
        terminal.key(b"t", b"Sayaka  /  Preview")
        # Never type a confirmation phrase or invoke o/p in an automated check.
        terminal.key(b"\x1b", b"Plan cancelled")
        terminal.key(b"m", b"Browse disk")
        terminal.key(b"\x1b", b"Sayaka  /  Browse")
        terminal.resize(40, 12)
        terminal.read_once(0.1)
        terminal.resize(100, 30)
        terminal.read_once(0.1)
        stopped = time.monotonic()
        os.write(terminal.master, b"q")
        terminal.finish(0)
        shutdown = (time.monotonic() - stopped) * 1000
        assert first <= budget["max_first_frame_ms"], "first frame %.3f ms exceeds frozen budget" % first
        assert ready <= budget["max_first_usable_snapshot_ms"], "first usable snapshot %.3f ms exceeds frozen budget" % ready
        assert max(responses) <= budget["max_input_response_ms"], "keyboard response exceeds frozen budget"
        assert shutdown <= budget["max_shutdown_ms"], "shutdown exceeds frozen budget"
        return {"first_frame_ms": first, "first_usable_snapshot_ms": ready,
                "input_response_ms": responses, "shutdown_ms": shutdown,
                "peak_rss_bytes": terminal.rss}
    finally:
        terminal.close()


def signal_case(binary, fixture, signum, expected, budget):
    terminal = TerminalProcess(binary, fixture)
    try:
        terminal.wait_for(b"Sayaka  /")
        start = time.monotonic()
        terminal.process.send_signal(signum)
        terminal.finish(expected)
        elapsed = (time.monotonic() - start) * 1000
        assert elapsed <= budget["max_shutdown_ms"], "signal shutdown exceeds frozen budget"
        return elapsed
    finally:
        terminal.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=REPO / "target/release/sayaka")
    args = parser.parse_args()
    if platform.system() != "Darwin":
        raise SystemExit("BLOCKED: this native fixture requires macOS")
    binary = args.binary.resolve(strict=True)
    budget = json.loads((REPO / "benchmarks/m7-v1.json").read_text())
    fixture = Fixture()
    try:
        index_ms = check_plain(binary, fixture, budget)
        runs = [interactive_run(binary, fixture, budget) for _ in range(budget["runs"])]
        signals = {
            "sigint_ms": signal_case(binary, fixture, signal.SIGINT, 130, budget),
            "sigterm_ms": signal_case(binary, fixture, signal.SIGTERM, 143, budget),
        }
        fixture.verify_payload()
        peak = max(run["peak_rss_bytes"] for run in runs)
        assert peak <= budget["max_peak_rss_bytes"], "child peak RSS exceeds frozen budget"
        result = {"fixture": budget["fixture"], "os": platform.mac_ver()[0], "arch": platform.machine(),
                  "scope": budget["scope"], "index_ms": index_ms, "runs": runs,
                  "signal_shutdown": signals, "peak_rss_bytes": peak, "effects_performed": False}
    finally:
        fixture.close()
    result["cleanup"] = "passed"
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
