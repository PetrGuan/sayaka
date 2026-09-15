#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Persistent PTY validation for `sayaka menu` child-dispatch lifecycle."""

import argparse
import fcntl
import json
import os
from pathlib import Path
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
import json, os, signal, subprocess, sys, time
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
os.write(status, (json.dumps({"exit": code}) + "\n").encode())
os.read(acknowledge, 1)
sys.exit(code if code >= 0 else 128 - code)
"""


class Fixture:
    def __init__(self):
        self.base = Path(tempfile.mkdtemp(prefix="sayaka-menu-pty-", dir=REPO / "crates/cli"))
        self.directories = []
        self.files = []
        self.remember_directory(self.base)
        self.write(self.base / "ownership-marker", b"sayaka-menu-pty-owned")
        self.root = self.mkdir(self.base / "root")
        pkg = self.mkdir(self.root / "pkg")
        pycache = self.mkdir(pkg / "__pycache__")
        self.write(pkg / "m.py", b"print('ok')\n")
        self.write(pycache / "m.cpython-311.pyc", b"\0\0\0\0pyc fixture")
        self.write(self.root / "Foo.java", b"class Foo {}\n")
        self.write(self.root / "Foo.class", bytes.fromhex("cafebabe0000003d0011"))
        self.write(self.root / "still-there.txt", b"owned payload")
        for name in ["home", "temp", "cache", "config", "state"]:
            self.mkdir(self.base / name)
        self.missing = self.base / "missing"

    @staticmethod
    def identity(path: Path):
        info = path.lstat()
        return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)

    def remember_directory(self, path: Path):
        self.directories.append((path, self.identity(path)))

    def remember_file(self, path: Path):
        self.files.append((path, self.identity(path)))

    def mkdir(self, path: Path):
        path.mkdir(mode=0o700)
        self.remember_directory(path)
        return path

    def write(self, path: Path, contents: bytes):
        path.write_bytes(contents)
        self.remember_file(path)

    def env(self, extra=None):
        env = {
            "PATH": "/usr/bin:/bin",
            "TERM": "xterm-256color",
            "NO_COLOR": "1",
            "HOME": str(self.base / "home"),
            "USERPROFILE": str(self.base / "home"),
            "APPDATA": str(self.base / "config"),
            "LOCALAPPDATA": str(self.base / "state"),
            "XDG_CONFIG_HOME": str(self.base / "config"),
            "XDG_STATE_HOME": str(self.base / "state"),
            "XDG_CACHE_HOME": str(self.base / "cache"),
            "TMPDIR": str(self.base / "temp"),
            "TMP": str(self.base / "temp"),
            "TEMP": str(self.base / "temp"),
        }
        if extra:
            env.update(extra)
        return env

    def verify_unchanged(self):
        assert (self.root / "still-there.txt").read_bytes() == b"owned payload"
        assert (self.root / "pkg" / "m.py").read_bytes() == b"print('ok')\n"
        assert (self.root / "pkg" / "__pycache__" / "m.cpython-311.pyc").exists()
        assert (self.root / "Foo.class").read_bytes() == bytes.fromhex("cafebabe0000003d0011")
        assert not any((self.base / "state").iterdir()), "menu tests must not create state"

    def close(self):
        assert (self.base / "ownership-marker").read_bytes() == b"sayaka-menu-pty-owned"
        known = {path for path, _ in self.files + self.directories}
        discovered = 0
        for auxiliary in ["home", "temp", "cache", "config", "state"]:
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
        for path, identity in self.files + self.directories:
            assert self.identity(path) == identity, f"owned fixture identity changed: {path}"
        marker = self.base / "ownership-marker"
        for path, _ in reversed(self.files):
            if path == marker:
                continue
            path.unlink()
        for path, _ in reversed(self.directories):
            if path == self.base:
                continue
            path.rmdir()
        marker.unlink()
        self.base.rmdir()


def controlling_terminal():
    os.setsid()
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)


class TerminalProcess:
    def __init__(self, binary: Path, fixture: Fixture, columns=100, rows=30, extra_env=None):
        self.master, self.slave = pty.openpty()
        self.before = termios.tcgetattr(self.slave)
        self.resize(columns, rows)
        self.transcript = bytearray()
        self.status_buffer = bytearray()
        self.started = None
        self.child_pid = None
        self.child_exit = None
        status_read, status_write = os.pipe()
        acknowledge_read, self.acknowledge_write = os.pipe()
        self.status_read = status_read
        self.process = subprocess.Popen(
            [sys.executable, "-c", BROKER, str(status_write), str(acknowledge_read), str(binary), "menu"],
            stdin=self.slave,
            stdout=self.slave,
            stderr=self.slave,
            cwd=fixture.base,
            env=fixture.env(extra_env),
            close_fds=True,
            preexec_fn=controlling_terminal,
            pass_fds=(status_write, acknowledge_read),
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
            if len(self.transcript) > 8 * 1024 * 1024:
                raise AssertionError("terminal transcript budget exceeded")
        if self.status_read in ready:
            self.status_buffer.extend(os.read(self.status_read, 4096))
            while b"\n" in self.status_buffer:
                line, _, remaining = self.status_buffer.partition(b"\n")
                self.status_buffer = bytearray(remaining)
                message = json.loads(line)
                if "pid" in message:
                    self.child_pid = message["pid"]
                    self.started = message["started"]
                if "exit" in message:
                    self.child_exit = message["exit"]

    def wait_for(self, text: bytes, timeout=10, start=0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if text in ANSI.sub(b"", bytes(self.transcript[start:])):
                return
            if self.child_exit is not None:
                raise AssertionError(
                    f"process exited before waiting for {text!r}: {bytes(self.transcript[-4000:])!r}"
                )
            self.read_once(0.02)
        raise AssertionError(f"timeout waiting for {text!r}: {bytes(self.transcript[-4000:])!r}")

    def send(self, payload: bytes):
        os.write(self.master, payload)

    def key_and_wait(self, payload: bytes, text: bytes, timeout=10):
        start = len(self.transcript)
        self.send(payload)
        self.wait_for(text, timeout=timeout, start=start)

    def send_signal(self, sig):
        assert self.child_pid is not None, "child pid not reported yet"
        os.kill(self.child_pid, sig)

    def wait_exit(self, timeout=10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.child_exit is not None:
                return self.child_exit
            if self.process.poll() is not None and self.child_exit is None:
                raise AssertionError("terminal broker exited before reporting child status")
            self.read_once(0.02)
        raise AssertionError(f"child did not exit: {bytes(self.transcript[-4000:])!r}")

    def finish(self, expected):
        code = self.wait_exit()
        self.read_once(0)
        assert code == expected, f"expected {expected}, got {code}: {bytes(self.transcript[-5000:])!r}"
        assert termios.tcgetattr(self.slave) == self.before, "terminal attributes were not restored"
        assert b"\x1b[?1049h" in self.transcript, "alternate screen enter missing"
        assert b"\x1b[?1049l" in self.transcript, "alternate screen restore missing"
        assert b"\x1b[?25h" in self.transcript, "cursor restore missing"

    def close(self):
        if self.closed:
            return
        try:
            if self.child_exit is None and self.process.poll() is None:
                self.process.send_signal(signal.SIGTERM)
                self.wait_exit()
            if self.process.poll() is None:
                os.write(self.acknowledge_write, b"x")
                self.process.wait(timeout=5)
        finally:
            os.close(self.master)
            os.close(self.slave)
            os.close(self.status_read)
            os.close(self.acknowledge_write)
            self.closed = True


def case_startup_and_path_cancel(binary: Path):
    fixture = Fixture()
    term = TerminalProcess(binary, fixture)
    try:
        term.wait_for(b"Sayaka menu")
        term.key_and_wait(b"2", b"Python cache clean rule")
        term.key_and_wait(b"\r", b"ROOT:")
        term.key_and_wait(b"\x1b", b"Path entry cancelled")
        term.key_and_wait(b"\x1b", b"Choose action")
        term.send(b"q")
        term.finish(0)
        assert b"sayaka menu child outcome" not in ANSI.sub(b"", bytes(term.transcript))
        fixture.verify_unchanged()
    finally:
        term.close()
        fixture.close()


def select_rule_preview(term: TerminalProcess, action_digit: bytes, root: Path):
    term.key_and_wait(action_digit, b"rule")
    term.key_and_wait(b"\r", b"ROOT:")
    term.send(str(root).encode())
    term.key_and_wait(b"\r", b"Choose rule action mode")
    term.key_and_wait(b"\r", b"=== sayaka menu child outcome ===", timeout=20)


def return_to_menu(term: TerminalProcess):
    term.key_and_wait(b"\r", b"Choose action")


def case_repeated_rule_previews(binary: Path):
    fixture = Fixture()
    term = TerminalProcess(binary, fixture)
    try:
        term.wait_for(b"Choose action")
        select_rule_preview(term, b"2", fixture.root)
        return_to_menu(term)
        select_rule_preview(term, b"3", fixture.root)
        return_to_menu(term)
        term.send(b"q")
        term.finish(0)
        fixture.verify_unchanged()
    finally:
        term.close()
        fixture.close()


def case_clean_approval_cancel(binary: Path):
    fixture = Fixture()
    term = TerminalProcess(binary, fixture)
    try:
        term.wait_for(b"Choose action")
        term.key_and_wait(b"2", b"Python cache clean rule")
        term.key_and_wait(b"\r", b"ROOT:")
        term.send(str(fixture.root).encode())
        term.key_and_wait(b"\r", b"Choose rule action mode")
        term.send(b"j")
        term.key_and_wait(b"\r", b"Selection:", timeout=20)
        term.key_and_wait(b"\r", b"Cancelled; no files selected.", timeout=20)
        term.wait_for(b"=== sayaka menu child outcome ===")
        return_to_menu(term)
        term.send(b"q")
        term.finish(0)
        fixture.verify_unchanged()
    finally:
        term.close()
        fixture.close()


def case_child_nonzero_and_ignored_override(binary: Path):
    fixture = Fixture()
    term = TerminalProcess(binary, fixture)
    try:
        term.wait_for(b"Choose action")
        term.key_and_wait(b"4", b"Installer files")
        term.key_and_wait(b"\r", b"ROOT:")
        term.send(str(fixture.missing).encode())
        term.key_and_wait(b"\r", b"Choose installer action mode")
        term.key_and_wait(b"\r", b"=== sayaka menu child outcome ===", timeout=20)
        term.wait_for(b"Child exited: code 1")
        return_to_menu(term)
        term.send(b"q")
        term.finish(0)
        fixture.verify_unchanged()
    finally:
        term.close()
        fixture.close()

    fixture = Fixture()
    term = TerminalProcess(
        binary,
        fixture,
        extra_env={"SAYAKA_MENU_TEST_CURRENT_EXE": str(fixture.base / "missing-binary")},
    )
    try:
        term.wait_for(b"Choose action")
        term.key_and_wait(b"4", b"Installer files")
        term.key_and_wait(b"\r", b"ROOT:")
        term.send(str(fixture.root).encode())
        term.key_and_wait(b"\r", b"Choose installer action mode")
        term.key_and_wait(b"\r", b"=== sayaka menu child outcome ===", timeout=20)
        term.wait_for(b"Child exited: code 0")
        assert b"Child spawn failed:" not in ANSI.sub(b"", bytes(term.transcript))
        return_to_menu(term)
        term.send(b"q")
        term.finish(0)
        fixture.verify_unchanged()
    finally:
        term.close()
        fixture.close()


def case_installer_approval_cancel(binary: Path):
    fixture = Fixture()
    image = fixture.root / "image.dmg"
    contents = bytearray(2048)
    contents[1536:1540] = b"koly"
    struct.pack_into(">I", contents, 1540, 4)
    struct.pack_into(">I", contents, 1544, 512)
    struct.pack_into(">Q", contents, 1536 + 0xD8, 128)
    struct.pack_into(">Q", contents, 1536 + 0xE0, 64)
    fixture.write(image, bytes(contents))
    term = TerminalProcess(binary, fixture)
    try:
        term.wait_for(b"Choose action")
        term.key_and_wait(b"4", b"Installer files")
        term.key_and_wait(b"\r", b"ROOT:")
        term.send(str(fixture.root).encode())
        term.key_and_wait(b"\r", b"Choose installer action mode")
        term.send(b"j")
        term.key_and_wait(b"\r", b"Selection:", timeout=20)
        term.key_and_wait(b"1\r", b'Type "trash 1"', timeout=20)
        term.key_and_wait(b"\r", b"Cancelled; no files moved.", timeout=20)
        term.wait_for(b"=== sayaka menu child outcome ===")
        return_to_menu(term)
        term.send(b"q")
        term.finish(0)
        fixture.verify_unchanged()
        assert image.read_bytes() == bytes(contents)
    finally:
        term.close()
        fixture.close()


def case_narrow_terminal_blocks_dispatch(binary: Path):
    fixture = Fixture()
    term = TerminalProcess(binary, fixture, columns=40, rows=12)
    try:
        term.wait_for(b"Terminal too small")
        term.send(b"2")
        time.sleep(0.1)
        term.read_once(0.1)
        assert b"sayaka menu child outcome" not in ANSI.sub(b"", bytes(term.transcript))
        term.send(b"q")
        term.finish(0)
        fixture.verify_unchanged()
    finally:
        term.close()
        fixture.close()


def case_sigint_idle(binary: Path):
    fixture = Fixture()
    term = TerminalProcess(binary, fixture)
    try:
        term.wait_for(b"Choose action")
        term.send_signal(signal.SIGINT)
        term.finish(130)
        fixture.verify_unchanged()
    finally:
        term.close()
        fixture.close()


def case_sigint_result_prompt(binary: Path):
    fixture = Fixture()
    term = TerminalProcess(binary, fixture)
    try:
        term.wait_for(b"Choose action")
        select_rule_preview(term, b"2", fixture.root)
        term.send_signal(signal.SIGINT)
        term.finish(130)
        fixture.verify_unchanged()
    finally:
        term.close()
        fixture.close()


def case_sigterm_result_prompt(binary: Path):
    fixture = Fixture()
    term = TerminalProcess(binary, fixture)
    try:
        term.wait_for(b"Choose action")
        select_rule_preview(term, b"2", fixture.root)
        term.send_signal(signal.SIGTERM)
        code = term.wait_exit(timeout=3)
        assert code == 143, f"expected 143 on SIGTERM at result prompt, got {code}"
        term.read_once(0)
        assert termios.tcgetattr(term.slave) == term.before, "terminal attributes were not restored"
        fixture.verify_unchanged()
    finally:
        term.close()
        fixture.close()


def case_sigterm_active_child(binary: Path):
    fixture = Fixture()
    term = TerminalProcess(binary, fixture)
    try:
        term.wait_for(b"Choose action")
        term.key_and_wait(b"2", b"Python cache clean rule")
        term.key_and_wait(b"\r", b"ROOT:")
        term.send(str(fixture.root).encode())
        term.key_and_wait(b"\r", b"Choose rule action mode")
        term.send(b"j")
        term.key_and_wait(b"\r", b"Selection:", timeout=20)
        term.send_signal(signal.SIGTERM)
        term.finish(143)
        fixture.verify_unchanged()
    finally:
        term.close()
        fixture.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    args = parser.parse_args()
    binary = Path(args.binary)
    assert binary.exists(), binary
    if sys.platform != "darwin":
        print("menu PTY checks are macOS-only")
        return 0
    case_startup_and_path_cancel(binary)
    case_repeated_rule_previews(binary)
    case_clean_approval_cancel(binary)
    case_installer_approval_cancel(binary)
    case_child_nonzero_and_ignored_override(binary)
    case_narrow_terminal_blocks_dispatch(binary)
    case_sigint_idle(binary)
    case_sigint_result_prompt(binary)
    case_sigterm_result_prompt(binary)
    case_sigterm_active_child(binary)
    print("menu PTY checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
