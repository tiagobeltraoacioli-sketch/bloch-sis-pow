#!/usr/bin/env python3
"""Exercise the real keys-seal terminal path without reading or creating keys.

Each supervisor retains the controlling PTY after its child exits, allowing
termios inspection. Normal input intentionally mismatches confirmation before
any keystore operation. Signal cases use only public disposable test markers.
"""
import fcntl
import os
import pty
import select
import signal
import sys
import tempfile
import termios
import time

BINARY = os.path.abspath(sys.argv[1])
JOB_CONTROL = (signal.SIGTSTP, signal.SIGTTIN, signal.SIGTTOU)


def case(label, directory, sig=None, mode="", repeat=False):
    master, slave = pty.openpty()
    saved = termios.tcgetattr(slave)
    supervisor = os.fork()
    if supervisor == 0:
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
        signal.signal(signal.SIGTTOU, signal.SIG_IGN)
        for fd in (0, 1, 2):
            os.dup2(slave, fd)
        os.close(master)
        gate_r, gate_w = os.pipe()
        worker = os.fork()
        if worker == 0:
            os.close(gate_w)
            os.setpgid(0, 0)
            os.read(gate_r, 1)
            os.close(gate_r)
            signal.signal(signal.SIGTTOU, signal.SIG_DFL)
            if mode == "blocked":
                signal.pthread_sigmask(signal.SIG_BLOCK, [signal.SIGTERM])
            elif mode == "ignored":
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
            for key in list(os.environ):
                if key.startswith("BLOCH_KEYSTORE_"):
                    del os.environ[key]
            os.execv(BINARY, [BINARY, "keys", "seal", "--dir", directory])
        os.close(gate_r)
        os.setpgid(worker, worker)
        os.tcsetpgrp(slave, worker)
        os.write(1, ("PID:" + str(worker) + "\n").encode())
        os.write(gate_w, b"x")
        os.close(gate_w)
        while True:
            _, status = os.waitpid(worker, os.WUNTRACED)
            if os.WIFSTOPPED(status):
                os.write(1, b"STOPPED\n")
                continue
            os.write(1, ("FINISHED:" + str(status) + "\n").encode())
            break
        # The parent ends this supervisor after examining the terminal.
        time.sleep(30)
        os._exit(0)
    output = b""
    worker = None

    def until(marker):
        nonlocal output
        deadline = time.monotonic() + 10
        while marker not in output and time.monotonic() < deadline:
            if select.select([master], [], [], .05)[0]:
                output += os.read(master, 4096)
        assert marker in output, (label, output)

    def echo_is_restored():
        return termios.tcgetattr(slave) == saved

    try:
        until(b"New keystore passphrase: ")
        worker = int(output.split(b"PID:")[1].split()[0])
        assert not (termios.tcgetattr(slave)[3] & termios.ECHO), (label, output)
        if repeat:
            os.write(master, b"public-first-marker\n")
            until(b"Repeat passphrase: ")
            assert not (termios.tcgetattr(slave)[3] & termios.ECHO), (label, output)
        if sig is not None:
            os.write(master, b"public-partial-marker")
            os.kill(worker, sig)
            if sig in JOB_CONTROL:
                until(b"STOPPED")
                assert echo_is_restored(), "terminal must restore before suspension"
                os.kill(worker, signal.SIGCONT)
        if sig is None or mode:
            if mode:
                time.sleep(.2)
            os.write(master, b"public-first-marker\n")
            until(b"Repeat passphrase: ")
            assert not (termios.tcgetattr(slave)[3] & termios.ECHO), (label, output)
            os.write(master, b"public-different-marker\n")
        until(b"FINISHED:")
        worker = None  # Already reaped: never signal a potentially reused PID.
        assert echo_is_restored(), (label, output)
        status = int(output.split(b"FINISHED:")[1].split()[0])
        if sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT) and not mode:
            assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == sig, (label, status, output)
        else:
            assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 1, (label, status, output)
            expected = b"interrupted" if sig in JOB_CONTROL else b"passphrases do not match"
            assert expected in output, (label, output)
        assert b"public-" not in output, (label, output)
        assert not os.path.exists(directory), "test must stop before any key operation"
        print("PASS", label, flush=True)
    finally:
        termios.tcsetattr(slave, termios.TCSANOW, saved)
        if worker:
            try:
                os.kill(worker, signal.SIGKILL)
            except ProcessLookupError:
                pass
        os.kill(supervisor, signal.SIGKILL)
        # macOS session teardown can wait for retained terminal descriptors.
        os.close(master)
        os.close(slave)
        os.waitpid(supervisor, 0)


with tempfile.TemporaryDirectory(prefix="bloch-native-tty-") as root:
    absent = os.path.join(root, "never-created")
    case("normal-confirmation-mismatch", absent)
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT, *JOB_CONTROL):
        case(signal.Signals(sig).name, absent, sig=sig)
    case("repeat-prompt-SIGTERM", absent, sig=signal.SIGTERM, repeat=True)
    for mode in ("blocked", "ignored"):
        case("caller-" + mode + "-SIGTERM", absent, sig=signal.SIGTERM, mode=mode)
