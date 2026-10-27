import socket
import subprocess
import threading
from pathlib import Path

import pytest

from agentcage import Cage, CageViolation, CommandGuard, NetworkGuard, PathGuard, Scope


def test_path_guard_blocks_unlisted_path(tmp_path: Path) -> None:
    scope = Scope()
    with PathGuard(scope), pytest.raises(CageViolation):
        open(tmp_path / "secret.txt", "w")


def test_path_guard_allows_listed_path(tmp_path: Path) -> None:
    scope = Scope().paths(f"{tmp_path}/*")
    target = tmp_path / "allowed.txt"
    with PathGuard(scope):
        with open(target, "w") as f:
            f.write("hello")
    assert target.read_text() == "hello"


def test_path_guard_restores_open_after_exit(tmp_path: Path) -> None:
    scope = Scope()
    with PathGuard(scope):
        pass
    # Outside the guard, unrestricted opens work again.
    target = tmp_path / "unguarded.txt"
    with open(target, "w") as f:
        f.write("ok")
    assert target.read_text() == "ok"


def test_command_guard_blocks_unlisted_command() -> None:
    scope = Scope()
    with CommandGuard(scope), pytest.raises(CageViolation):
        subprocess.run(["true"])


def test_command_guard_allows_listed_command() -> None:
    scope = Scope().commands("true")
    with CommandGuard(scope):
        result = subprocess.run(["true"])
    assert result.returncode == 0


def _start_echo_server() -> tuple[socket.socket, int]:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def accept_once() -> None:
        try:
            conn, _ = server.accept()
            conn.close()
        except OSError:
            pass  # the blocked-connection test never completes a handshake

    threading.Thread(target=accept_once, daemon=True).start()
    return server, port


def test_network_guard_blocks_unlisted_host() -> None:
    server, port = _start_echo_server()
    try:
        scope = Scope()
        with NetworkGuard(scope), pytest.raises(CageViolation):
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect(("127.0.0.1", port))
    finally:
        server.close()


def test_network_guard_allows_listed_host() -> None:
    server, port = _start_echo_server()
    try:
        scope = Scope().hosts("127.0.0.1")
        with NetworkGuard(scope):
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect(("127.0.0.1", port))
            client.close()
    finally:
        server.close()


def test_cage_enforces_all_three_guards_together(tmp_path: Path) -> None:
    scope = Scope().paths(f"{tmp_path}/*").commands("true")
    with Cage(scope):
        with open(tmp_path / "ok.txt", "w") as f:
            f.write("ok")
        subprocess.run(["true"])
        with pytest.raises(CageViolation):
            subprocess.run(["false"])

    # Guards are fully removed once the Cage block exits.
    subprocess.run(["false"])
