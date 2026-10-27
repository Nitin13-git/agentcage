from __future__ import annotations

import builtins
import os
import socket
import subprocess

from agentcage.scope import CapabilityKind, Scope


class CageViolation(PermissionError):
    pass


class PathGuard:
    """Blocks `open()` calls on paths not granted in scope.

    Patches `builtins.open` for the lifetime of the context manager and
    restores the original on exit, including on exception.
    """

    def __init__(self, scope: Scope) -> None:
        self._scope = scope
        self._original_open = None

    def __enter__(self) -> PathGuard:
        self._original_open = builtins.open
        original_open = self._original_open
        scope = self._scope

        def guarded_open(path, *args, **kwargs):
            target = os.fspath(path)
            if not scope.allows(CapabilityKind.PATH, target):
                raise CageViolation(f"path not in scope: {target}")
            return original_open(path, *args, **kwargs)

        builtins.open = guarded_open
        return self

    def __exit__(self, *exc_info) -> None:
        builtins.open = self._original_open


class CommandGuard:
    """Blocks `subprocess` calls on commands not granted in scope.

    Patches `subprocess.Popen.__init__`, which `subprocess.run`, `.call`,
    and `.check_call` all go through, so one patch point covers the
    standard library's subprocess entry points.
    """

    def __init__(self, scope: Scope) -> None:
        self._scope = scope
        self._original_init = None

    def __enter__(self) -> CommandGuard:
        self._original_init = subprocess.Popen.__init__
        original_init = self._original_init
        scope = self._scope

        def guarded_init(self_popen, args, *rest, **kwargs):
            command = args[0] if isinstance(args, (list, tuple)) else args
            name = os.path.basename(command)
            if not scope.allows(CapabilityKind.COMMAND, name):
                raise CageViolation(f"command not in scope: {name}")
            return original_init(self_popen, args, *rest, **kwargs)

        subprocess.Popen.__init__ = guarded_init
        return self

    def __exit__(self, *exc_info) -> None:
        subprocess.Popen.__init__ = self._original_init


class NetworkGuard:
    """Blocks outbound `socket.connect()` calls to hosts not granted in scope."""

    def __init__(self, scope: Scope) -> None:
        self._scope = scope
        self._original_connect = None

    def __enter__(self) -> NetworkGuard:
        self._original_connect = socket.socket.connect
        original_connect = self._original_connect
        scope = self._scope

        def guarded_connect(self_socket, address):
            host = address[0] if isinstance(address, tuple) else str(address)
            if not scope.allows(CapabilityKind.HOST, host):
                raise CageViolation(f"host not in scope: {host}")
            return original_connect(self_socket, address)

        socket.socket.connect = guarded_connect
        return self

    def __exit__(self, *exc_info) -> None:
        socket.socket.connect = self._original_connect
