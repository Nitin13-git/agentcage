from __future__ import annotations

from contextlib import ExitStack

from agentcage.guards import CommandGuard, NetworkGuard, PathGuard
from agentcage.scope import Scope


class Cage:
    """Enforces a Scope's path, command, and host capabilities for one block.

    `with Cage(scope):` denies by default and only allows what the scope
    explicitly grants, for everything run inside the block — not just the
    agent's own code, but any library it calls into, since the guards
    patch the standard library entry points directly.
    """

    def __init__(self, scope: Scope) -> None:
        self._scope = scope
        self._stack = ExitStack()

    def __enter__(self) -> Cage:
        self._stack.enter_context(PathGuard(self._scope))
        self._stack.enter_context(CommandGuard(self._scope))
        self._stack.enter_context(NetworkGuard(self._scope))
        return self

    def __exit__(self, *exc_info) -> None:
        self._stack.close()
