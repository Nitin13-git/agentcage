from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from enum import Enum


class CapabilityKind(str, Enum):
    PATH = "path"
    COMMAND = "command"
    HOST = "host"


@dataclass(frozen=True)
class Capability:
    kind: CapabilityKind
    pattern: str


class Scope:
    """A least-privilege capability set: deny anything not explicitly granted."""

    def __init__(self, *capabilities: Capability) -> None:
        self._granted = set(capabilities)

    def grant(self, capability: Capability) -> None:
        self._granted.add(capability)

    def allows(self, kind: CapabilityKind, value: str) -> bool:
        return any(
            cap.kind == kind and fnmatch.fnmatch(value, cap.pattern) for cap in self._granted
        )

    def paths(self, *patterns: str) -> Scope:
        for pattern in patterns:
            self.grant(Capability(CapabilityKind.PATH, pattern))
        return self

    def commands(self, *patterns: str) -> Scope:
        for pattern in patterns:
            self.grant(Capability(CapabilityKind.COMMAND, pattern))
        return self

    def hosts(self, *patterns: str) -> Scope:
        for pattern in patterns:
            self.grant(Capability(CapabilityKind.HOST, pattern))
        return self
