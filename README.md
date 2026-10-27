# AgentCage

Least-privilege sandboxing for a single agent session, at the Python
process level: declare the paths, commands, and hosts a session is allowed
to touch, then run arbitrary code inside `with Cage(scope):` — anything
outside that scope raises `CageViolation` instead of silently happening.

## How it works

`Cage` patches three standard-library entry points for the lifetime of the
`with` block and restores them unconditionally on exit:

- **`PathGuard`** — patches `builtins.open`; blocks any path not matching a
  granted `PATH` pattern.
- **`CommandGuard`** — patches `subprocess.Popen.__init__` (which `run`,
  `call`, and `check_call` all go through); blocks any command whose
  basename isn't a granted `COMMAND` pattern.
- **`NetworkGuard`** — patches `socket.socket.connect`; blocks any outbound
  connection to a host that isn't a granted `HOST` pattern.

This is process-level, monkeypatch-based enforcement, not a kernel sandbox —
it stops an agent's *own Python-level actions* (and anything called through
the patched stdlib entry points) from reaching outside its declared scope.
It is not a substitute for OS-level isolation (containers, VMs, seccomp) if
you're running code you don't trust at all; it's the harness-side
least-privilege layer that sits in front of that.

## Quickstart

```bash
pip install -e ".[dev]"
pytest
```

```python
from agentcage import Cage, Scope

scope = Scope().paths("/repo/workdir/*").commands("pytest", "git").hosts("127.0.0.1")

with Cage(scope):
    ...  # only the granted paths/commands/hosts are reachable here
```

## License

MIT
