# Contributing

Contributions that improve safe CTF learning, correctness, portability, or documentation are welcome.

## Development checks

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
ruff format --check .
ruff check .
mypy
pytest
python -m build
```

Tests must be deterministic and network-free. Scanner tests must inject a fake resolver, executable lookup,
and process runner. Never contact a live CTF machine from CI.

## Safety boundaries

- Keep scan targets explicit, authorized, address-validated, and rate-limited.
- Do not add credential attacks, persistence, exploit delivery, evasion, destructive actions, or reverse shells.
- Do not execute or dynamically import analyzed files.
- Keep decoding single-pass and resource-bounded.
- Add regression tests for every validation or security-sensitive change.

Open a focused pull request and describe both behavior and verification results.
