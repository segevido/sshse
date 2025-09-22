# System Testing Strategy

This project now includes a lightweight system test harness that exercises the
CLI via real subprocess execution. The goals of these tests are to:

- verify that the installed entry point behaves correctly when invoked with
  common flags and subcommands;
- validate the interaction with on-disk configuration data without relying on
  unit-level monkeypatching;
- provide a foundation for future end-to-end workflows (e.g. credential
  management, history browser flows) as features grow.

## How the harness works

- System tests live under `tests/system/` and are tagged with the `system`
  pytest marker.
- A shared fixture (`run_cli`) launches the CLI through `python -m sshse`. This
  executes the same entry point users rely on while keeping control over
  standard I/O capture for assertions.
- Tests run with an isolated environment that points `SSHSE_DATA_DIR` to a
  temporary directory. Runtime components (config, history, credentials) honour
  this override so system tests never touch a developer's real state.
- The fixture also ensures `PYTHONPATH` includes the project root so the
  in-repo sources are importable without an editable install.

## Running the system suite

```bash
pytest -m system
```

The command above runs only the system tests. They also execute as part of the
regular suite; the marker allows selectively running them when iterating on
end-to-end behaviours. The complementary unit suite executes with
`pytest -m unit`, which is the command exercised in CI for coverage.

## Extending system coverage

When adding new CLI functionality:

1. Prefer asserting behaviour through the CLI surface (commands, flags, exit
   codes) instead of internal functions.
2. Use the existing fixtures to prepare any required state. For example, write
   configuration files via `ConfigStore` into `system_data_dir` before invoking
   the CLI.
3. If a scenario needs additional environment configuration, pass overrides via
   the `extra_env` parameter on `run_cli`.

These patterns keep system tests hermetic, deterministic, and fast enough to run
routinely alongside unit tests.
