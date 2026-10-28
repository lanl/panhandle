# CHANGELOG

## v1.0.25

- Implemented Aya 0.16 improvements:
  - **TestRun for eBPF unit tests**: Added test module in `panhandle-ebpf/src/main.rs`
    with `#[test]` functions for eBPF program logic.
  - **GlobalData for config**: Replaced 6 runtime maps with 2 `GlobalData` structs
    (`PANHANDLE_CONFIG` and `SHELL_CONFIG`) for type-safe, zero-copy config access
    from eBPF programs.
  - **RawTracepoint for execve**: Changed `#[tracepoint]` to `#[raw_tracepoint]`
    with `ctx.arg()` for direct argument access, eliminating BTF dependency.
  - **VerifierLogLevel**: Added `VERIFIER_LOG_LEVEL = DEBUG` in debug mode for
    easier eBPF verifier debugging.
- **Modular architecture**: Split monolithic `main.rs` into focused modules:
  `config.rs`, `ebpf_loader.rs`, `output.rs`, `monitors.rs`, `shell.rs`,
  `blocking.rs`, `error.rs`, `helpers.rs`, `input_configs.rs`.
- **Proper error types**: Added `thiserror` dependency, created `PanhandleError`
  enum with manual `PartialEq` impl for variants wrapping non-`PartialEq` types.
- **Removed unused dependencies**: Removed `bytes`, `config`, `bytemuck` crates.
- **Feature flags**: Added optional feature flags for components
  (`network`, `gpu`, `blocking`, `shell`, `http`, `syslog`, `file`, `default`).
- **Updated test configs**: All test config files updated to new API format
  (direct `http`, `syslog`, `file` fields instead of `output` array).
- **Config validation before root check**: Config file loading and validation
  now happens before root privilege check, enabling integration tests to run
  without root.
- **Comprehensive integration test fixes**: All 21 config_integration tests pass,
  including validation for unknown fields, non-numeric UIDs, comm list conflicts,
  length/count limits, and unsupported file extensions.
- **Linting improvements**: Updated `./scripts/lint` to exclude generated docs
  and handle optional `cargo-outdated`.

## v1.0.24

- Updated to Aya 0.16 from git (tag aya-v0.16.0) to resolve version conflicts
  and use latest eBPF library features.
- Replaced deprecated `serde_yaml` (which used unmaintained `unsafe-libyaml`)
  with `serde-saphyr`, a safe Rust YAML parser using `saphyr` backend.
- Fixed AsyncFd usage to use safe `register_with_interest()` + `ready_mut()`
  instead of deprecated unsound `with_interest()` API.
- Updated HashMap `insert()` calls to use references (`&key, &value`) per
  Aya 0.16 API changes.
- Updated UProbe `attach()` to use iterator of attach points per Aya 0.16 API.
- Added comprehensive linting infrastructure: markdownlint, yamllint,
  jsonlint, cargo deny, cargo clippy, cargo fmt via `./scripts/lint`.
- Added `./scripts/update` for dependency updates and SBOM generation.
- Updated documentation: README, CHANGELOG, CONTRIBUTORS, man page.
- Fixed YAML test configs to pass yamllint.
- Bumped version to 1.0.24.

## v1.0.23

- Fixed a startup crash when a `block_paths` or `include_uid` entry supplied
  via the config file (rather than the CLI) exceeded the length/format limits
  that were previously only enforced for CLI-sourced values.
- Fixed a startup crash when the canonicalized path to `/bin/bash` or
  `/bin/zsh` wasn't valid UTF-8.
- Fixed config-file `comm_allow`/`comm_deny` entries over the length limit
  being silently truncated instead of rejected, unlike the equivalent
  CLI-sourced values.
- Fixed a `--block-paths` bypass in the file-open blocker where a path
  exactly filling the internal scratch buffer could be misread as an empty
  path and allowed through.
- Fixed shell-name matching for execve filtering (`sh`, `bash`, `zsh`,
  `tcsh`, `csh`) to require an exact comm match, so processes like
  `shutdown` or `shred` no longer false-positive as shells.
- Replaced the per-PID socket usage stats map, which was not atomic across
  CPUs (concurrent updates for the same PID on different cores could lose an
  update) and never evicted a PID once it had sent or received any data
  (letting the map fill permanently on a long-running host), with a stateless
  ring-buffer-based design accumulated in userspace.
- Fixed execve event logging embedding raw NUL bytes into JSON output and
  log lines.
- Fixed per-process network connection/interface attribution reporting the
  same (arbitrary) connection for every process sharing a network namespace
  instead of that process's own; added IPv6 support to this same lookup,
  which previously only handled IPv4.
- Fixed `--memory`'s shared/data MB figures assuming a 4KB page size, which
  undercounts on architectures using larger pages.
- Fixed syslog output performing blocking socket I/O directly on the async
  runtime, which could stall event processing for the whole host if the
  remote syslog target was slow or unreachable.
- Raised the HTTP log output timeout from an unrealistic 200ms to 3 seconds,
  reducing silent event loss to ordinary network latency.
- Fixed the RPM uninstall script never actually running (it wasn't wired
  up); it's now correctly invoked before removal so the service is stopped
  rather than left running with its files gone.
- Added baseline systemd hardening (`NoNewPrivileges`, `ProtectHome`,
  `PrivateTmp`) to the packaged service unit and fixed a service startup
  ordering race with `network-online.target`.
- Fixed the man page documenting the version flag as `--Version` instead of
  the actual `--version`.

## v1.0.22

- Added integration tests.

## v1.0.21

- Fixed the `--bash` option for newer CPUs.

## v1.0.20

- Fixed a bug where `--executables` silently discarded every event queued
  behind the first non-matching one in a ring buffer batch, so matching
  events were dropped without any indication; each non-matching event is now
  skipped individually.
- Added test coverage for the `--executables` filter, including the
  batch-skipping regression.

## v1.0.19

- Added CI for ARM and SLES to the GitHub CI.

## v1.0.18

- Fixed a bug where the first CPU% sample after starting `--cpu` could spike
  (or clamp to 100%) because there was no prior sample yet to compare
  against.
- Fixed a bug where the system-wide CPU% baseline could be poisoned by a
  transient `/proc/stat` read failure, causing an inflated delta on the next
  successful sample.
- Fixed the `--cpu` per-PID tracking to drop stale PIDs from its internal
  maps each poll, closing a memory-growth leak.
- Fixed a bug where providing both `--comm-deny` and `--comm-allow` silently
  used the deny list instead of erroring as intended.
- Removed a redundant procfs read per PID in `--cpu` by reusing the
  already-open process handle instead of looking up the process a second
  time.
- Fixed a bug where the documented `--block-paths`/`--comm-allow`/`--comm-deny`
  maximums (64 entries) were never actually enforced for the documented
  comma-separated usage, since clap's per-flag argument limit doesn't apply
  to values split out of a single delimited argument; these are now checked
  explicitly at startup like the existing `--executables`/`--include-uid`
  limits.
- Added test coverage for CLI argument parsing (including the process-blocking
  list options and their length/count limits), the default-monitor fallback
  logic, config-file/CLI argument merging, network interface resolution, and
  CPU accounting.
- `--verbose` now also reports each process's owner (UID and resolved
  username) and current state (running/sleeping/etc) alongside the existing
  PPID/Parent_Comm, across the `--cpu`, `--gpu`, `--io`, `--socket`,
  `--memory`, and `--memory-faults` reports; username resolution is cached
  per poll to avoid repeat NSS/LDAP lookups for processes sharing a UID.
- Added test coverage for the new owner/state resolution
  (`get_process_uid`, `resolve_username`) and formatting
  (`format_owner`, `format_state`) helpers.
- `--debug` now logs each eBPF program's load/attach outcome by name
  (uprobes, kprobes, tracepoints, and LSM hooks) instead of leaving success
  silent and failure to surface only as a generic top-level error; attach
  failures are always logged, not just under `--debug`.
- Standardized JSON outputs to use JSON numbers instead of strings.
- Extracted JSON generators to standardize with tests instead of using debug
  formatting which can be error prone.

## v1.0.17

- Updated to aya v0.14, switching execve/readline/zlentry event delivery
  from per-CPU perf arrays to ring buffers.
- Reduced allocations and blocking I/O in the periodic
  cpu/network/gpu/io/memory/fault monitors, and cached the network
  interface list instead of re-querying it per PID.
- Switched `--cpu` from an always-on sched_switch eBPF probe to procfs
  polling, fixing PID-reuse and map-exhaustion bugs in the old
  implementation; added a system-wide CPU% summary alongside the existing
  per-PID reporting.

## v1.0.16

- Added process blocking. Control how blocking is done using the
  comm-deny, comm-allow, syscalls, and block-paths options.

## v1.0.15

- Reduced resource allocation to reduce memory footprint.

## v1.0.14

- Added I/O usage monitoring, displaying disk reads/writes and inode
  creation. Can be filtered by PIDs using `--pid-list`. The poll interval
  can be adjusted using `--poll`.

## v1.0.13

- Added GPU usage monitoring, displaying metrics like VRAM utilization. Can
  be filtered by PIDs using `--pid-list`. The poll interval can be adjusted
  using `--poll`.

## v1.0.12

- Added network usage monitoring, displaying connection counts and socket
  states. Can be filtered by PIDs using `--pid-list`. The poll interval can
  be adjusted using `--poll`.

## v1.0.11

- Added memory usage monitoring, displaying RSS per PID. Can be filtered by
  PIDs using `--pid-list`. The poll interval can be adjusted using
  `--poll`.

## v1.0.10

- Added CPU usage monitoring, displaying utilization. Can be filtered by
  PIDs using `--pid-list`. The poll interval can be adjusted using
  `--poll`.

## v1.0.9

- Added monitoring for sockets and memory paging.

## v1.0.8

- Changed how the output subcommand is read in from the provided config file
  to support current Ansible YAML syntax.

## v1.0.7

- Bugfix for the quiet option.

## v1.0.6

- Added a `--quiet` option to not output to the terminal logger.

## v1.0.5

- Added a config file option and updated associated files (manpage, systemd
  service).

## v1.0.4

- Added an output subcommand for consolidating outputs.
- Fixed the file output always creating a new file.
- Added hostname to the message field.
- Updated README.

## v1.0.3

- Added a syslog output.
