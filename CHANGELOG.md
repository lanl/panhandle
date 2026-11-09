# CHANGELOG

## v1.0.26

- **Added `--cgroup <PATH>`**: scopes `--syscalls` blocking to a single cgroup v2
  directory (e.g. `/sys/fs/cgroup/myjob.slice`) instead of system-wide. Uses aya's
  `LsmCgroup` program type (separate `block_open_cgroup`/`block_execve_cgroup`
  eBPF programs alongside the existing system-wide `block_open`/`block_execve` -
  the kernel's BPF_LSM_CGROUP and BPF_LSM_MAC attach types need their own
  `#[lsm_cgroup]`/`#[lsm]` sections even though the blocking logic is identical).
  Requires a kernel with LsmCgroup support (6.0+) and, like `--syscalls` generally,
  "bpf" in the kernel's active LSM list to actually enforce anything (same
  startup warning as plain `--syscalls` applies). Works through `--config` (YAML
  and JSON) with the usual CLI-overrides-config precedence.
  **Along the way, found a real correctness issue specific to this attach type**:
  cgroup-scoped LSM programs must return `0` (allow) or `1` (deny) - the verifier
  rejects the `-EPERM` convention the system-wide programs use ("At program exit
  the register R0 ... should have been in [0, 1]"). The shared blocking decision
  logic was refactored to a plain bool (`should_block_open`/`should_block_execve`),
  with each `#[lsm]`/`#[lsm_cgroup]` wrapper translating it to whichever
  convention its attach type requires.
- **`--bound`'s network-wait timing now covers UDP, not just TCP**: added an
  `udp_recvmsg` fentry/fexit pair alongside the existing `tcp_recvmsg` one,
  folding into the same `NET_WAIT` accumulator per process - "Network_Wait"
  is meant to be protocol-agnostic time spent waiting on any socket read.
- **`--bound`/`--socket`'s kprobes replaced with fentry/fexit** (aya 0.16
  exposes `FEntry`/`FExit` program types): `tcp_recvmsg`/`udp_recvmsg` (wait
  timing), `tcp_sendmsg`/`tcp_cleanup_rbuf`/`udp_sendmsg`/`udp_recvmsg` (byte
  counting). fentry/fexit attach via a BTF trampoline instead of a kprobe's
  breakpoint trap, at near-zero overhead per call - worth it here since these
  all run on every socket read/write.
- **Fixed: `--socket`'s UDP received-byte count was the requested buffer
  size, not the actual bytes received.** The old kprobe on `udp_recvmsg`
  read its `len` argument at function entry - the size of the buffer the
  caller passed to `recvfrom()`/`recvmsg()`, not how much data arrived.
  Verified live: 50 datagrams of 10 real bytes each, read into a
  65507-byte buffer, reported ~3 MB received instead of the correct ~0 MB.
  Moving to fexit and reading the function's actual return value (bytes
  received, or a negative errno on failure) fixes this; the same
  entry-vs-return-value issue applied to `tcp_sendmsg`/`udp_sendmsg` (a
  short write or a failed send could be counted as a full-size success),
  fixed the same way.
- Implemented Aya 0.16 improvements:
  - **TestRun for eBPF unit tests**: Added test module in
    `panhandle-ebpf/src/main.rs` with `#[test]` functions for eBPF program
    logic.
  - **VerifierLogLevel**: Added `VERIFIER_LOG_LEVEL = DEBUG` in debug mode for
    easier eBPF verifier debugging.
  - UID filtering for the execve/readline/zlentry programs stays on the
    original runtime-configurable `uid_options`/`uid_include_list` maps
    rather than load-time-only `GlobalData`, so those filters can still be
    changed without reloading the eBPF program.
- **Fixed: default execve monitoring never actually attached.** An earlier
  change on this branch moved `panhandle`'s execve tracepoint from
  `#[tracepoint]` to `#[raw_tracepoint]`, attached by the per-syscall name
  `sys_enter_execve`. The kernel only exposes raw tracepoints named
  `sys_enter`/`sys_exit` (shared across every syscall - there is no raw
  tracepoint per syscall), so `bpf_raw_tracepoint_open` always failed with
  ENOENT on real hardware. Reverted to a plain `#[tracepoint]` on
  `syscalls:sys_enter_execve`, which does have its own per-syscall tracepoint.
  This is the default monitoring mode (no flags needed), so it affected every
  invocation of the binary that didn't pass `--bash`/`--zsh`/etc.
- **Fixed: `--bash`/`--zsh`/`--syscalls` failed to load ("fd N is not
  pointing to valid bpf_map").** `ebpf_loader::load_ebpf` populated the
  `uid_options`/`uid_include_list`-family maps by `take_map`-ing them, which
  deregisters a map from the loaded object; the `readline`/`zlentry`
  programs (and `block_open`/`block_execve` for `--syscalls`) couldn't then
  resolve their own map relocations when loaded afterward. Added
  `get_hash_map_mut` (borrows via `map_mut` instead of removing the map) and
  switched both call sites to it.
- **`main.rs` now actually uses the modular helpers**: `ebpf_loader.rs`
  (program loading/attaching, UID-filter map population) and `blocking.rs`
  (syscall blocking) are wired into `main.rs` instead of duplicating that
  logic inline. `config.rs` is kept (`AppConfig`/`PanhandleConfig`/
  `ShellConfig` back both of the above). `monitors.rs`, `shell.rs`, and
  `output.rs` were a second, never-adopted implementation of `main.rs`'s
  CPU/GPU/IO/memory/process-bounds monitoring and event output - deleted,
  along with their dedicated tests, rather than left to drift further from
  what `main.rs` actually does.
- **Proper error types**: Added `thiserror` dependency, created `PanhandleError`
  enum with manual `PartialEq` impl for variants wrapping non-`PartialEq` types.
- **Removed unused dependencies**: Removed `bytes`, `config`, `bytemuck` crates.
- **Updated test configs**: All test config files updated to new API format
  (direct `http`, `syslog`, `file` fields instead of `output` array).
- **Config validation before root check**: Config file loading and validation
  now happens before root privilege check, enabling integration tests to run
  without root.
- **Comprehensive integration test fixes**: All 21 config_integration tests
  pass, including validation for unknown fields, non-numeric UIDs, comm list
  conflicts, length/count limits, and unsupported file extensions.
- **Linting improvements**: Updated `./scripts/lint` to exclude generated docs
  and handle optional `cargo-outdated`.
- **`aya`/`aya-log`/etc. now sourced from crates.io releases** instead of the
  `aya-v0.16.0` git tag, now that upstream publishes matching versions there.
  Pinned to a minimum version (not an exact `=` pin), and bumped `aya-ebpf`/
  `aya-log-ebpf` to the latest published releases.
- **Fixed: `--bound`'s network-wait stats were silently zero for
  multi-threaded processes.** `tcp_recvmsg_entry`/`tcp_recvmsg_exit` keyed
  the `NET_WAIT` accumulator by the raw kernel pid (the specific *thread*
  that called `tcp_recvmsg`) instead of the tgid (the process id every
  consumer, including `monitor_process_bounds.rs`'s procfs-driven lookup,
  actually uses). Any process whose network I/O ran on a thread other than
  the group leader - normal for most multi-threaded servers/clients - never
  showed `Network_Wait_Count`/`Network_Wait_Time_MS` above 0.
- **Fixed: `--memory-faults` silently ignored `--pid-list`**, despite
  `--pid-list`'s own help text listing `memory_faults` as one of the
  options it filters - it never accepted a `pid_filter` parameter at all.
- **Performance: `--bound` opened a fresh netlink socket per process, per
  poll cycle.** `linux_taskstats::Client::open()` does a full generic-netlink
  round trip to resolve the taskstats family id; it's now opened once per
  cycle and reused across every process instead.
- **Performance: parent-process-name lookups weren't cached under
  `--verbose`** for `memory`/`memory-faults`/`io`/`network`/`gpu` (many
  processes commonly share one parent - a shell, container init, etc.) -
  `cpu` already cached this; the same per-poll cache is now applied
  consistently.
- **Fixed: `--debug` mangled event output into invalid pseudo-JSON.**
  `info!("\\{:#?}\\", json_string)` debug-formatted an already-serialized
  JSON *string*, re-escaping it and wrapping the result in literal
  backslashes - not pretty-printed, not readable, and not valid JSON. All
  three call sites now log the already-valid JSON or prose string as-is.
- **Execve/shell event JSON now built with `serde_json::json!`** instead of
  hand-templated `format!`, and uid/pid/gid/tgid serialize as JSON numbers
  instead of quoted strings, matching every other event type in this
  codebase.
- **`main.rs` no longer duplicates library modules.** `helpers.rs`,
  `input_configs.rs`, `monitor_cpu_usage.rs`, `monitor_gpu_usage.rs`,
  `monitor_io_usage.rs`, `monitor_network_usage.rs`, and `procfs_helpers.rs`
  were each compiled twice - once in the `panhandle` lib target, again as a
  separate local copy in the bin - letting the two drift out of sync
  undetected. `main.rs` now imports these from the lib crate instead.
- **New debug/verbose diagnostics**: a one-line summary of what's actually
  enabled (monitors, `--pid-list`, poll interval) at startup; per-poll scan
  timing and `--pid-list` match counts for every procfs-scanning monitor;
  and which side (CLI or config file) supplied each merged value when both
  are used together - all under `--debug`.
- **Documented exclude/include UID precedence**: a uid inside
  `--exclude-min-uid`/`--exclude-max-uid`'s range stays excluded even if
  it's also listed in `--include-uid` (the eBPF side checks exclude first);
  now noted in `--help` and the man page.
- **Added `scripts/verify-functionality`**: a live regression suite that
  runs the compiled binary against a real kernel as root, covering every
  CLI/config option and the combinations most likely to interact. Not run
  by CI by default (needs root and working eBPF) - see the script's header.
- **Fixed: `--syscalls` could silently block nothing, with no error.**
  Verified live via `strace`: a `BPF_PROG_TYPE_LSM` program's
  `BPF_PROG_LOAD`/`BPF_RAW_TRACEPOINT_OPEN` (attach) calls both succeed
  purely based on `CONFIG_BPF_LSM=y` being compiled into the kernel - they
  don't check whether `bpf` is actually part of the kernel's *active* LSM
  list (`/sys/kernel/security/lsm`). If it isn't, the kernel's security
  framework never calls the attached hook at all, so `--syscalls` starts up
  clean, logs nothing unusual, and enforces nothing. Added a startup check
  (`blocking::bpf_lsm_active`) that prints a loud warning when `bpf` is
  absent from `/sys/kernel/security/lsm`, so an operator can't mistake a
  running-with-no-errors process for one that's actually blocking anything.
  `scripts/verify-functionality` now asserts this warning fires on hosts
  where the condition reproduces (this dev host included), and skips the
  actual-blocking assertion there instead of silently appearing to pass.

## v1.0.24

Added process bound reporting. Receive a report of what processes are bound by
through per process delay counts and delay times. Includes memory, cpu, io,
and network.

## v1.0.23

- fixed a startup crash when a `block_paths` or `include_uid` entry supplied
  via the config file (rather than the CLI) exceeded the length/format limits
  that were previously only enforced for CLI-sourced values
- fixed a startup crash when the canonicalized path to `/bin/bash` or
  `/bin/zsh` wasn't valid UTF-8
- fixed config-file `comm_allow`/`comm_deny` entries over the length limit
  being silently truncated instead of rejected, unlike the equivalent
  CLI-sourced values
- fixed a `--block-paths` bypass in the file-open blocker where a path
  exactly filling the internal scratch buffer could be misread as an empty
  path and allowed through
- fixed shell-name matching for execve filtering (`sh`, `bash`, `zsh`,
  `tcsh`, `csh`) to require an exact comm match, so processes like
  `shutdown` or `shred` no longer false-positive as shells
- replaced the per-PID socket usage stats map, which was not atomic across
  CPUs (concurrent updates for the same PID on different cores could lose an
  update) and never evicted a PID once it had sent or received any data
  (letting the map fill permanently on a long-running host), with a stateless
  ring-buffer-based design accumulated in userspace
- fixed execve event logging embedding raw NUL bytes into JSON output and log
  lines
- fixed per-process network connection/interface attribution reporting the
  same (arbitrary) connection for every process sharing a network namespace
  instead of that process's own; added IPv6 support to this same lookup,
  which previously only handled IPv4
- fixed `--memory`'s shared/data MB figures assuming a 4KB page size, which
  undercounts on architectures using larger pages
- fixed syslog output performing blocking socket I/O directly on the async
  runtime, which could stall event processing for the whole host if the
  remote syslog target was slow or unreachable
- raised the HTTP log output timeout from an unrealistic 200ms to 3 seconds,
  reducing silent event loss to ordinary network latency
- fixed the RPM uninstall script never actually running (it wasn't wired up);
  it's now correctly invoked before removal so the service is stopped rather
  than left running with its files gone
- added baseline systemd hardening (`NoNewPrivileges`, `ProtectHome`,
  `PrivateTmp`) to the packaged service unit and fixed a service startup
  ordering race with `network-online.target`
- fixed the man page documenting the version flag as `--Version` instead of
  the actual `--version`

## v1.0.22

- adding integration tests

## v1.0.21

- fixed the --bash option for newer cpus

## v1.0.20

- fixed a bug where `--executables` silently discarded every event queued
  behind the first non-matching one in a ring buffer batch, so matching
  events were dropped without any indication; each non-matching event is now
  skipped individually
- added test coverage for the `--executables` filter, including the
  batch-skipping regression

## v1.0.19

- added ci for arm and sles to the GitHub ci

## v1.0.18

- fixed a bug where the first CPU% sample after starting --cpu could spike
  (or clamp to 100%) because there was no prior sample yet to compare against
- fixed a bug where the system-wide CPU% baseline could be poisoned by a
  transient /proc/stat read failure, causing an inflated delta on the next
  successful sample
- fixed the --cpu per-PID tracking to drop stale PIDs from its internal maps
  each poll, closing a memory-growth leak
- fixed a bug where providing both --comm-deny and --comm-allow silently
  used the deny list instead of erroring as intended
- removed a redundant procfs read per PID in --cpu by reusing the
  already-open process handle instead of looking up the process a second time
- fixed a bug where the documented --block-paths/--comm-allow/--comm-deny
  maximums (64 entries) were never actually enforced for the documented
  comma-separated usage, since clap's per-flag argument limit doesn't apply
  to values split out of a single delimited argument; these are now checked
  explicitly at startup like the existing --executables/--include-uid limits
- added test coverage for CLI argument parsing (including the process-blocking
  list options and their length/count limits), the default-monitor fallback
  logic, config-file/CLI argument merging, network interface resolution, and
  CPU accounting
- --verbose now also reports each process's owner (UID and resolved username)
  and current state (running/sleeping/etc) alongside the existing
  PPID/Parent_Comm, across the --cpu, --gpu, --io, --socket, --memory, and
  --memory-faults reports; username resolution is cached per poll to avoid
  repeat NSS/LDAP lookups for processes sharing a UID
- added test coverage for the new owner/state resolution
  (get_process_uid, resolve_username) and formatting (format_owner,
  format_state) helpers
- --debug now logs each eBPF program's load/attach outcome by name (uprobes,
  kprobes, tracepoints, and LSM hooks) instead of leaving success silent and
  failure to surface only as a generic top-level error; attach failures are
  always logged, not just under --debug
- standardized json outputs to use json numbers instead of strings
- extracted json generators to standardize with tests instead of using debug
  formatting which can be error prone

## v1.0.17

- updated to aya v0.14, switching execve/readline/zlentry event delivery from
  per-CPU perf arrays to ring buffers
- reduced allocations and blocking I/O in the periodic cpu/network/gpu/io/
  memory/fault monitors, and cached the network interface list instead of
  re-querying it per PID
- switched --cpu from an always-on sched_switch eBPF probe to procfs
  polling, fixing PID-reuse and map-exhaustion bugs in the old
  implementation; added a system-wide CPU% summary alongside the existing
  per-PID reporting

## v1.0.16

- added process blocking. Control how blocking is done using the comm-deny,
  comm-allow, syscalls, and block-paths options.

## v1.0.15

- reduced resource allocation to reduce memory footprint.

## v1.0.14

- added io usage monitoring, displaying disk reads/writes and inode creation.
  Can be filtered by PIDs using --pid-list. The poll interval can be
  adjusted using --poll.

## v1.0.13

- added gpu usage monitoring, displaying metrics like VRAM utilization. Can be
  filtered by PIDs using --pid-list. The poll interval can be adjusted using
  --poll.

## v1.0.12

- added network usage monitoring, displaying connection counts and socket
  states. Can be filtered by PIDs using --pid-list. The poll interval can be
  adjusted using --poll.

## v1.0.11

- added memory usage monitoring, displaying RSS per PID. Can be filtered by
  PIDs using --pid-list. The poll interval can be adjusted using --poll.

## v1.0.10

- added cpu usage monitoring, displaying utilization. Can be filtered by PIDs
  using --pid-list. The poll interval can be adjusted using --poll.

## v1.0.9

- added monitoring for sockets and memory paging

## v1.0.8

- changed how the output subcommand is read in from the provided config file
  to support current Ansible YAML syntax

## v1.0.7

- bugfix for the quiet option

## v1.0.6

- added a `--quiet` option to not output to the terminal logger

## v1.0.5

- added a config file option and updated associated files (manpage, systemd
  service)

## v1.0.4

- added an output subcommand for consolidating outputs
- fixed the file output always creating a new file
- added hostname to the message field
- updated README

## v1.0.3

- added a syslog output
