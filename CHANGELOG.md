# CHANGELOG

## v1.0.25

- **Fixed: `--syscalls open/openat/creat` failed to load on newer kernels**
  (roughly 6.12+, including RHEL 10). `block_open` reached `f_path` at an
  offset compiled in from a bundled `vmlinux.rs`, but `struct file`'s layout
  differs between kernels. The offset is now read from the running kernel's
  BTF at startup and injected as a load-time global; `vmlinux.rs` is gone.
- **Fixed: listing more than one of `open`/`openat`/`creat` exited at
  startup** - they share one program, which was loaded once per name.
- A panic in one monitor no longer silently kills the whole daemon
  (workspace `panic = "abort"` removed; the non-debug panic hook now logs).
- Attach failures now name the failing eBPF program in the log.
- `--socket` documented as needing kernel 5.17+ (`bpf_get_func_ret`).
- Dropped RHEL 8 (4.18 kernel) builds.
- **Fixed: `--bound`'s `NET_WAIT` accumulator had the same cross-CPU
  lost-update race `socket.rs` was already redesigned around** - two threads
  of the same process finishing a network wait on different CPUs at the same
  time could race and lose an update. Fixed the same way: eBPF streams a
  `NetWaitEvent` delta per completed wait over a new `net_wait_events` ring
  buffer, and `monitor_process_bounds.rs` accumulates them in its own
  userspace-owned map instead.
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
- **`--bound`/`--socket`'s kprobes replaced with fentry/fexit** (aya 0.16
  exposes `FEntry`/`FExit` program types): `tcp_recvmsg`/`udp_recvmsg` (wait
  timing), `tcp_sendmsg`/`tcp_cleanup_rbuf`/`udp_sendmsg`/`udp_recvmsg` (byte
  counting). fentry/fexit attach via a BTF trampoline instead of a kprobe's
  breakpoint trap, at near-zero overhead per call - worth it here since these
  all run on every socket read/write.
- Implemented Aya 0.16 improvements:
  - Added test module in
    `panhandle-ebpf/src/main.rs` with `#[test]` functions for eBPF program
    logic.
  - Added `VERIFIER_LOG_LEVEL = DEBUG` in debug mode for
    easier eBPF verifier debugging.
  - UID filtering for the execve/readline/zlentry programs stays on the
    original runtime-configurable `uid_options`/`uid_include_list` maps
    rather than load-time-only `GlobalData`, so those filters can still be
    changed without reloading the eBPF program.
- `--bound` opened a fresh netlink socket per process, per
  poll cycle. `linux_taskstats::Client::open()` does a full generic-netlink
  round trip to resolve the taskstats family id; it's now opened once per
  cycle and reused across every process instead.
- parent-process-name lookups weren't cached under
  `--verbose` for `memory`/`memory-faults`/`io`/`network`/`gpu` (many
  processes commonly share one parent - a shell, container init, etc.) -
  `cpu` already cached this; the same per-poll cache is now applied
  consistently.
- JSON now built with `serde_json::json!` instead of
  hand-templated `format!`, and uid/pid/gid/tgid serialize as JSON numbers
  instead of quoted strings, matching every other event type in this
  codebase.

## v1.0.24

- Added process bound reporting. Receive a report of what processes are bound by
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
