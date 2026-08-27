# CHANGELOG

### v1.0.21

- fixed the --bash option for newer cpus

### v1.0.20

- fixed a bug where `--executables` silently discarded every event queued behind the first non-matching one in a ring buffer batch, so matching events were dropped without any indication; each non-matching event is now skipped individually
- added test coverage for the `--executables` filter, including the batch-skipping regression

### v1.0.19

- added ci for arm and sles to the GitHub ci

### v1.0.18

- fixed a bug where the first CPU% sample after starting --cpu could spike (or clamp to 100%) because there was no prior sample yet to compare against
- fixed a bug where the system-wide CPU% baseline could be poisoned by a transient /proc/stat read failure, causing an inflated delta on the next successful sample
- fixed the --cpu per-PID tracking to drop stale PIDs from its internal maps each poll, closing a memory-growth leak
- fixed a bug where providing both --comm-deny and --comm-allow silently used the deny list instead of erroring as intended
- removed a redundant procfs read per PID in --cpu by reusing the already-open process handle instead of looking up the process a second time
- fixed a bug where the documented --block-paths/--comm-allow/--comm-deny maximums (64 entries) were never actually enforced for the documented comma-separated usage, since clap's per-flag argument limit doesn't apply to values split out of a single delimited argument; these are now checked explicitly at startup like the existing --executables/--include-uid limits
- added test coverage for CLI argument parsing (including the process-blocking list options and their length/count limits), the default-monitor fallback logic, config-file/CLI argument merging, network interface resolution, and CPU accounting
- --verbose now also reports each process's owner (UID and resolved username) and current state (running/sleeping/etc) alongside the existing PPID/Parent_Comm, across the --cpu, --gpu, --io, --socket, --memory, and --memory-faults reports; username resolution is cached per poll to avoid repeat NSS/LDAP lookups for processes sharing a UID
- added test coverage for the new owner/state resolution (get_process_uid, resolve_username) and formatting (format_owner, format_state) helpers
- --debug now logs each eBPF program's load/attach outcome by name (uprobes, kprobes, tracepoints, and LSM hooks) instead of leaving success silent and failure to surface only as a generic top-level error; attach failures are always logged, not just under --debug
- standardized json outputs to use json numbers instead of strings
- extracted json generators to standardize with tests instead of using debug formatting which can be error prone

### v1.0.17

- updated to aya v0.14, switching execve/readline/zlentry event delivery from per-CPU perf arrays to ring buffers
- reduced allocations and blocking I/O in the periodic cpu/network/gpu/io/memory/fault monitors, and cached the network interface list instead of re-querying it per PID
- switched --cpu from an always-on sched_switch eBPF probe to procfs polling, fixing PID-reuse and map-exhaustion bugs in the old implementation; added a system-wide CPU% summary alongside the existing per-PID reporting

### v1.0.16

- added process blocking. Control how blocking is done using the comm-deny, comm-allow, syscalls, and block-paths options.

### v1.0.15

- reduced resource allocation to reduce memory footprint.

### v1.0.14

- added io usage monitoring, displaying disk reads/writes and inode creation. Can be filtered by PIDs using --pid-list. The poll interval can be adjusted using --poll.

### v1.0.13

- added gpu usage monitoring, displaying metrics like VRAM utilization. Can be filtered by PIDs using --pid-list. The poll interval can be adjusted using --poll.

### v1.0.12

- added network usage monitoring, displaying connection counts and socket states. Can be filtered by PIDs using --pid-list. The poll interval can be adjusted using --poll.

### v1.0.11

- added memory usage monitoring, displaying RSS per PID. Can be filtered by PIDs using --pid-list. The poll interval can be adjusted using --poll.

### v1.0.10

- added cpu usage monitoring, displaying utilization. Can be filtered by PIDs using --pid-list. The poll interval can be adjusted using --poll.

### v1.0.9

- added monitoring for sockets and memory paging

### v1.0.8

- changed how the output subcommand is read in from the provided config file to support current Ansible YAML syntax
 
### v1.0.7

- bugfix for the quiet option

### v1.0.6

- added a `--quiet` option to not output to the terminal logger

### v1.0.5

- added a config file option and updated associated files (manpage, systemd service)

### v1.0.4

- added an output subcommand for consolidating outputs
- fixed the file output always creating a new file
- added hostname to the message field
- updated README

### v1.0.3

- added a syslog output
