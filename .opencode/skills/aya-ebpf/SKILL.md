---
name: aya-ebpf
description: Use when working with Aya library for eBPF development in Rust. Covers latest Aya library features from GitHub, eBPF program development, map types, and HPC monitoring patterns for the panhandle project.
license: MIT
---

# Aya eBPF Development Skill for Panhandle

## When to Use
Use this skill when:
- Developing eBPF programs with the Aya library
- Working on panhandle's user activity monitoring features
- Implementing kernel-level monitoring in Rust
- Using Aya library APIs and features
- Debugging eBPF programs and verifier issues

## Aya Library Expertise

### Core Concepts
- **Program Types**: XDP, TC, socket filters, tracepoints, kprobes, uprobes
- **Map Types**: HashMap, Array, ProgArray, PerCpuArray, RingBuf, Queue, Stack
- **BTF (BPF Type Format)**: CO-RE (Compile Once, Run Everywhere) support
- **Program Loading**: Attaching eBPF programs to kernel hooks
- **Map in Map**: Nested map structures for complex data

### Latest from GitHub (aya-rs/aya)
- Monitor latest commits to main branch for new features
- Track breaking changes and migration guides
- Follow community RFCs and discussions
- Check for performance improvements and optimizations

## Panhandle-Specific Patterns

### User Activity Monitoring
- Process execution monitoring (execve, execveat)
- System call tracing for HPC environments
- Network activity tracking with minimal overhead
- File access pattern analysis
- Resource utilization metrics collection

### eBPF Program Safety
- Verifier compliance for production HPC environments
- Memory safety in kernel context
- Loop bounds and termination proofs
- Register state tracking
- Stack usage limits

### Performance Optimization
- Minimal overhead eBPF program design
- Efficient map usage and data structures
- Batch processing techniques
- Kernel to userspace communication optimization

## Development Workflow

### Program Development
1. Define eBPF program structure in Rust with `#[map]` and `#[program]` macros
2. Implement program logic with safety checks
3. Use `Btf::from_kernel()` for CO-RE support
4. Load and attach programs using `Bpf::load()` and appropriate attach methods

### Testing and Debugging
- Use `cargo xtask` for building and testing
- Check verifier logs with `RUST_LOG=debug`
- Use `bpftrace` or `bpftool` for debugging
- Monitor with `perf` for performance analysis

## Common Patterns in Panhandle

### Event Monitoring
```rust
// Example: Monitor process execution
#[tracepoint]
fn trace_execve(ctx: TracepointContext) -> i32 {
    // Extract process information
    // Format and send to userspace
    0
}
```

### Data Collection
- Use `RingBuf` for efficient kernel-to-userspace data transfer
- Implement per-CPU maps for lock-free access
- Use `PerfBuffer` for high-performance event streaming

### Error Handling
- Check return values from all eBPF operations
- Handle map lookup errors gracefully
- Validate all pointer accesses
- Ensure proper error propagation to userspace

## Resources

### Primary References
- [Aya GitHub Repository](https://github.com/aya-rs/aya)
- [Aya Documentation](https://aya-rs.dev/)
- [Linux eBPF Documentation](https://www.kernel.org/doc/html/latest/bpf/)
- [Panhandle Project](../README.md)

### Community
- Aya Discord/Slack channels
- GitHub discussions and issues
- Rust eBPF working group

## Safety Reminders
- Always test eBPF programs on non-production systems first
- Verify all memory accesses are within bounds
- Check for potential infinite loops
- Validate all external inputs
- Monitor kernel logs for verifier errors
