---
name: rust-ebpf
description: Use when developing Rust code with eBPF-specific patterns for the panhandle project. Covers unsafe Rust, FFI, memory safety, and eBPF-specific optimizations.
license: MIT
---

# Rust eBPF Development Skill for Panhandle

## When to Use
Use this skill when:
- Writing Rust code that interacts with eBPF
- Handling unsafe Rust in eBPF context
- Working with FFI between Rust and C
- Optimizing Rust code for eBPF programs
- Debugging memory safety issues in eBPF

## Rust for eBPF

### Unsafe Rust Patterns
- **Pointer Arithmetic**: Only use with bounds checking
- **Memory Access**: Validate all pointer dereferences
- **Slice Operations**: Ensure indices are within bounds
- **Type Punning**: Use `std::mem::transmute` carefully

### FFI Considerations
- **ABI Compatibility**: Ensure C-compatible types
- **String Handling**: Use CString for C interop
- **Error Handling**: Map C error codes to Rust Result
- **Lifetime Management**: Be careful with borrowed references

## Panhandle-Specific Rust Patterns

### Updated Project Structure
```
panhandle/                              # Workspace root
├── Cargo.toml                          # Workspace manifest
├── panhandle/                          # Main application crate
│   ├── Cargo.toml                      # Application manifest
│   ├── src/                            # Userspace main entry
│   │   ├── main.rs                     # Main entry point
│   │   ├── helpers.rs                  # Event processing
│   │   ├── monitor_*.rs                # Monitoring modules
│   │   └── input_configs.rs           # CLI parsing
│   └── build.rs                        # Build script
├── panhandle-common/                   # Shared definitions
│   └── src/lib.rs                      # Common types
└── panhandle-ebpf/                     # eBPF programs
    └── src/                            # eBPF source files
        ├── main.rs
        ├── readline.rs               # Shell monitoring
        ├── socket.rs                 # Network monitoring
        └── zlentry.rs                # Zsh monitoring
```

**Note**: This is a Cargo workspace with three crates: main application, common types, and eBPF programs.

### Build Configuration
- Use `cargo` with appropriate features
- Configure BTF generation for CO-RE
- Set up cross-compilation for different kernel versions
- Manage dependencies with Cargo.toml

### Error Handling
- Use `thiserror` or `anyhow` for error types
- Implement proper error propagation
- Handle eBPF-specific errors (verifier, loader, etc.)
- Provide meaningful error messages

### Generic Event Processing Patterns
For unified handling of different eBPF event types (from the panhandle merge resolution):

```rust
// Define a common trait for all event types
pub trait EbpfEvent: Sized + std::fmt::Debug + std::fmt::Display {
    fn get_filter_key(&self) -> &str;
    fn get_command(&self) -> &str;
    fn get_filename(&self) -> Option<&str>;
    fn get_args(&self) -> String;
    fn get_uid(&self) -> u32;
    fn get_pid(&self) -> u32;
    fn get_tgid(&self) -> u32;
    fn get_gid(&self) -> u32;
}

// Implement for Readline
hash[derive(Clone, Copy, Debug)]
pub struct Readline {
    /* fields */
}

impl EbpfEvent for Readline {
    fn get_filter_key(&self) -> &str {
        // Extract from self.command
    }
    // ... implement other methods
}

// Generic event processor
pub fn consume_ebpf_map<T: EbpfEvent + Copy>(
    client: &Client,
    buf: PerfEventArrayBuffer<aya::maps::MapData>,
    process_event: impl Fn(&T) + Copy,
) {
    buf.for_each(|event| {
        // Generic processing logic
    });
}

// Type-specific processors
fn process_readline(data: &Readline) { /* ... */ }
fn process_execve(data: &ExecveEvent) { /* ... */ }
```

**Best Practice**: Implement `Debug` trait on all event structs to enable compatibility with generic code.

## Common Rust Patterns in eBPF

### Safe Abstractions
- Wrap unsafe eBPF operations in safe Rust APIs
- Use newtypes for type safety
- Implement builder pattern for complex operations
- Use Result for error handling

### Memory Management
- Use `Box` for heap allocation in userspace
- Be careful with stack usage in eBPF programs
- Manage lifetimes explicitly
- Avoid memory leaks in long-running processes

### Concurrency
- Use `Arc<Mutex<T>>` for thread-safe shared state
- Implement lock-free data structures where possible
- Be careful with eBPF map concurrency
- Use per-CPU maps for lock-free access

## Performance Optimization

### Rust-Specific Optimizations
- Use `#[inline]` for hot functions
- Avoid unnecessary allocations
- Use `Copy` types where possible
- Optimize iterator chains

### eBPF-Specific Optimizations
- Minimize map lookups in hot paths
- Use batch processing where possible
- Avoid expensive operations in eBPF context
- Optimize for cache locality

## Debugging and Testing

### Debugging Techniques
- Use `println!` for userspace debugging
- Use `trace_print!` macro for eBPF debugging (if available)
- Check kernel logs with `dmesg`
- Use `perf` for performance profiling

### Testing Strategies
- Unit tests for userspace logic
- Integration tests for eBPF programs
- End-to-end tests for monitoring functionality
- Performance benchmarks

## Safety Checklist

### Before Committing Code
- [ ] All unsafe blocks have safety comments
- [ ] All pointer accesses are validated
- [ ] All array indices are bounds-checked
- [ ] All map lookups handle errors
- [ ] All FFI boundaries are safe
- [ ] All eBPF programs pass verifier
- [ ] All tests pass
- [ ] No memory leaks detected

### Code Review Focus
- Memory safety in unsafe code
- Proper error handling
- Performance implications
- Kernel compatibility
- Security considerations

## Resources

### Rust Documentation
- [Rust Book](https://doc.rust-lang.org/book/)
- [Rust by Example](https://doc.rust-lang.org/rust-by-example/)
- [Rust Standard Library](https://doc.rust-lang.org/std/)

### eBPF Resources
- [Aya Documentation](https://aya-rs.dev/)
- [libbpf-rs](https://github.com/libbpf/libbpf-rs)
- [Rust eBPF Working Group](https://github.com/rust-lang/wg-ebpf)

### Panhandle Specific
- [Panhandle README](../README.md)
- [Panhandle Architecture](docs/architecture.md)
