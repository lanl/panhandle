# Panhandle Project - Comprehensive Task List and Implementation Steps

## Overview

This document provides a detailed, actionable task list with specific implementation steps derived from the comprehensive review in `REVIEW.md`. Each task is categorized by priority, includes estimated effort, and provides step-by-step implementation guidance.

**Last Updated**: June 16, 2026
**Total Tasks**: 150+
**Estimated Total Effort**: 400+ hours

---

## Task Categories and Priorities

- 🔴 **Critical** - Must fix immediately (security, crashes, data loss)
- 🟡 **High** - Should fix in next release (major functionality, performance)
- 🟢 **Medium** - Important improvements (code quality, documentation)
- 🔵 **Low** - Nice to have (enhancements, minor improvements)

---

## Table of Contents

1. [Critical Security and Stability Tasks](#1-critical-security-and-stability-tasks)
2. [High Priority Code Quality Tasks](#2-high-priority-code-quality-tasks)
3. [Testing and Quality Assurance Tasks](#3-testing-and-quality-assurance-tasks)
4. [Documentation Tasks](#4-documentation-tasks)
5. [Performance Optimization Tasks](#5-performance-optimization-tasks)
6. [eBPF-Specific Tasks](#6-ebpf-specific-tasks)
7. [Configuration and Deployment Tasks](#7-configuration-and-deployment-tasks)
8. [Project Infrastructure Tasks](#8-project-infrastructure-tasks)
9. [User Experience Tasks](#9-user-experience-tasks)
10. [Refactoring Tasks](#10-refactoring-tasks)

---

## 1. Critical Security and Stability Tasks 🔴

### 1.1 Security Vulnerabilities

#### Task 1.1.1: Add Opt-in HTTPS/TLS Support for HTTP Output
**Priority**: 🔴 Critical
**Effort**: 8-12 hours
**Dependencies**: None
**Files Affected**: `panhandle/src/helpers.rs`, `panhandle/src/input_configs.rs`, `Cargo.toml`

**Implementation Steps**:
1. Add `reqwest` feature for HTTPS: `reqwest = { version = "0.13.1", features = ["json", "rustls-tls"] }`
2. Add CLI argument `--https` (default: false) to explicitly enable HTTPS mode
3. Add configuration option `https: false` (default) in config files
4. Modify `send_http_post` function in helpers.rs to:
   - Accept a boolean flag for HTTPS (defaults to false for HTTP)
   - Validate URLs start with `http://` or `https://`
   - Default to HTTP when no protocol is specified or when --https is not used
   - Enable certificate validation by default when HTTPS is explicitly enabled
   - Handle TLS errors appropriately
5. Update `validate_url` function to accept both HTTP and HTTPS URLs
6. Update `RawArgs` struct in input_configs.rs to include `https: bool` field with default false
7. Add tests for both HTTP (default) and HTTPS (opt-in) functionality
8. Document HTTPS as opt-in feature in README, with HTTP as the default

**Code Changes**:
```rust
// In input_configs.rs, add to RawArgs:
#[arg(long, global = true)]
#[serde(default)]
pub https: bool,  // Default false - HTTP is the default

// In helpers.rs
pub async fn send_http_post(
    client: &Client,
    url: &Arc<String>,
    arc_string: &Arc<String>,
    json: &bool,
    debug: &bool,
    use_https: bool,  // NEW - defaults to false (HTTP)
) -> Result<(), Error> {
    let mut client_builder = Client::builder();
    
    // Only enable HTTPS features if explicitly requested
    if use_https {
        client_builder = client_builder.use_rustls_tls();
    }
    
    let client = client_builder.build()?;
    // ... rest of function using the client
}
```

**Validation**:
- Test with HTTP endpoints (default behavior, no --https flag)
- Test with HTTPS endpoints when --https flag is explicitly used
- Verify certificate validation works for HTTPS connections
- Test that HTTP remains the default when no flag is specified
- Test with self-signed certificates (when validation is disabled via separate flag)

---

#### Task 1.1.2: Fix Memory Safety Issues in eBPF Code
**Priority**: 🔴 Critical
**Effort**: 16-24 hours
**Dependencies**: None
**Files Affected**: All eBPF source files

**Implementation Steps**:
1. Audit all unsafe blocks in eBPF code:
   - `panhandle-ebpf/src/main.rs`
   - `panhandle-ebpf/src/cpu_usage.rs`
   - `panhandle-ebpf/src/socket.rs`
   - `panhandle-ebpf/src/readline.rs`
   - `panhandle-ebpf/src/zlentry.rs`
2. For each unsafe block:
   - Verify bounds checking is adequate
   - Add comprehensive safety comments explaining why it's safe
   - Consider using safe abstractions where possible
3. Focus on critical areas:
   - Pointer dereferencing (lines 41-44 in main.rs)
   - Map access (lines 86-88 in main.rs)
   - Context casting (lines 37-38 in cpu_usage.rs)
   - Argument access (lines 46-48 in socket.rs)
4. Use `bpf_probe_read_user` with proper size checking
5. Validate all map accesses with bounds checking
6. Add static analysis with `cargo clippy` for eBPF code

**Validation**:
- Run eBPF verifier on all programs
- Test with various input sizes
- Verify no kernel crashes or memory corruption

---

#### Task 1.1.3: Address Integer Overflow Potential
**Priority**: 🔴 Critical
**Effort**: 8-12 hours
**Dependencies**: None
**Files Affected**: `panhandle/src/monitor_cpu_usage.rs`, `panhandle-ebpf/src/cpu_usage.rs`

**Implementation Steps**:
1. Identify all integer arithmetic operations that could overflow:
   - CPU time calculations (lines 54-55, 84-85 in cpu_usage.rs)
   - Delta calculations (lines 78, 86 in monitor_cpu_usage.rs)
   - Map value accumulations
2. Replace with checked arithmetic:
   - Use `checked_sub()`, `checked_add()`, `saturating_sub()`
   - Add overflow checks with meaningful error handling
3. For performance-critical paths, use saturating arithmetic where appropriate
4. Add compile-time assertions for size limits
5. Update comments to explain overflow protection

**Code Changes**:
```rust
// In cpu_usage.rs
let delta = now.checked_sub(prev_start).ok_or_else(|| {
    info!(&ctx, "Time delta overflow detected");
    1i64
})?;

// In monitor_cpu_usage.rs
let busy_delta = total_busy.saturating_sub(last_total_busy);
let delta = cpu_time.checked_sub(last_time).unwrap_or(0);
```

**Validation**:
- Test with large values that would cause overflow
- Verify proper error handling
- Check performance impact of checked arithmetic

---

#### Task 1.1.4: Fix TOCTOU Issues in procfs Access
**Priority**: 🔴 Critical
**Effort**: 8-12 hours
**Dependencies**: None
**Files Affected**: `panhandle/src/procfs_helpers.rs`

**Implementation Steps**:
1. Identify TOCTOU vulnerabilities:
   - Lines 56-59: Process may exit between `all_processes()` and `stat()`
   - Lines 118-120: Process may exit between `stat()` and `statm()`
2. Implement retry logic with exponential backoff:
   - Add maximum retry count (e.g., 3 retries)
   - Add delay between retries (increasing exponentially)
   - Log warnings for failed processes
3. Consider alternative approaches:
   - Use `procfs::process::Process::stat_once()` for atomic reads
   - Implement process state caching
4. Add proper error handling for missing processes

**Code Changes**:
```rust
// In procfs_helpers.rs
fn get_process_stat_with_retry(pid: i32, max_retries: u32) -> Option<Stat> {
    let mut retries = 0;
    loop {
        match Process::new(pid) {
            Ok(proc) => {
                if let Ok(stat) = proc.stat() {
                    return Some(stat);
                }
            }
            Err(_) => {}
        }
        
        retries += 1;
        if retries >= max_retries {
            return None;
        }
        
        tokio::time::sleep(Duration::from_millis(10 * 2u64.pow(retries))).await;
    }
}
```

**Validation**:
- Test with rapidly exiting processes
- Verify retry logic works correctly
- Check performance impact

---

#### Task 1.1.5: Implement Proper Resource Cleanup on Errors
**Priority**: 🔴 Critical
**Effort**: 8-12 hours
**Dependencies**: None
**Files Affected**: `panhandle/src/main.rs`, all monitoring modules

**Implementation Steps**:
1. Audit all error paths for resource leaks:
   - eBPF program detachments
   - File handles
   - Network connections
   - Memory allocations
2. Implement RAII for resource management:
   - Create structs that implement Drop trait for cleanup
   - Use scoping to ensure cleanup
3. Add cleanup handlers for Ctrl-C and other signals
4. Ensure all monitoring tasks are properly aborted
5. Add cleanup logging for debugging

**Code Changes**:
```rust
// In main.rs
struct EbpfResources {
    programs: Vec<Box<dyn Program>>,
    maps: Vec<Box<dyn Map>>,
}

impl Drop for EbpfResources {
    fn drop(&mut self) {
        for program in &mut self.programs {
            if let Err(e) = program.detach() {
                error!("Failed to detach program: {}", e);
            }
        }
    }
}

// Usage in main():
let ebpf_resources = EbpfResources { ... };
// Resources will be cleaned up automatically when ebpf_resources goes out of scope
```

**Validation**:
- Test with Ctrl-C during various operations
- Verify all resources are cleaned up
- Check for memory leaks with valgrind or similar

---

### 1.2 Error Handling Improvements

#### Task 1.2.1: Replace unwrap() Calls with Proper Error Handling
**Priority**: 🔴 Critical
**Effort**: 24-32 hours
**Dependencies**: None
**Files Affected**: All source files (especially main.rs, helpers.rs, input_configs.rs)

**Implementation Steps**:
1. Use `grep` to find all `unwrap()` and `expect()` calls:
   ```bash
   grep -rn "\.unwrap()" panhandle/src/
   grep -rn "\.expect(" panhandle/src/
   ```
2. Categorize calls by context:
   - Configuration loading (can propagate errors)
   - Runtime operations (may need different handling)
   - eBPF operations (critical, need careful handling)
3. Replace with appropriate error handling:
   - Use `?` operator for propagatable errors
   - Use `match` for context-specific handling
   - Use `if let` for optional operations
4. Define custom error types for better error categorization
5. Add meaningful error messages

**Priority Order for Replacement**:
1. Configuration loading (input_configs.rs)
2. eBPF program loading (main.rs:199-202)
3. Map access operations
4. Process creation and access
5. Network operations

**Code Changes**:
```rust
// Before:
let config_args = load_config_args(config).await.unwrap();

// After:
let config_args = load_config_args(config).await
    .map_err(|e| {
        error!("Failed to load configuration: {}", e);
        process::exit(1);
    })?;
```

**Validation**:
- Verify all error paths are handled
- Test with invalid inputs
- Check error messages are helpful

---

#### Task 1.2.2: Implement Consistent Panic Handling
**Priority**: 🔴 Critical
**Effort**: 4-8 hours
**Dependencies**: Task 1.2.1
**Files Affected**: `panhandle/src/main.rs`

**Implementation Steps**:
1. Review current panic hook (lines 64-66 in main.rs)
2. Enhance panic hook to:
   - Log panic information
   - Clean up resources
   - Exit with appropriate error code
3. Consider using `catch_unwind` for critical sections
4. Add panic logging for debugging
5. Document panic handling behavior

**Code Changes**:
```rust
// Enhanced panic hook
panic::set_hook(Box::new(|panic_info| {
    error!("Panic occurred: {:?}", panic_info);
    
    // Attempt cleanup
    if let Some(args) = panic_info.payload().downcast_ref::<&dyn std::any::Any>() {
        // Custom cleanup logic
    }
    
    // Log location if available
    if let Some(location) = panic_info.location() {
        error!("Panic location: {}", location);
    }
    
    process::exit(1);
}));
```

**Validation**:
- Test with forced panics
- Verify cleanup happens
- Check error logs

---

## 2. High Priority Code Quality Tasks 🟡

### 2.1 Code Duplication Elimination

#### Task 2.1.1: Refactor consume_shell_ebpf_map and consume_execve_ebpf_map
**Priority**: 🟡 High
**Effort**: 16-24 hours
**Dependencies**: None
**Files Affected**: `panhandle/src/helpers.rs`

**Implementation Steps**:
1. Analyze both functions to identify common patterns:
   - Event reading loop
   - Pointer dereferencing
   - Command/filename processing
   - Executable filtering
   - User lookup
   - Timestamp generation
   - Output formatting (JSON/text)
   - HTTP/syslog/file output
2. Create a generic function using traits:
   ```rust
   pub async fn consume_ebpf_map<T: EbpfEvent + Display + Debug + Serialize>(
       client: &Client,
       mut buf: AsyncPerfEventArrayBuffer<aya::maps::MapData>,
       mut buffers: Vec<BytesMut>,
       ref_executable_vec: Vec<String>,
       global_url: Arc<String>,
       http: bool,
       syslog_address: Arc<String>,
       hostname: Arc<String>,
       syslog: bool,
       json: bool,
       debug: bool,
       event_processor: impl Fn(&T) -> ProcessedEvent,
   ) { ... }
   ```
3. Define trait for event types:
   ```rust
   pub trait EbpfEvent: Sized {
       fn from_buffer(buf: &[u8]) -> &Self;
       fn get_command(&self) -> &[u8; 16];
       fn get_filename(&self) -> Option<&[u8; LEN_MAX_PATH]>;
       fn get_uid(&self) -> u32;
       fn get_pid(&self) -> u32;
       fn get_gid(&self) -> u32;
       fn get_tgid(&self) -> u32;
       fn get_timestamp(&self) -> u64;
   }
   ```
4. Implement trait for ExecveEvent and Readline
5. Create event-specific processors for differences
6. Update call sites to use the generic function
7. Test thoroughly to ensure no regression

**Validation**:
- Verify both shell and execve monitoring still work
- Check all output formats (JSON, text, HTTP, syslog, file)
- Test with various configurations

---

#### Task 2.1.2: Eliminate Magic Numbers
**Priority**: 🟡 High
**Effort**: 8-12 hours
**Dependencies**: None
**Files Affected**: All source files

**Implementation Steps**:
1. Identify all magic numbers using grep:
   ```bash
   grep -rn "[0-9]+" panhandle/src/ | grep -v "// " | grep -v version
   ```
2. Categorize by type:
   - Buffer sizes
   - Timeouts
   - Map sizes
   - Array dimensions
   - Polling intervals
   - Port numbers
3. Define constants in appropriate locations:
   - panhandle-common/src/lib.rs for shared constants
   - Module-level constants for module-specific values
4. Replace magic numbers with named constants
5. Document constant purposes

**Constants to Add**:
```rust
// In panhandle-common/src/lib.rs
pub const DEFAULT_BUFFER_CAPACITY: usize = 2048;
pub const HTTP_TIMEOUT_MS: u64 = 200;
pub const MAX_RETRIES: u32 = 3;
pub const DEFAULT_POLL_INTERVAL_SECS: u32 = 30;
pub const MAX_PROCESS_NAME_LENGTH: usize = 16;
pub const MAX_FILENAME_LENGTH: usize = 1024;

// In monitoring modules
pub const CPU_MAP_MAX_ENTRIES: u32 = 1024;
pub const NET_STATS_MAP_MAX_ENTRIES: u32 = 1024;
```

**Validation**:
- Verify all magic numbers are replaced
- Check that constants are used consistently
- Ensure no performance impact

---

#### Task 2.1.3: Improve Type Safety
**Priority**: 🟡 High
**Effort**: 12-16 hours
**Dependencies**: None
**Files Affected**: All source files

**Implementation Steps**:
1. Replace primitive types with newtypes where appropriate:
   - UID, PID, GID as newtypes
   - Timestamp as newtype
   - Map keys as newtypes
2. Add validation to newtypes:
   ```rust
   #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
   pub struct Uid(u32);
   
   impl Uid {
       pub fn new(value: u32) -> Option<Self> {
           if value <= MAX_POSSIBLE_UID {
               Some(Self(value))
           } else {
               None
           }
       }
       
       pub fn get(&self) -> u32 {
           self.0
       }
   }
   ```
3. Add From/Into traits for compatibility
4. Update function signatures to use newtypes
5. Add type aliases for clarity:
   ```rust
   pub type ProcessId = u32;
   pub type ThreadId = u32;
   pub type UserId = u32;
   pub type GroupId = u32;
   ```

**Validation**:
- Verify type safety is improved
- Check that no implicit conversions are missed
- Ensure backward compatibility where needed

---

### 2.2 Unused Code Cleanup

#### Task 2.2.1: Remove Unused Imports and Code
**Priority**: 🟡 High
**Effort**: 4-8 hours
**Dependencies**: None
**Files Affected**: All source files

**Implementation Steps**:
1. Run `cargo clippy -- -D warnings` to find unused items
2. Review each warning and either:
   - Remove the unused item
   - Add `#[allow(unused)]` with justification
3. Focus on:
   - Unused imports
   - Unused functions
   - Unused struct fields
   - Unused constants
4. Remove commented-out code:
   - main.rs:9 `// use aya_log::EbpfLogger;`
5. Remove unnecessary allow attributes:
   - vanilla_execve.rs:4 `#![allow(unused_imports)]`
6. Clean up allow attributes in eBPF files

**Validation**:
- Verify `cargo clippy` passes with no warnings
- Check that all necessary code is retained
- Ensure no functionality is broken

---

## 3. Testing and Quality Assurance Tasks 🟡

### 3.1 Comprehensive Testing

#### Task 3.1.1: Add Unit Tests for Monitoring Modules
**Priority**: 🟡 High
**Effort**: 32-40 hours
**Dependencies**: None
**Files Affected**: New test files in `panhandle/tests/`

**Implementation Steps**:
1. Create test directory structure:
   ```
   panhandle/tests/
   ├── test_helpers.rs
   ├── test_monitor_cpu.rs
   ├── test_monitor_network.rs
   ├── test_procfs_helpers.rs
   └── test_input_configs.rs
   ```
2. Add tests for helpers.rs:
   - Test `get_canonical_executable_list`
   - Test `validate_syslog`
   - Test `validate_url`
   - Test `output_message`
   - Test `send_http_post` (mock HTTP server)
   - Test `send_syslog` (mock syslog server)
3. Add tests for monitor_cpu_usage.rs:
   - Test CPU time calculations
   - Test statistics aggregation
   - Test output formatting
4. Add tests for monitor_network_usage.rs:
   - Test network stats processing
   - Test PID filtering
   - Test output formatting
5. Add tests for procfs_helpers.rs:
   - Test memory fault detection
   - Test memory usage calculation
6. Use mocking for external dependencies:
   - Mock HTTP server for output tests
   - Mock syslog server
   - Mock procfs for process tests

**Validation**:
- Run all tests with `cargo test`
- Verify test coverage > 80%
- Check for edge cases

---

#### Task 3.1.2: Add Integration Tests
**Priority**: 🟡 High
**Effort**: 24-32 hours
**Dependencies**: Task 3.1.1
**Files Affected**: `panhandle/tests/test_integration.rs`

**Implementation Steps**:
1. Create integration test file:
   ```rust
   // panhandle/tests/test_integration.rs
   #[test]
   fn test_execve_monitoring() {
       // Start panhandle with execve monitoring
       // Execute test commands
       // Verify events are captured
   }
   
   #[test]
   fn test_bash_monitoring() {
       // Start panhandle with bash monitoring
       // Execute bash commands
       // Verify events are captured
   }
   
   #[test]
   fn test_config_file_loading() {
       // Test loading various config files
       // Verify configuration is applied correctly
   }
   ```
2. Use test virtual machines for isolated testing:
   - Set up test VMs with different kernel versions
   - Test with various system configurations
3. Add end-to-end tests:
   - Test complete monitoring pipeline
   - Test output to file, syslog, HTTP
   - Test JSON and text output formats
4. Add error scenario tests:
   - Test with invalid configurations
   - Test with missing dependencies
   - Test with permission errors

**Validation**:
- Run integration tests in CI
- Verify tests pass on different platforms
- Check test coverage

---

#### Task 3.1.3: Add eBPF-Specific Tests
**Priority**: 🟡 High
**Effort**: 24-32 hours
**Dependencies**: None
**Files Affected**: `panhandle-ebpf/tests/` (new directory)

**Implementation Steps**:
1. Set up eBPF testing environment:
   - Use `aya-tool` for eBPF testing
   - Set up test kernel modules
2. Create eBPF test file:
   ```rust
   // panhandle-ebpf/tests/test_ebpf.rs
   #[test]
   fn test_panhandle_tracepoint() {
       // Load eBPF program
       // Trigger tracepoint
       // Verify event is captured
   }
   
   #[test]
   fn test_uid_filtering() {
       // Test UID filtering in eBPF
       // Verify events are filtered correctly
   }
   
   #[test]
   fn test_shell_filtering() {
       // Test shell command filtering
       // Verify only shell events are captured
   }
   ```
3. Test each eBPF program:
   - panhandle (execve tracepoint)
   - sched_switch (CPU monitoring)
   - inet_sock_set_state (network state)
   - tcp_sendmsg, tcp_cleanup_rbuf (TCP data)
   - udp_sendmsg, udp_recvmsg (UDP data)
   - readline (bash monitoring)
   - zlentry (zsh monitoring)
4. Test map operations:
   - Test map insert/lookup/update
   - Test map bounds checking
   - Test PerCpuArray operations
5. Use `bpftrace` for manual verification

**Validation**:
- Run eBPF tests with `cargo test`
- Verify programs load and run correctly
- Check eBPF verifier passes

---

#### Task 3.1.4: Add Performance Tests
**Priority**: 🟡 High
**Effort**: 16-24 hours
**Dependencies**: None
**Files Affected**: `panhandle/benches/` (new directory)

**Implementation Steps**:
1. Add criterion dependency to Cargo.toml:
   ```toml
   [dev-dependencies]
   criterion = "0.5"
   ```
2. Create benchmark file:
   ```rust
   // panhandle/benches/benchmark.rs
   use criterion::{black_box, criterion_group, criterion_main, Criterion};
   
   fn benchmark_event_processing(c: &mut Criterion) {
       let event = black_box(create_test_event());
       c.bench_function("process_execve_event", |b| {
           b.iter(|| process_event(&event))
       });
   }
   
   fn benchmark_string_formatting(c: &mut Criterion) {
       let event = black_box(create_test_event());
       c.bench_function("format_json_event", |b| {
           b.iter(|| format_event_json(&event))
       });
   }
   
   criterion_group!(benches, benchmark_event_processing, benchmark_string_formatting);
   criterion_main!(benches);
   ```
3. Add benchmarks for:
   - Event processing throughput
   - String formatting performance
   - JSON serialization
   - Map operations
   - Network I/O
4. Add stress tests:
   - High event rate scenarios
   - Large number of processes
   - Many concurrent connections
5. Document benchmark results

**Validation**:
- Run benchmarks with `cargo bench`
- Compare results across changes
- Establish performance baselines

---

#### Task 3.1.5: Add Security Testing
**Priority**: 🟡 High
**Effort**: 12-16 hours
**Dependencies**: None
**Files Affected**: `.github/workflows/security.yml` (new), `Cargo.toml`

**Implementation Steps**:
1. Add security audit to CI:
   ```yaml
   # .github/workflows/security.yml
   name: Security Audit
   on: [push, pull_request]
   jobs:
     audit:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
         - run: cargo audit
         - run: cargo clippy -- -D warnings
   ```
2. Add security lints:
   ```toml
   [lints.clippy]
   integer_overflow = "deny"
   unchecked_duration_subtraction = "deny"
   index_refutable_slice = "deny"
   ```
3. Run security-focused clippy:
   ```bash
   cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic -W clippy::nursery -W clippy::cargo
   ```
4. Add static analysis tools:
   - `cargo-geiger` for unsafe code detection
   - `cargo-udeps` for unused dependencies
5. Add dependency vulnerability scanning:
   - `cargo-audit` with database updates
   - GitHub Dependabot integration
6. Document security testing process

**Validation**:
- Run security audit in CI
- Fix all identified issues
- Verify no new vulnerabilities are introduced

---

### 3.2 Test Infrastructure Improvements

#### Task 3.2.1: Improve Test Organization
**Priority**: 🟡 High
**Effort**: 8-12 hours
**Dependencies**: None
**Files Affected**: `panhandle/src/unit_tests.rs`, `panhandle/tests/`

**Implementation Steps**:
1. Move unit tests from `src/unit_tests.rs` to `tests/` directory
2. Organize tests by module:
   ```
   panhandle/tests/
   ├── helpers/
   │   ├── mod.rs
   │   ├── test_output.rs
   │   ├── test_validation.rs
   │   └── test_network.rs
   ├── monitoring/
   │   ├── mod.rs
   │   ├── test_cpu.rs
   │   ├── test_network.rs
   │   └── test_memory.rs
   ├── config/
   │   ├── mod.rs
   │   ├── test_loading.rs
   │   └── test_merging.rs
   └── integration/
       ├── mod.rs
       ├── test_execve.rs
       ├── test_bash.rs
       └── test_zsh.rs
   ```
3. Update Cargo.toml to include all test files
4. Add test utilities module:
   ```rust
   // panhandle/tests/utils/mod.rs
   pub mod mocks;
   pub mod fixtures;
   pub mod helpers;
   ```
5. Add common test setup/teardown
6. Document test organization

**Validation**:
- Verify all tests still pass
- Check test discovery works correctly
- Ensure proper test isolation

---

#### Task 3.2.2: Add Test Coverage Analysis
**Priority**: 🟡 High
**Effort**: 4-8 hours
**Dependencies**: None
**Files Affected**: `.github/workflows/ci.yml`, `Cargo.toml`

**Implementation Steps**:
1. Add tarpaulin dependency:
   ```toml
   [dev-dependencies]
   tarpaulin = "0.20"
   ```
2. Add coverage job to CI:
   ```yaml
   coverage:
     runs-on: ubuntu-latest
     steps:
       - uses: actions/checkout@v4
       - run: cargo install cargo-tarpaulin
       - run: cargo tarpaulin --all-features --workspace --timeout 120
       - run: cargo tarpaulin --all-features --workspace --timeout 120 --out Xml
       - uses: codecov/codecov-action@v3
         with:
           file: ./coverage/cobertura.xml
   ```
3. Add coverage badges to README
4. Set minimum coverage threshold (e.g., 80%)
5. Document coverage requirements
6. Add coverage exclusion for generated code

**Validation**:
- Verify coverage reports are generated
- Check coverage meets minimum threshold
- Ensure coverage data is uploaded to codecov

---

## 4. Documentation Tasks 🟡

### 4.1 Code Documentation

#### Task 4.1.1: Add Comprehensive Doc Comments
**Priority**: 🟡 High
**Effort**: 24-32 hours
**Dependencies**: None
**Files Affected**: All source files

**Implementation Steps**:
1. Audit current documentation coverage:
   ```bash
   cargo doc --no-deps --open 2>&1 | grep -i warning
   ```
2. Add doc comments to all public items:
   - Modules
   - Structs
   - Enums
   - Functions
   - Methods
3. Follow Rustdoc conventions:
   - Use `///` for doc comments
   - First line is short summary
   - Detailed description on new lines
   - Use `# Examples` section
   - Use `# Panics`, `# Errors`, `# Safety` as needed
4. Add module-level documentation:
   ```rust
   //! This module provides helper functions for event processing and output.
   //!
   //! It includes functions for consuming eBPF events, formatting output,
   //! and sending data to various destinations (HTTP, syslog, file).
   ```
5. Add examples to doc comments:
   ```rust
   /// # Examples
   ///
   /// ```no_run
   /// use panhandle::helpers::validate_url;
   ///
   /// let result = validate_url("http://example.com").await;
   /// assert!(result.is_ok());
   /// ```
   ```
6. Add safety comments to all unsafe blocks:
   ```rust
   // SAFETY: This is safe because we verify the pointer is valid
   // and the memory is properly aligned before dereferencing.
   unsafe { ... }
   ```

**Validation**:
- Run `cargo doc` with no warnings
- Verify documentation is comprehensive
- Check that all public items are documented

---

#### Task 4.1.2: Generate and Publish API Documentation
**Priority**: 🟡 High
**Effort**: 4-8 hours
**Dependencies**: Task 4.1.1
**Files Affected**: `Cargo.toml`, GitHub Pages configuration

**Implementation Steps**:
1. Add rustdoc configuration to Cargo.toml:
   ```toml
   [package]
   # ...
   documentation = "https://docs.rs/panhandle"
   
   [package.metadata.docs.rs]
   features = ["all"]
   no-default-features = false
   ```
2. Set up GitHub Pages for documentation:
   - Create `gh-pages` branch
   - Set up GitHub Pages to serve from `gh-pages` branch
   - Add workflow to build and deploy docs:
     ```yaml
     name: Documentation
     on:
       push:
         branches: [main]
     jobs:
       docs:
         runs-on: ubuntu-latest
         steps:
           - uses: actions/checkout@v4
           - run: cargo doc --all-features --no-deps
           - run: echo "<meta http-equiv=refresh content=0;url=panhandle/index.html>" > target/doc/index.html
           - uses: peaceiris/actions-gh-pages@v3
             with:
               github_token: ${{ secrets.GITHUB_TOKEN }}
               publish_dir: ./target/doc
     ```
3. Add documentation badges to README
4. Add link to documentation in README
5. Document how to build documentation locally

**Validation**:
- Verify documentation builds successfully
- Check that documentation is accessible via GitHub Pages
- Ensure all modules are documented

---

### 4.2 Architecture Documentation

#### Task 4.2.1: Create ARCHITECTURE.md
**Priority**: 🟡 High
**Effort**: 8-12 hours
**Dependencies**: None
**Files Affected**: `ARCHITECTURE.md` (new)

**Implementation Steps**:
1. Create ARCHITECTURE.md file with structure:
   ```markdown
   # Panhandle Architecture
   
   ## Overview
   
   ## System Components
   
   ### User-Space Components
   - Main Application
   - Configuration Management
   - Event Processing
   - Output Handlers
   - Monitoring Modules
   
   ### eBPF Components
   - Tracepoints
   - Kprobes
   - Uprobes
   - Maps
   
   ### Data Flow
   
   ### Module Dependencies
   
   ## Design Decisions
   
   ## Performance Considerations
   
   ## Security Considerations
   
   ## Future Architecture
   ```
2. Document each component in detail:
   - Responsibilities
   - Interfaces
   - Data structures
   - Key algorithms
3. Add architecture diagrams (ASCII or Mermaid)
4. Document design decisions and trade-offs
5. Document performance characteristics
6. Document security considerations
7. Add future architecture plans

**Content Outline**:
- System overview and high-level architecture
- Component diagrams
- Data flow diagrams
- Sequence diagrams for key operations
- Design patterns used
- Rationale for key decisions

**Validation**:
- Review with team members
- Verify accuracy with code
- Ensure diagrams are clear and accurate

---

#### Task 4.2.2: Create DESIGN.md
**Priority**: 🟡 High
**Effort**: 8-12 hours
**Dependencies**: Task 4.2.1
**Files Affected**: `DESIGN.md` (new)

**Implementation Steps**:
1. Create DESIGN.md file with structure:
   ```markdown
   # Panhandle Design Document
   
   ## Problem Statement
   
   ## Requirements
   
   ## Design Goals
   
   ## System Design
   
   ### Monitoring Approach
   
   ### eBPF Program Design
   
   ### User-Space Design
   
   ### Configuration Design
   
   ### Output Design
   
   ## Data Structures
   
   ## Algorithms
   
   ## Error Handling Strategy
   
   ## Performance Optimization
   
   ## Security Design
   
   ## Extensibility
   
   ## Limitations
   
   ## Future Enhancements
   ```
2. Document design for each major component:
   - Monitoring approach (tracepoints vs kprobes vs uprobes)
   - eBPF program design (maps, programs, attachments)
   - User-space architecture (tokio, async, threads)
   - Configuration management (CLI, config files, merging)
   - Output system (modular design, multiple destinations)
3. Document data structures with examples
4. Document key algorithms with pseudocode
5. Document error handling strategy
6. Document performance optimization techniques
7. Document security design decisions

**Validation**:
- Review with team members
- Verify consistency with implementation
- Ensure completeness

---

### 4.3 User Documentation

#### Task 4.3.1: Create CONFIGURATION.md
**Priority**: 🟡 High
**Effort**: 8-12 hours
**Dependencies**: None
**Files Affected**: `CONFIGURATION.md` (new)

**Implementation Steps**:
1. Create CONFIGURATION.md file with structure:
   ```markdown
   # Panhandle Configuration Guide
   
   ## Configuration Overview
   
   ## Configuration Files
   
   ### YAML Configuration
   
   ### JSON Configuration
   
   ## Configuration Options
   
   ### Monitoring Options
   - `bash`
   - `zsh`
   - `syscall_execve`
   - `cpu`
   - `memory`
   - `socket`
   - `memory_faults`
   
   ### Filtering Options
   - `exclude_min_uid`
   - `exclude_max_uid`
   - `include_uid`
   - `executables`
   - `pid_list`
   - `shells`
   
   ### Output Options
   - `json`
   - `quiet`
   - `output.file`
   - `output.http`
   - `output.syslog`
   
   ### Performance Options
   - `poll`
   
   ### Debug Options
   - `debug`
   - `verbose`
   
   ## Configuration Examples
   
   ### Basic Configuration
   
   ### Advanced Configuration
   
   ### Production Configuration
   
   ### Development Configuration
   
   ## Configuration Merging
   
   ## Configuration Validation
   
   ## Troubleshooting
   ```
2. Document each configuration option:
   - Description
   - Type
   - Default value
   - Valid values
   - Examples
3. Add multiple configuration examples:
   - Minimal configuration
   - Full monitoring configuration
   - Development configuration
   - Production configuration
   - Troubleshooting configuration
4. Document configuration merging rules
5. Document configuration validation
6. Add troubleshooting section

**Validation**:
- Verify all options are documented
- Test all examples
- Check for accuracy

---

#### Task 4.3.2: Update Man Page
**Priority**: 🟡 High
**Effort**: 4-8 hours
**Dependencies**: None
**Files Affected**: `files/panhandle.man`

**Implementation Steps**:
1. Review current man page content
2. Update man page with:
   - Complete option descriptions
   - Examples for each option
   - Configuration file format
   - Environment variables (if any)
   - Exit codes
   - Signals
3. Add sections:
   - NAME
   - SYNOPSIS
   - DESCRIPTION
   - OPTIONS
   - CONFIGURATION
   - EXAMPLES
   - FILES
   - ENVIRONMENT
   - EXIT STATUS
   - SIGNALS
   - DIAGNOSTICS
   - BUGS
   - AUTHOR
   - COPYRIGHT
4. Use proper roff format
5. Test man page rendering:
   ```bash
   man ./files/panhandle.man
   ```
6. Update man page in RPM build

**Validation**:
- Verify man page renders correctly
- Check all options are documented
- Ensure examples are accurate

---

#### Task 4.3.3: Create DEPLOYMENT.md
**Priority**: 🟡 High
**Effort**: 8-12 hours
**Dependencies**: None
**Files Affected**: `DEPLOYMENT.md` (new)

**Implementation Steps**:
1. Create DEPLOYMENT.md file with structure:
   ```markdown
   # Panhandle Deployment Guide
   
   ## Prerequisites
   
   ### System Requirements
   
   ### Kernel Requirements
   
   ### Dependency Requirements
   
   ## Installation Methods
   
   ### RPM Installation
   
    ### Manual Installation

    ### From Source
   
   ## Configuration
   
   ### Basic Configuration
   
   ### Advanced Configuration
   
   ## Running Panhandle
   
   ### Systemd Service
   
   ### Manual Execution
   
   ### Command Line Usage
   
   ## Output Configuration
   
   ### File Output
   
   ### Syslog Output
   
   ### HTTP Output
   
   ## Monitoring Configuration
   
   ### Process Monitoring
   
   ### Shell Monitoring
   
   ### Network Monitoring
   
   ### CPU Monitoring
   
   ### Memory Monitoring
   
   ## Security Configuration
   
   ### Permissions
   
   ### SELinux
   
   ### AppArmor
   
   ## Performance Tuning
   
   ### Resource Limits
   
   ### Polling Intervals
   
   ### Buffer Sizes
   
   ## Troubleshooting
   
   ### Common Issues
   
   ### Log Analysis
   
   ### Debug Mode
   
   ## Upgrading
   
   ## Uninstalling
   
   ## Best Practices
   
   ### Production Deployment
   
   ### Development Deployment
   
   ### Testing Deployment
   ```
2. Document each installation method:
    - RPM installation (yum, dnf, zypper)
    - Manual installation (binary, config files)
    - From source installation
3. Document configuration for each use case
4. Document running panhandle:
   - Systemd service management
   - Manual execution
   - Command line options
5. Document output configuration for each destination
6. Document monitoring configuration for each type
7. Document security configuration
8. Document performance tuning
9. Add troubleshooting section with common issues
10. Add upgrading and uninstalling instructions
11. Add best practices

**Validation**:
- Verify all installation methods work
- Test all configuration examples
- Check troubleshooting section is helpful

---

#### Task 4.3.4: Update README.md
**Priority**: 🟡 High
**Effort**: 4-8 hours
**Dependencies**: Task 4.3.1, Task 4.3.3
**Files Affected**: `README.md`

**Implementation Steps**:
1. Review current README content
2. Add sections:
   - Features (detailed list)
   - Installation (quick start)
   - Usage (basic examples)
   - Configuration (link to CONFIGURATION.md)
   - Deployment (link to DEPLOYMENT.md)
   - Architecture (link to ARCHITECTURE.md)
   - Documentation (links to all docs)
   - Examples (basic usage examples)
   - Troubleshooting (common issues)
   - Contributing (link to CONTRIBUTING.md)
   - License
   - Acknowledgments
3. Add badges:
   - CI status
   - Test coverage
   - Documentation
   - License
   - Version
4. Add table of contents
5. Add screenshots or diagrams (optional)
6. Update release information
7. Add contact information

**Validation**:
- Verify README is comprehensive
- Check all links work
- Ensure information is accurate

---

### 4.4 Developer Documentation

#### Task 4.4.1: Create CONTRIBUTING.md
**Priority**: 🟢 Medium
**Effort**: 4-8 hours
**Dependencies**: None
**Files Affected**: `CONTRIBUTING.md` (new)

**Implementation Steps**:
1. Create CONTRIBUTING.md file with structure:
   ```markdown
   # Contributing to Panhandle
   
   ## Getting Started
   
   ### Prerequisites
   
   ### Building
   
   ### Running Tests
   
   ### Running the Project
   
   ## Development Workflow
   
   ### Forking the Repository
   
   ### Creating a Branch
   
   ### Making Changes
   
   ### Submitting Changes
   
   ## Code Guidelines
   
   ### Coding Style
   
   ### Code Formatting
   
   ### Documentation
   
   ### Testing
   
   ### Performance
   
   ### Security
   
   ## Commit Guidelines
   
   ### Commit Messages
   
   ### Signing Commits
   
   ## Pull Request Guidelines
   
   ### Pull Request Template
   
   ### Review Process
   
   ### Merging
   
   ## Issue Guidelines
   
   ### Reporting Issues
   
   ### Issue Template
   
   ### Issue Labels
   
   ## Code Review Process
   
   ### Reviewer Guidelines
   
   ### Author Guidelines
   
   ## Community Guidelines
   
   ### Code of Conduct
   
   ### Communication
   
   ## Additional Resources
   
   ### Documentation
   
   ### Examples
   
   ### Tutorials
   ```
2. Document development environment setup:
   - Prerequisites (Rust, LLVM, clang, etc.)
   - Building from source
   - Running tests
   - Running the project
3. Document development workflow:
   - Forking the repository
   - Creating branches
   - Making changes
   - Submitting pull requests
4. Document code guidelines:
   - Coding style
   - Code formatting (rustfmt)
   - Documentation (rustdoc)
   - Testing requirements
   - Performance considerations
   - Security considerations
5. Document commit guidelines:
   - Commit message format
   - Signing commits
6. Document pull request guidelines:
   - Pull request template
   - Review process
   - Merging criteria
7. Document issue guidelines:
   - Reporting issues
   - Issue template
   - Issue labels
8. Document code review process
9. Add code of conduct
10. Add community guidelines

**Validation**:
- Verify all development information is accurate
- Check that all links work
- Ensure guidelines are clear

---

#### Task 4.4.2: Create ROADMAP.md
**Priority**: 🟢 Medium
**Effort**: 4-8 hours
**Dependencies**: None
**Files Affected**: `ROADMAP.md` (new)

**Implementation Steps**:
1. Create ROADMAP.md file with structure:
   ```markdown
   # Panhandle Roadmap
   
   ## Vision
   
   ## Current Status
   
   ## Upcoming Releases
   
   ### Version 1.1.0
   - [ ] Feature 1
   - [ ] Feature 2
   - [ ] Bug fix 1
   
   ### Version 1.2.0
   - [ ] Feature 3
   - [ ] Feature 4
   
   ## Long-Term Goals
   
   ### Monitoring Enhancements
   - [ ] Feature idea 1
   - [ ] Feature idea 2
   
   ### Performance Improvements
   - [ ] Optimization 1
   - [ ] Optimization 2
   
   ### Usability Improvements
   - [ ] UI enhancement 1
   - [ ] UI enhancement 2
   
   ## Completed Features
   
   ### Version 1.0.10
   - [x] Added CPU usage monitoring
   
   ### Version 1.0.9
   - [x] Added monitoring for sockets and memory paging
   
   ## Contribution Opportunities
   
   ### Good First Issues
   
   ### Help Wanted
   
   ### Mentored Issues
   
   ## Release Process
   
   ### Release Schedule
   
   ### Release Checklist
   ```
2. Document current status:
   - Current version
   - Recent releases
   - Current development focus
3. Document upcoming releases:
   - Planned features
   - Tentative release dates
   - Priority order
4. Document long-term goals:
   - Monitoring enhancements
   - Performance improvements
   - Usability improvements
   - Architecture improvements
5. Document completed features:
   - Recent releases
   - Historical releases
6. Document contribution opportunities:
   - Good first issues
   - Help wanted issues
   - Mentored issues
7. Document release process:
   - Release schedule
   - Release checklist
   - Versioning policy

**Validation**:
- Verify roadmap is realistic
- Check that all completed features are listed
- Ensure priorities are clear

---

#### Task 4.4.3: Create SECURITY.md
**Priority**: 🟡 High
**Effort**: 4-8 hours
**Dependencies**: None
**Files Affected**: `SECURITY.md` (new)

**Implementation Steps**:
1. Create SECURITY.md file with structure:
   ```markdown
   # Panhandle Security
   
   ## Security Policy
   
   ### Supported Versions
   
   ### Reporting a Vulnerability
   
   ## Security Features
   
   ### Authentication
   
   ### Authorization
   
   ### Encryption
   
   ### Auditing
   
   ## Security Best Practices
   
   ### Deployment
   
   ### Configuration
   
   ### Monitoring
   
   ### Incident Response
   
   ## Security Vulnerabilities
   
   ### Known Vulnerabilities
   
   ### Fixed Vulnerabilities
   
   ## Security Testing
   
   ### Static Analysis
   
   ### Dynamic Analysis
   
   ### Penetration Testing
   
   ## Security Contacts
   
   ## Security Advisories
   
   ## Security Update Policy
   ```
2. Document security policy:
   - Supported versions
   - Vulnerability reporting process
   - Response time commitments
3. Document security features:
   - Current security features
   - Planned security features
4. Document security best practices:
   - Secure deployment
   - Secure configuration
   - Security monitoring
   - Incident response
5. Document known and fixed vulnerabilities
6. Document security testing:
   - Static analysis tools
   - Dynamic analysis tools
   - Penetration testing
7. Add security contacts
8. Document security update policy

**Validation**:
- Verify security policy is clear
- Check that reporting process is straightforward
- Ensure all security information is accurate

---

## 5. Performance Optimization Tasks 🟢

### 5.1 String Handling Optimization

#### Task 5.1.1: Optimize String Formatting in Event Processing
**Priority**: 🟢 Medium
**Effort**: 8-12 hours
**Dependencies**: None
**Files Affected**: `panhandle/src/helpers.rs`

**Implementation Steps**:
1. Profile current string formatting performance:
   ```bash
   cargo bench
   ```
2. Identify hot spots in string formatting:
   - JSON string construction (lines 73-90, 223-256)
   - Plain text string construction (lines 124-130, 287-293)
3. Optimize string formatting:
   - Use `String` with pre-allocated capacity
   - Use `write!` macro for efficient string building
   - Avoid intermediate string allocations
   - Use `&str` slices where possible
4. Replace format! macros with more efficient alternatives:
   ```rust
   // Before:
   let json_string = format!(
       "{{...}}", hostname, user, data, ...
   );
   
   // After:
   let mut json_string = String::with_capacity(1024);
   write!(
       json_string,
       "{{...}}", hostname, user, data, ...
   ).unwrap();
   ```
5. Use serde_json for JSON formatting where appropriate
6. Cache frequently used strings (hostname, application name)
7. Benchmark before and after optimization

**Validation**:
- Verify performance improvement
- Check that output is identical
- Ensure no functionality is broken

---

#### Task 5.1.2: Reduce Memory Allocations in Hot Paths
**Priority**: 🟢 Medium
**Effort**: 12-16 hours
**Dependencies**: Task 5.1.1
**Files Affected**: All monitoring modules, helpers.rs

**Implementation Steps**:
1. Profile memory allocations:
   - Use `valgrind --tool=massif`
   - Use `heaptrack`
   - Use `/usr/bin/time -v`
2. Identify allocation hot spots:
   - Event processing loops
   - String formatting
   - Data structure creation
3. Reduce allocations:
   - Use object pools for frequently allocated objects
   - Pre-allocate buffers and strings
   - Reuse objects where possible
   - Use stack allocation for small objects
4. Implement object pooling:
   ```rust
   struct BytesMutPool {
       pool: Vec<BytesMut>,
   }
   
   impl BytesMutPool {
       fn new(capacity: usize) -> Self {
           Self {
               pool: Vec::with_capacity(capacity),
           }
       }
       
       fn get(&mut self) -> BytesMut {
           self.pool.pop().unwrap_or_else(|| BytesMut::with_capacity(2048))
       }
       
       fn return(&mut self, buf: BytesMut) {
           buf.clear();
           self.pool.push(buf);
       }
   }
   ```
5. Use Arc instead of cloning for shared data
6. Use Cow (Copy-on-Write) for string data
7. Benchmark before and after optimization

**Validation**:
- Verify memory usage reduction
- Check performance improvement
- Ensure no memory leaks

---

### 5.2 Buffer Sizing

#### Task 5.2.1: Make Buffer Sizes Configurable
**Priority**: 🟢 Medium
**Effort**: 8-12 hours
**Dependencies**: Task 2.1.2
**Files Affected**: `panhandle/src/helpers.rs`, `panhandle/src/main.rs`, `panhandle-common/src/lib.rs`

**Implementation Steps**:
1. Add buffer size constants to panhandle-common:
   ```rust
   pub const DEFAULT_EVENT_BUFFER_CAPACITY: usize = 2048;
   pub const MIN_EVENT_BUFFER_CAPACITY: usize = 1024;
   pub const MAX_EVENT_BUFFER_CAPACITY: usize = 65536;
   ```
2. Add CLI argument for buffer size:
   ```rust
   #[arg(long, value_parser = clap::value_parser!(usize).range(MIN_EVENT_BUFFER_CAPACITY..=MAX_EVENT_BUFFER_CAPACITY))]
   pub event_buffer_capacity: Option<usize>,
   ```
3. Add configuration option for buffer size
4. Update buffer creation to use configurable size:
   ```rust
   let buffer_capacity = args.event_buffer_capacity.unwrap_or(DEFAULT_EVENT_BUFFER_CAPACITY);
   let buffers = (0..num_cpus)
       .map(|_| BytesMut::with_capacity(buffer_capacity))
       .collect::<Vec<_>>();
   ```
5. Add validation for buffer size
6. Document buffer size configuration
7. Test with different buffer sizes

**Validation**:
- Verify buffer size can be configured
- Test with minimum, maximum, and default values
- Check that buffer overruns are handled

---

### 5.3 HTTP Client Optimization

#### Task 5.3.1: Implement HTTP Client Connection Pooling
**Priority**: 🟢 Medium
**Effort**: 8-12 hours
**Dependencies**: None
**Files Affected**: `panhandle/src/helpers.rs`, `panhandle/src/main.rs`

**Implementation Steps**:
1. Review current HTTP client usage:
   - New client created for each request in some locations
   - Client reused in others
2. Create shared HTTP client:
   ```rust
   #[derive(Clone)]
   struct HttpOutput {
       client: Client,
       url: Arc<String>,
       json: bool,
       debug: bool,
   }
   
   impl HttpOutput {
       fn new(url: Arc<String>, json: bool, debug: bool) -> Self {
           let client = Client::builder()
               .timeout(Duration::from_millis(HTTP_TIMEOUT_MS))
               .build()
               .expect("Failed to create HTTP client");
           
           Self {
               client,
               url,
               json,
               debug,
           }
       }
       
       async fn send(&self, message: &str) -> Result<(), Error> {
           // Use self.client for all requests
           let mut request = self.client.post(&self.url);
           // ...
       }
   }
   ```
3. Create single HTTP client at startup
4. Pass client reference to all functions that need it
5. Configure client with appropriate settings:
   - Timeout
   - Connection pooling
   - TLS settings
   - Retry policy
6. Add client metrics (optional):
   - Request count
   - Error count
   - Response time
7. Test connection pooling

**Validation**:
- Verify HTTP client is reused
- Check connection count with `netstat` or `ss`
- Test with high request volume
- Verify performance improvement

---

### 5.4 Polling Optimization

#### Task 5.4.1: Implement Adaptive Polling
**Priority**: 🟢 Medium
**Effort**: 12-16 hours
**Dependencies**: None
**Files Affected**: `panhandle/src/monitor_cpu_usage.rs`, `panhandle/src/main.rs`

**Implementation Steps**:
1. Design adaptive polling algorithm:
   - Monitor event rate
   - Adjust polling interval based on load
   - Set minimum and maximum polling intervals
2. Add event rate tracking:
   ```rust
   struct AdaptivePoller {
       base_interval: Duration,
       min_interval: Duration,
       max_interval: Duration,
       event_rate: f64, // events per second
       last_adjustment: Instant,
       adjustment_interval: Duration,
   }
   
   impl AdaptivePoller {
       fn new(base_interval: Duration) -> Self {
           Self {
               base_interval,
               min_interval: Duration::from_millis(100),
               max_interval: Duration::from_secs(60),
               event_rate: 0.0,
               last_adjustment: Instant::now(),
               adjustment_interval: Duration::from_secs(10),
           }
       }
       
       fn record_event(&mut self) {
           self.event_rate += 1.0;
       }
       
       fn get_interval(&mut self) -> Duration {
           if self.last_adjustment.elapsed() >= self.adjustment_interval {
               // Adjust interval based on event rate
n               let target_interval = self.base_interval.mul_f64(1.0 / (1.0 + self.event_rate.powi(2)));
               self.base_interval = target_interval.clamp(self.min_interval, self.max_interval);
               
               // Reset counters
               self.event_rate = 0.0;
               self.last_adjustment = Instant::now();
           }
           
           self.base_interval
       }
   }
   ```
3. Integrate adaptive poller into monitoring modules
4. Add configuration for adaptive polling:
   - Enable/disable
   - Base interval
   - Minimum interval
   - Maximum interval
   - Adjustment sensitivity
5. Test adaptive polling with different workloads
6. Benchmark performance improvement

**Validation**:
- Verify adaptive polling works correctly
- Test with varying event rates
- Check that polling interval stays within bounds
- Verify performance improvement

---

## 6. eBPF-Specific Tasks 🟡

### 6.1 eBPF Safety Improvements

#### Task 6.1.1: Review and Enhance All Unsafe Blocks in eBPF
**Priority**: 🔴 Critical
**Effort**: 24-32 hours
**Dependencies**: None
**Files Affected**: All eBPF source files

**Implementation Steps**:
1. Create comprehensive list of all unsafe blocks:
   ```bash
   grep -rn "unsafe" panhandle-ebpf/src/
   ```
2. For each unsafe block:
   a. Identify the operation (pointer dereference, map access, etc.)
   b. Verify bounds checking is adequate
   c. Add comprehensive safety comments
   d. Consider using safe abstractions
3. Focus on high-risk operations:
   - Pointer casting (cpu_usage.rs:37-38)
   - Map access (main.rs:86-88, 140-142)
   - Context argument access (socket.rs:46-48, 94, 123, etc.)
   - Probe read operations (main.rs:95-99, 107, 125-128, etc.)
4. Add safety comments template:
   ```rust
   // SAFETY: [Explanation of why this is safe]
   // - [Condition 1 that ensures safety]
   // - [Condition 2 that ensures safety]
   // - [Error handling if conditions are not met]
   unsafe { ... }
   ```
5. Example enhanced safety comment:
   ```rust
   // SAFETY: We are reading from a kernel tracepoint context that is guaranteed
   // to be valid by the kernel. The trace_event_raw_sched_switch struct is
   // defined by the kernel and stable across versions we support.
   // The pointer is provided by the kernel and is guaranteed to be valid.
   let tp: *const trace_event_raw_sched_switch = ctx.as_ptr().cast();
   ```
6. Consider using safe abstractions:
   - Use `ctx.read_at()` instead of raw pointer casting
   - Use map helper methods instead of raw pointer access
7. Add static analysis for eBPF safety

**Validation**:
- Review all unsafe blocks with team
- Verify safety comments are comprehensive
- Check that all safety conditions are met

---

#### Task 6.1.2: Add eBPF Verification to Build Process
**Priority**: 🟡 High
**Effort**: 8-12 hours
**Dependencies**: None
**Files Affected**: `panhandle-ebpf/build.rs`, `.github/workflows/ci.yml`

**Implementation Steps**:
1. Add eBPF verification to build.rs:
   ```rust
   fn main() {
       // Existing bpf-linker check
       let bpf_linker = which("bpf-linker").unwrap_or(defaultpath);
       println!("cargo:rerun-if-changed={}", bpf_linker.to_str().unwrap());
       
       // Add verification step
       println!("cargo:rustc-env=BPF_VERIFY=1");
   }
   ```
2. Add verification script:
   ```bash
   #!/bin/bash
   # scripts/verify_ebpf.sh
   
   set -e
   
   echo "Verifying eBPF programs..."
   
   # Build eBPF programs
   cargo build --release --package panhandle-ebpf
   
   # Find eBPF object files
   find target -name "*.o" -type f | while read -r file; do
       echo "Verifying $file..."
       bpftool prog load "$file" || {
           echo "Verification failed for $file"
           exit 1
       }
   done
   
   echo "All eBPF programs verified successfully!"
   ```
3. Add verification to CI:
   ```yaml
   - name: Verify eBPF programs
     run: ./scripts/verify_ebpf.sh
   ```
4. Add verification to pre-commit hook (optional)
5. Document verification process

**Validation**:
- Verify all eBPF programs pass verification
- Test with different kernel versions
- Check that CI fails on verification errors

---

### 6.2 eBPF Testing

#### Task 6.2.1: Add eBPF Unit Tests
**Priority**: 🟡 High
**Effort**: 24-32 hours
**Dependencies**: Task 3.1.3
**Files Affected**: `panhandle-ebpf/tests/` (new directory)

**Implementation Steps**:
1. Set up eBPF testing environment:
   - Add `aya-tool` dependency
   - Set up test kernel modules
2. Create test infrastructure:
   ```rust
   // panhandle-ebpf/tests/utils.rs
   use aya_ebpf::Program;
   use aya_tool::test::BpfToolTest;
   
   pub struct EbpfTest {
       pub test: BpfToolTest,
   }
   
   impl EbpfTest {
       pub fn new() -> Self {
           Self {
               test: BpfToolTest::new(),
           }
       }
       
       pub fn load_program(&self, name: &str) -> Result<Program, anyhow::Error> {
           self.test.load_program(name)
       }
       
       pub fn trigger_tracepoint(&self, tracepoint: &str) -> Result<(), anyhow::Error> {
           self.test.trigger_tracepoint(tracepoint)
       }
   }
   ```
3. Add tests for each eBPF program:
   - panhandle (execve tracepoint)
   - sched_switch (CPU monitoring)
   - inet_sock_set_state (network state)
   - tcp_sendmsg, tcp_cleanup_rbuf (TCP data)
   - udp_sendmsg, udp_recvmsg (UDP data)
   - readline (bash monitoring)
   - zlentry (zsh monitoring)
4. Test map operations:
   - Insert, lookup, update, delete
   - PerCpuArray operations
   - HashMap operations
5. Test UID filtering:
   - Exclude UID range
   - Include UID list
   - Shell filtering
6. Test event processing:
   - Event data extraction
   - Event filtering
   - Event output
7. Run tests with:
   ```bash
   cargo test --package panhandle-ebpf
   ```

**Validation**:
- Verify all eBPF programs can be tested
- Check that tests cover all functionality
- Ensure tests pass on CI

---

#### Task 6.2.2: Add eBPF Integration Tests
**Priority**: 🟡 High
**Effort**: 16-24 hours
**Dependencies**: Task 6.2.1
**Files Affected**: `panhandle-ebpf/tests/test_integration.rs`

**Implementation Steps**:
1. Create integration test file
2. Add tests for complete eBPF workflows:
   ```rust
   #[test]
   fn test_execve_monitoring_integration() {
       // Load eBPF program
       let mut ebpf = Ebpf::load(include_bytes_aligned!("...")).unwrap();
       
       // Attach tracepoint
       let program: &mut TracePoint = ebpf.program_mut("panhandle").unwrap().try_into().unwrap();
       program.load().unwrap();
       program.attach("syscalls", "sys_enter_execve").unwrap();
       
       // Set up maps
       // ...
       
       // Trigger event
       std::process::Command::new("ls").output().unwrap();
       
       // Read events
       // ...
       
       // Verify event was captured
       // ...
       
       // Clean up
       program.detach().unwrap();
   }
   ```
3. Test end-to-end scenarios:
   - Execve monitoring
   - Bash monitoring
   - Zsh monitoring
   - CPU monitoring
   - Network monitoring
4. Test with different configurations:
   - UID filtering
   - Shell filtering
   - Executable filtering
5. Test error scenarios:
   - Invalid configurations
   - Permission errors
   - Resource exhaustion
6. Add performance tests for eBPF programs

**Validation**:
- Verify integration tests pass
- Check that all workflows are tested
- Ensure tests run on CI

---

### 6.3 eBPF Portability

#### Task 6.3.1: Add Kernel Version Compatibility Checks
**Priority**: 🟢 Medium
**Effort**: 8-12 hours
**Dependencies**: None
**Files Affected**: `panhandle/src/main.rs`, `panhandle-ebpf/src/lib.rs` (new)

**Implementation Steps**:
1. Research kernel version requirements:
   - Minimum kernel version for each eBPF feature
   - Tracepoints: Linux 4.7+
   - BTF: Linux 5.4+
   - etc.
2. Add kernel version detection:
   ```rust
   use std::fs;
   
   pub fn get_kernel_version() -> Result<(u32, u32, u32), anyhow::Error> {
       let uname = fs::read_to_string("/proc/sys/kernel/osrelease")?;
       let parts: Vec<&str> = uname.trim().split('.').collect();
       
       if parts.len() < 3 {
           return Err(anyhow::anyhow!("Invalid kernel version format"));
       }
       
       let major = parts[0].parse()?;
       let minor = parts[1].parse()?;
       let patch = parts[2].parse::<u32>().unwrap_or(0);
       
       Ok((major, minor, patch))
   }
   ```
3. Add feature detection:
   ```rust
   pub struct KernelFeatures {
       pub tracepoints: bool,
       pub btf: bool,
       pub kprobes: bool,
       pub uprobes: bool,
   }
   
   impl KernelFeatures {
       pub fn detect() -> Self {
           let (major, minor, _) = get_kernel_version().unwrap_or((0, 0, 0));
           
           Self {
               tracepoints: major > 4 || (major == 4 && minor >= 7),
               btf: major > 5 || (major == 5 && minor >= 4),
               kprobes: major > 4 || (major == 4 && minor >= 4),
               uprobes: major > 4 || (major == 4 && minor >= 4),
           }
       }
       
       pub fn supports_cpu_monitoring(&self) -> bool {
           self.tracepoints
       }
       
       pub fn supports_network_monitoring(&self) -> bool {
           self.btf && self.tracepoints
       }
       
       pub fn supports_shell_monitoring(&self) -> bool {
           self.uprobes
       }
   }
   ```
4. Add checks at startup:
   ```rust
   let kernel_features = KernelFeatures::detect();
   
   if args.cpu && !kernel_features.supports_cpu_monitoring() {
       error!("CPU monitoring requires Linux kernel 4.7+");
       process::exit(1);
   }
   
   if args.socket && !kernel_features.supports_network_monitoring() {
       error!("Network monitoring requires Linux kernel 5.4+ with BTF");
       process::exit(1);
   }
   ```
5. Add graceful degradation for unsupported features
6. Document kernel version requirements

**Validation**:
- Test on different kernel versions
- Verify appropriate error messages
- Check graceful degradation

---

## 7. Configuration and Deployment Tasks 🟢

### 7.1 Configuration Improvements

#### Task 7.1.1: Define Formal Configuration Schema
**Priority**: 🟢 Medium
**Effort**: 8-12 hours
**Dependencies**: None
**Files Affected**: `panhandle-common/src/lib.rs`, `Cargo.toml`

**Implementation Steps**:
1. Add schemars dependency:
   ```toml
   [dependencies]
   schemars = "0.8"
   ```
2. Add Schema derive to configuration structs:
   ```rust
   use schemars::JsonSchema;
   
   #[derive(Debug, Deserialize, Clone, PartialEq, JsonSchema)]
   #[serde(deny_unknown_fields)]
   pub struct ConfigArgs {
       // ...
   }
   ```
3. Generate JSON schema:
   ```rust
   use schemars::schema_for;
   
   let schema = schema_for!(ConfigArgs);
   let schema_json = serde_json::to_string_pretty(&schema).unwrap();
   std::fs::write("panhandle-config-schema.json", schema_json).unwrap();
   ```
4. Add schema generation to build process:
   ```rust
   // build.rs
   fn main() {
       // ... existing code
       
       // Generate configuration schema
       generate_config_schema();
   }
   
   fn generate_config_schema() {
       use panhandle_common::ConfigArgs;
       use schemars::schema_for;
       
       let schema = schema_for!(ConfigArgs);
       let schema_json = serde_json::to_string_pretty(&schema).unwrap();
       
       std::fs::create_dir_all("target/schemas").unwrap();
       std::fs::write("target/schemas/panhandle-config-schema.json", schema_json).unwrap();
       
       println!("cargo:rerun-if-changed=panhandle-common/src/lib.rs");
   }
   ```
5. Add schema to documentation
6. Use schema for validation
7. Document schema

**Validation**:
- Verify schema is generated correctly
- Check that schema matches configuration structs
- Test schema validation

---

#### Task 7.1.2: Add Environment Variable Support
**Priority**: 🟢 Medium
**Effort**: 8-12 hours
**Dependencies**: None
**Files Affected**: `panhandle/src/input_configs.rs`, `panhandle/src/main.rs`

**Implementation Steps**:
1. Add environment variable parsing:
   ```rust
   use std::env;
   
   pub fn get_env_bool(var: &str, default: bool) -> bool {
       match env::var(var) {
           Ok(val) => val.parse::<bool>().unwrap_or(default),
           Err(_) => default,
       }
   }
   
   pub fn get_env_usize(var: &str, default: usize) -> usize {
       match env::var(var) {
           Ok(val) => val.parse::<usize>().unwrap_or(default),
           Err(_) => default,
       }
   }
   
   pub fn get_env_string(var: &str, default: Option<String>) -> Option<String> {
       match env::var(var) {
           Ok(val) => Some(val),
           Err(_) => default,
       }
   }
   ```
2. Add environment variable support to ConfigArgs:
   ```rust
   impl ConfigArgs {
       pub fn from_env() -> Self {
           Self {
               verbose: get_env_bool("PANHANDLE_VERBOSE", false),
               debug: get_env_bool("PANHANDLE_DEBUG", false),
               json: get_env_bool("PANHANDLE_JSON", false),
               // ... other fields
               exclude_min_uid: env::var("PANHANDLE_EXCLUDE_MIN_UID")
                   .ok()
                   .and_then(|s| s.parse().ok()),
               // ...
           }
       }
   }
   ```
3. Update argument merging to include environment variables:
   ```rust
   pub async fn merge_args(
       cli_args: RawArgs,
       config_args: ConfigArgs,
       env_args: ConfigArgs,
   ) -> RawArgs {
       // Merge with priority: CLI > Environment > Config
       // ...
   }
   ```
4. Document environment variables:
   - Add to CONFIGURATION.md
   - Add to man page
   - Add to README
5. Add validation for environment variables

**Environment Variables to Support**:
- `PANHANDLE_VERBOSE`
- `PANHANDLE_DEBUG`
- `PANHANDLE_JSON`
- `PANHANDLE_QUIET`
- `PANHANDLE_CONFIG`
- `PANHANDLE_EXCLUDE_MIN_UID`
- `PANHANDLE_EXCLUDE_MAX_UID`
- `PANHANDLE_POLL`
- `PANHANDLE_OUTPUT_FILE`
- `PANHANDLE_OUTPUT_HTTP`
- `PANHANDLE_OUTPUT_SYSLOG`

**Validation**:
- Test environment variable parsing
- Verify priority order (CLI > Environment > Config)
- Check that all variables are documented

---

#### Task 7.1.3: Add Configuration Reloading
**Priority**: 🟢 Medium
**Effort**: 12-16 hours
**Dependencies**: None
**Files Affected**: `panhandle/src/main.rs`, `panhandle/src/input_configs.rs`

**Implementation Steps**:
1. Design configuration reloading mechanism:
   - SIGHUP signal handler
   - Configuration watcher (inotify)
   - Manual reload command
2. Add SIGHUP handler:
   ```rust
   use tokio::signal::unix::{signal, SignalKind};
   
   async fn handle_signals(mut config_reloader: ConfigReloader) {
       let mut sighup = signal(SignalKind::hangup()).unwrap();
       
       loop {
           sighup.recv().await;
           info!("Received SIGHUP, reloading configuration...");
           
           match config_reloader.reload().await {
               Ok(_) => info!("Configuration reloaded successfully"),
               Err(e) => error!("Failed to reload configuration: {}", e),
           }
       }
   }
   ```
3. Create ConfigReloader struct:
   ```rust
   struct ConfigReloader {
       config_path: Option<String>,
       current_args: Arc<RwLock<RawArgs>>,
   }
   
   impl ConfigReloader {
       async fn reload(&mut self) -> Result<(), anyhow::Error> {
           if let Some(path) = &self.config_path {
               let new_args = if let Some(cli_config) = self.current_args.read().await.config.clone() {
                   let config_args = load_config_args(path.clone()).await?;
                   merge_args(RawArgs::default(), config_args).await
               } else {
                   load_config_args(path.clone()).await?.into()
               };
               
               *self.current_args.write().await = new_args;
           }
           
           Ok(())
       }
   }
   ```
4. Update main function to support reloading:
   - Store current configuration in Arc<RwLock>
   - Pass configuration reference to monitoring tasks
   - Update tasks to use current configuration
5. Add configuration validation on reload
6. Add logging for configuration changes
7. Document configuration reloading

**Validation**:
- Test SIGHUP handling
- Verify configuration is reloaded correctly
- Check that monitoring continues during reload
- Test with invalid configuration

---

### 7.2 Deployment Improvements

#### Task 7.2.1: Improve RPM Packaging
**Priority**: 🟢 Medium
**Effort**: 8-12 hours
**Dependencies**: None
**Files Affected**: `panhandle/panhandle/Cargo.toml`, `scripts/`

**Implementation Steps**:
1. Review current RPM build configuration in Cargo.toml
2. Update RPM metadata:
   - Ensure all files are included
   - Update descriptions and summaries
   - Add proper dependencies
3. Improve pre-install and post-install scripts:
   - Review `scripts/pre-install-rpm.sh`
   - Review `scripts/post-uninstall-rpm.sh`
   - Add proper error handling
4. Add validation for RPM build process
5. Test RPM installation on target systems:
   - RHEL 8
   - RHEL 9
   - SLES 15
6. Document RPM installation and configuration
7. Add RPM build to CI pipeline

**Validation**:
- Build RPM package successfully
- Install RPM on test systems
- Verify all files are installed correctly
- Test service starts properly

---


## 8. Project Infrastructure Tasks 🟢

### 8.1 Build System Improvements

#### Task 8.1.1: Update and Clean Up Dependencies
**Priority**: 🟢 Medium
**Effort**: 8-12 hours
**Dependencies**: None
**Files Affected**: All Cargo.toml files

**Implementation Steps**:
1. Run dependency audit:
   ```bash
   cargo audit
   cargo outdated
   cargo tree
   ```
2. Update dependencies to latest stable versions:
   - Check for updates to aya and aya-ebpf
   - Update tokio
   - Update reqwest
   - Update serde and serde_json
   - Update clap
   - Update other dependencies
3. Review dependency features:
   - Ensure only necessary features are enabled
   - Consider disabling default features where not needed
4. Add dependency groups:
   ```toml
   [dependencies]
   # Core dependencies
   aya = { version = "0.13.1", default-features = false }
   tokio = { version = "1.52.2", features = ["macros", "rt", "rt-multi-thread", "net", "signal"] }
   
   # HTTP dependencies
   reqwest = { version = "0.13.1", features = ["json", "rustls-tls"] }
   url = "2.5.7"
   
   # Configuration dependencies
   serde = { version = "1.0.228", features = ["derive"] }
   serde_json = "1.0.150"
   serde_yaml = "0.9.34"
   config = "0.15.23"
   
   # Logging dependencies
   simplelog = { version = "0.12.2", features = ["paris", "local-offset"] }
   log = { version = "0.4.22", default-features = false }
   
   # System dependencies
   hostname = "0.4.1"
   sysinfo = "0.39.3"
   procfs = "0.18.0"
   uzers = "0.12.2"
   
   # Network dependencies
   network-interface = "2.0.5"
   port_check = "0.3.0"
   
   # CLI dependencies
   clap = { version = "4.6.0", features = ["derive"] }
   ```
5. Run `cargo update` and verify compatibility
6. Test with updated dependencies
7. Update Cargo.lock
8. Document dependency updates in CHANGELOG

**Validation**:
- Verify all tests pass with updated dependencies
- Check that build succeeds
- Ensure no breaking changes

---

#### Task 8.1.2: Improve Build Configuration
**Priority**: 🟢 Medium
**Effort**: 4-8 hours
**Dependencies**: None
**Files Affected**: All Cargo.toml files, build.rs files

**Implementation Steps**:
1. Review and standardize Cargo.toml files:
   - Ensure consistent formatting
   - Add missing metadata
   - Standardize feature usage
2. Add workspace inheritance:
   ```toml
   [workspace]
   resolver = "2"
   members = ["panhandle", "panhandle-common", "panhandle-ebpf"]
   default-members = ["panhandle"]
   
   [workspace.dependencies]
   # Shared dependencies
   aya = { version = "0.13.1", default-features = false }
   tokio = { version = "1.52.2", default-features = false }
   log = { version = "0.4.22", default-features = false }
   serde = { version = "1.0.228", features = ["derive"] }
   ```
3. Update panhandle/Cargo.toml to use workspace dependencies
4. Add profile configurations:
   ```toml
   [profile.release]
   opt-level = 3
   lto = "fat"
   codegen-units = 1
   panic = "abort"
   strip = true
   
   [profile.release.build-override]
   opt-level = 3
   
   [profile.dev]
   opt-level = 1
   
   [profile.test]
   opt-level = 1
   ```
5. Add build metadata:
   ```toml
   [package.metadata.generate-rpm]
   author = "Skip McGee <dmcgee@lanl.gov>"
   # ... existing metadata
   ```
6. Add rustc configuration:
   ```toml
   [package.metadata.rustc]
   # Enable all warnings
   rustflags = [
       "-W", "clippy::all",
       "-W", "clippy::pedantic",
       "-W", "clippy::nursery",
       "-W", "clippy::cargo",
   ]
   ```
7. Test build with new configuration

**Validation**:
- Verify build succeeds with new configuration
- Check that all features work
- Ensure no regressions

---

### 8.2 CI/CD Improvements

#### Task 8.2.1: Enhance GitHub Actions Workflow
**Priority**: 🟢 Medium
**Effort**: 8-12 hours
**Dependencies**: None
**Files Affected**: `.github/workflows/ci.yml`

**Implementation Steps**:
1. Review current workflow:
   ```yaml
   # Current workflow
   name: CI
   on: [push, pull_request]
   jobs:
     build:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
         - run: cargo build
   ```
2. Enhance workflow with comprehensive jobs:
   ```yaml
   name: CI
   on:
     push:
       branches: [main]
     pull_request:
       branches: [main]
   
   env:
     CARGO_TERM_COLOR: always
     RUSTFLAGS: -Dwarnings
   
   jobs:
     build:
       name: Build
       runs-on: ubuntu-latest
       strategy:
         matrix:
           features: ["", "all"]
       steps:
         - uses: actions/checkout@v4
         
         - name: Install Rust
           uses: actions-rs/toolchain@v1
           with:
             profile: minimal
             toolchain: stable
             override: true
             components: rustfmt, clippy
         
         - name: Install build dependencies
           run: |
             sudo apt-get update
             sudo apt-get install -y clang llvm libelf-dev linux-headers-$(uname -r)
         
         - name: Cache cargo registry
           uses: actions/cache@v3
           with:
             path: ~/.cargo/registry
             key: ${{ runner.os }}-cargo-registry-${{ hashFiles('**/Cargo.lock') }}
         
         - name: Cache cargo index
           uses: actions/cache@v3
           with:
             path: ~/.cargo/git
             key: ${{ runner.os }}-cargo-git-${{ hashFiles('**/Cargo.lock') }}
         
         - name: Cache cargo build
           uses: actions/cache@v3
           with:
             path: target
             key: ${{ runner.os }}-cargo-build-${{ hashFiles('**/Cargo.lock') }}-${{ matrix.features }}
         
         - name: Build with features
           run: |
             if [ -z "${{ matrix.features }}" ]; then
               cargo build --workspace --all-targets
             else
               cargo build --workspace --all-targets --features ${{ matrix.features }}
             fi
         
         - name: Build eBPF programs
           run: cargo build --package panhandle-ebpf --release
         
         - name: Verify eBPF programs
           run: ./scripts/verify_ebpf.sh
   
     test:
       name: Test
       runs-on: ubuntu-latest
       needs: build
       steps:
         - uses: actions/checkout@v4
         
         - name: Install Rust
           uses: actions-rs/toolchain@v1
           with:
             profile: minimal
             toolchain: stable
             override: true
         
         - name: Install build dependencies
           run: |
             sudo apt-get update
             sudo apt-get install -y clang llvm libelf-dev linux-headers-$(uname -r)
         
         - name: Cache cargo
           uses: actions/cache@v3
           with:
             path: |
               ~/.cargo/registry
               ~/.cargo/git
               target
             key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}
         
         - name: Run unit tests
           run: cargo test --workspace --all-features
         
         - name: Run clippy
           run: cargo clippy --workspace --all-features --all-targets -- -D warnings
         
         - name: Run fmt check
           run: cargo fmt --all -- --check
         
         - name: Run audit
           run: cargo audit
   
     coverage:
       name: Coverage
       runs-on: ubuntu-latest
       needs: test
       steps:
         - uses: actions/checkout@v4
         
         - name: Install Rust
           uses: actions-rs/toolchain@v1
           with:
             profile: minimal
             toolchain: stable
             override: true
         
         - name: Install build dependencies
           run: |
             sudo apt-get update
             sudo apt-get install -y clang llvm libelf-dev linux-headers-$(uname -r)
         
         - name: Cache cargo
           uses: actions/cache@v3
           with:
             path: |
               ~/.cargo/registry
               ~/.cargo/git
               target
             key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}
         
         - name: Install tarpaulin
           run: cargo install cargo-tarpaulin
         
         - name: Run coverage
           run: cargo tarpaulin --all-features --workspace --timeout 120 --out Xml
         
         - name: Upload coverage
           uses: codecov/codecov-action@v3
           with:
             file: ./coverage/cobertura.xml
   
     docs:
       name: Documentation
       runs-on: ubuntu-latest
       needs: test
       steps:
         - uses: actions/checkout@v4
         
         - name: Install Rust
           uses: actions-rs/toolchain@v1
           with:
             profile: minimal
             toolchain: stable
             override: true
         
         - name: Cache cargo
           uses: actions/cache@v3
           with:
             path: |
               ~/.cargo/registry
               ~/.cargo/git
             key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}
         
         - name: Build documentation
           run: cargo doc --all-features --no-deps
         
         - name: Deploy documentation
           uses: peaceiris/actions-gh-pages@v3
           with:
             github_token: ${{ secrets.GITHUB_TOKEN }}
             publish_dir: ./target/doc
   
     release:
       name: Release
       runs-on: ubuntu-latest
       needs: [test, coverage, docs]
       if: github.ref == 'refs/heads/main'
       steps:
         - uses: actions/checkout@v4
         
         - name: Install Rust
           uses: actions-rs/toolchain@v1
           with:
             profile: minimal
             toolchain: stable
             override: true
         
         - name: Install build dependencies
           run: |
             sudo apt-get update
             sudo apt-get install -y clang llvm libelf-dev linux-headers-$(uname -r)
         
         - name: Cache cargo
           uses: actions/cache@v3
           with:
             path: |
               ~/.cargo/registry
               ~/.cargo/git
               target
             key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}
         
         - name: Build release
           run: cargo build --release --workspace --all-features
         
         - name: Create release artifacts
           run: |
             mkdir -p release
             cp target/release/panhandle release/
             cp files/config.yaml release/
             cp files/panhandle.service release/
             cp files/panhandle.man release/
             cp README.md release/
             cp CHANGELOG.md release/
             tar -czvf release/panhandle-$(grep version panhandle/panhandle/Cargo.toml | head -1 | awk -F: '{ print $2 }' | sed 's/[" ]//g').tar.gz -C release .
         
         - name: Upload release
           uses: softprops/action-gh-release@v1
           with:
             files: release/*.tar.gz
             draft: true
   ```
3. Add workflow dispatch for manual runs
4. Add concurrency control to prevent duplicate runs
5. Add artifacts retention
6. Document CI workflow

**Validation**:
- Verify workflow runs successfully
- Check all jobs complete
- Test with pull requests
- Verify release creation

---

#### Task 8.2.2: Add GitLab CI Configuration
**Priority**: 🟢 Medium
**Effort**: 4-8 hours
**Dependencies**: Task 8.2.1
**Files Affected**: `.gitlab-ci.yml`

**Implementation Steps**:
1. Review current GitLab CI configuration
2. Update configuration to match GitHub Actions:
   ```yaml
   stages:
     - build
     - test
     - coverage
     - docs
     - release
   
   variables:
     CARGO_TERM_COLOR: always
     RUSTFLAGS: -Dwarnings
   
   cache:
     key: ${CI_COMMIT_REF_SLUG}
     paths:
       - ~/.cargo/registry
       - ~/.cargo/git
       - target
   
   build:
     stage: build
     image: rust:latest
     before_script:
       - apt-get update -y
       - apt-get install -y clang llvm libelf-dev linux-headers-amd64
     script:
       - cargo build --workspace --all-targets --all-features
       - cargo build --package panhandle-ebpf --release
     artifacts:
       paths:
         - target/
       expire_in: 1 week
   
   test:
     stage: test
     image: rust:latest
     before_script:
       - apt-get update -y
       - apt-get install -y clang llvm libelf-dev linux-headers-amd64
     script:
       - cargo test --workspace --all-features
       - cargo clippy --workspace --all-features --all-targets -- -D warnings
       - cargo fmt --all -- --check
       - cargo audit
   
   coverage:
     stage: coverage
     image: rust:latest
     before_script:
       - apt-get update -y
       - apt-get install -y clang llvm libelf-dev linux-headers-amd64
       - cargo install cargo-tarpaulin
     script:
       - cargo tarpaulin --all-features --workspace --timeout 120 --out Xml
     artifacts:
       reports:
         cobertura: coverage/cobertura.xml
   
   docs:
     stage: docs
     image: rust:latest
     script:
       - cargo doc --all-features --no-deps
     artifacts:
       paths:
         - target/doc/
       expire_in: 1 week
   
   release:
     stage: release
     image: rust:latest
     only:
       - main
     before_script:
       - apt-get update -y
       - apt-get install -y clang llvm libelf-dev linux-headers-amd64
     script:
       - cargo build --release --workspace --all-features
       - mkdir -p release
       - cp target/release/panhandle release/
       - cp files/config.yaml release/
       - cp files/panhandle.service release/
       - cp README.md release/
       - cp CHANGELOG.md release/
       - tar -czvf release/panhandle-$(grep version panhandle/panhandle/Cargo.toml | head -1 | awk -F: '{ print $2 }' | sed 's/[" ]//g').tar.gz -C release .
     artifacts:
       paths:
         - release/
       expire_in: never
   ```
3. Test GitLab CI configuration
4. Document GitLab CI setup

**Validation**:
- Verify GitLab CI runs successfully
- Check all stages complete
- Test with merge requests

---

### 8.3 Project Metadata

#### Task 8.3.1: Update Changelog
**Priority**: 🟢 Medium
**Effort**: 2-4 hours
**Dependencies**: None
**Files Affected**: `CHANGELOG.md`

**Implementation Steps**:
1. Review current changelog format
2. Adopt standard changelog format:
   ```markdown
   # Changelog
   
   All notable changes to this project will be documented in this file.
   
   The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
   and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
   
   ## [Unreleased]
   
   ### Added
   - Description of new feature
   
   ### Changed
   - Description of changed feature
   
   ### Fixed
   - Description of bug fix
   
   ### Deprecated
   - Description of deprecated feature
   
   ### Removed
   - Description of removed feature
   
   ### Security
   - Description of security fix
   
   ## [1.0.10] - 2026-06-16
   
   ### Added
   - Added CPU usage monitoring
   
   ## [1.0.9] - 2026-06-15
   
   ### Added
   - Added monitoring for sockets and memory paging
   ```
3. Add all missing releases:
   - v1.0.8
   - v1.0.7
   - v1.0.6
   - v1.0.5
   - v1.0.4
   - v1.0.3
4. Add detailed descriptions for each change
5. Add links to related issues or pull requests
6. Add release dates
7. Add [Unreleased] section for upcoming changes
8. Document changelog update process

**Validation**:
- Verify all releases are documented
- Check that format is consistent
- Ensure all changes are included

---

#### Task 8.3.2: Update SBOM
**Priority**: 🟢 Medium
**Effort**: 4-8 hours
**Dependencies**: Task 8.1.1
**Files Affected**: `panhandle-sbom.spdx`

**Implementation Steps**:
1. Review current SBOM format
2. Update SBOM generation:
   - Use `cargo-license` to generate license information
   - Use `cargo-audit` to generate vulnerability information
   - Use standard SPDX format
3. Automate SBOM generation:
   ```rust
   // build.rs
   fn generate_sbom() {
       use std::process::Command;
       
       // Generate license information
       let output = Command::new("cargo")
           .args(&["license"])
           .output()
           .expect("Failed to run cargo license");
       
       // Generate dependency tree
       let output = Command::new("cargo")
           .args(&["tree", "--prefix", "none"])
           .output()
           .expect("Failed to run cargo tree");
       
       // Generate SPDX SBOM
       // ...
       
       std::fs::write("target/panhandle-sbom.spdx", sbom_content).unwrap();
       println!("cargo:rerun-if-changed=build.rs");
   }
   ```
4. Update SBOM in RPM build:
   ```toml
   [package.metadata.generate-rpm]
   # ... existing assets
   { source = "target/panhandle-sbom.spdx", dest = "/usr/share/doc/panhandle/SBOM.spdx", mode = "644" },
   ```
5. Document SBOM update process
6. Add SBOM validation to CI

**Validation**:
- Verify SBOM is generated correctly
- Check that all dependencies are included
- Ensure SBOM is valid SPDX format

---

## 9. User Experience Tasks 🟢

### 9.1 CLI Improvements

#### Task 9.1.1: Restructure CLI with Subcommands
**Priority**: 🟢 Medium
**Effort**: 16-24 hours
**Dependencies**: None
**Files Affected**: `panhandle/src/input_configs.rs`, `panhandle/src/main.rs`

**Implementation Steps**:
1. Analyze current CLI structure:
   - Flat structure with many flags
   - Some argument conflicts possible
   - Hard to discover related options
2. Design new subcommand structure:
   ```
   panhandle [OPTIONS] <COMMAND>
   
   Commands:
     monitor    Monitor system activity
     config    Manage configuration
     version   Show version information
     help      Show help information
   
   Monitor Subcommands:
     panhandle monitor execve [OPTIONS]    Monitor execve syscalls
     panhandle monitor bash [OPTIONS]      Monitor bash shell
     panhandle monitor zsh [OPTIONS]       Monitor zsh shell
     panhandle monitor cpu [OPTIONS]       Monitor CPU usage
     panhandle monitor memory [OPTIONS]    Monitor memory usage
     panhandle monitor network [OPTIONS]   Monitor network usage
     panhandle monitor all [OPTIONS]       Monitor all activity
   
   Config Subcommands:
     panhandle config generate [OPTIONS]   Generate configuration file
     panhandle config validate [OPTIONS]   Validate configuration file
     panhandle config show [OPTIONS]       Show current configuration
   ```
3. Implement new CLI structure:
   ```rust
   #[derive(Subcommand)]
   enum Command {
       /// Monitor system activity
       Monitor(MonitorCommand),
       /// Manage configuration
       Config(ConfigCommand),
       /// Show version information
       Version,
   }
   
   #[derive(Subcommand)]
   enum MonitorCommand {
       /// Monitor execve syscalls
       Execve(ExecveArgs),
       /// Monitor bash shell
       Bash(BashArgs),
       /// Monitor zsh shell
       Zsh(ZshArgs),
       /// Monitor CPU usage
       Cpu(CpuArgs),
       /// Monitor memory usage
       Memory(MemoryArgs),
       /// Monitor network usage
       Network(NetworkArgs),
       /// Monitor all activity
       All(AllArgs),
   }
   ```
4. Implement argument merging for subcommands:
   - Common options (output, filtering, etc.)
   - Monitor-specific options
5. Update help text for new structure
6. Add examples for new CLI
7. Maintain backward compatibility (if possible)
8. Document new CLI structure

**Validation**:
- Verify all subcommands work
- Test argument merging
- Check help text
- Ensure backward compatibility

---

#### Task 9.1.2: Add Shell Completion Support
**Priority**: 🟢 Medium
**Effort**: 4-8 hours
**Dependencies**: Task 9.1.1
**Files Affected**: `panhandle/src/input_configs.rs`

**Implementation Steps**:
1. Add clap_complete dependency:
   ```toml
   [build-dependencies]
   clap_complete = "4.6"
   ```
2. Add completion generation to build.rs:
   ```rust
   use clap_complete::{generate_to, Shell};
   use std::env;
   
   fn main() {
       // ... existing code
       
       // Generate completions
       if let Ok(shell) = env::var("COMPLETION_SHELL") {
           let out_dir = match env::var_os("OUT_DIR") {
               Some(out_dir) => out_dir,
               None => return,
           };
           
           let mut cmd = RawArgs::command();
           
           match shell.as_str() {
               "bash" => generate_to(Shell::Bash, &mut cmd, "panhandle", &out_dir).unwrap(),
               "zsh" => generate_to(Shell::Zsh, &mut cmd, "panhandle", &out_dir).unwrap(),
               "fish" => generate_to(Shell::Fish, &mut cmd, "panhandle", &out_dir).unwrap(),
               "powershell" => generate_to(Shell::PowerShell, &mut cmd, "panhandle", &out_dir).unwrap(),
               "elvish" => generate_to(Shell::Elvish, &mut cmd, "panhandle", &out_dir).unwrap(),
               _ => {}
           }
       }
   }
   ```
3. Add completion generation script:
   ```bash
   #!/bin/bash
   # scripts/generate-completions.sh
   
   COMPLETIONS_DIR="./completions"
   mkdir -p "$COMPLETIONS_DIR"
   
   # Bash
   cargo run --features completions --bin panhandle -- --generate-completions bash > "$COMPLETIONS_DIR/panhandle.bash"
   
   # Zsh
   cargo run --features completions --bin panhandle -- --generate-completions zsh > "$COMPLETIONS_DIR/_panhandle"
   
   # Fish
   cargo run --features completions --bin panhandle -- --generate-completions fish > "$COMPLETIONS_DIR/panhandle.fish"
   ```
4. Add completion feature flag:
   ```toml
   [features]
   completions = ["clap_complete"]
   ```
5. Document shell completion installation:
   - Bash: source completions/panhandle.bash
   - Zsh: copy _panhandle to ~/.zsh/completion/
   - Fish: copy panhandle.fish to ~/.config/fish/completions/

**Validation**:
- Generate completions for all shells
- Test completions work
- Verify completion scripts are correct

---

### 9.2 Output Improvements

#### Task 9.2.1: Enhance Verbose Output
**Priority**: 🟢 Medium
**Effort**: 4-8 hours
**Dependencies**: None
**Files Affected**: All source files (especially main.rs, helpers.rs)

**Implementation Steps**:
1. Add more detailed verbose logging:
   - Startup information (version, configuration, environment)
   - eBPF program loading and attachment
   - Map information
   - Monitoring status
   - Performance statistics
2. Add timing information to verbose output:
   ```rust
   use std::time::Instant;
   
   let start = Instant::now();
   // ... operation
   let duration = start.elapsed();
   debug!("Operation completed in {:?}", duration);
   ```
3. Add progress indicators for long operations:
   ```rust
   use indicatif::ProgressBar;
   
   let pb = ProgressBar::new(100);
   for i in 0..100 {
       // ... do work
       pb.inc(1);
   }
   pb.finish_with_message("Done");
   ```
4. Add configuration summary at startup:
   ```rust
   if args.verbose {
       info!("Panhandle v{}", env!("CARGO_PKG_VERSION"));
       info!("Configuration:");
       info!("  Monitoring: {:?}", get_monitoring_types(&args));
       info!("  Output: {:?}", get_output_types(&args));
       info!("  Filters: {:?}", get_filters(&args));
       info!("  Poll interval: {}s", args.poll.unwrap_or(30));
       // ... more configuration
   }
   ```
5. Add performance statistics at shutdown:
   ```rust
   let uptime = start_time.elapsed();
   let events_processed = event_counter.load(Ordering::SeqCst);
   let events_per_second = events_processed as f64 / uptime.as_secs_f64();
   
   info!("Shutting down...");
   info!("Uptime: {:?}", uptime);
   info!("Events processed: {}", events_processed);
   info!("Events per second: {:.2}", events_per_second);
   ```
6. Add debug output for troubleshooting:
   - eBPF map contents
   - Process information
   - Network connection details

**Validation**:
- Test verbose output with various configurations
- Verify all important information is logged
- Check that output is not too verbose

---

#### Task 9.2.2: Add Progress Feedback
**Priority**: 🟢 Medium
**Effort**: 4-8 hours
**Dependencies**: Task 9.2.1
**Files Affected**: All source files

**Implementation Steps**:
1. Add progress indicators for long operations:
   - eBPF program loading
   - Map initialization
   - Configuration loading
   - Process scanning
2. Use indicatif crate for progress bars:
   ```toml
   [dependencies]
   indicatif = "0.17"
   ```
3. Add progress bars to slow operations:
   ```rust
   use indicatif::ProgressBar;
   
   // In main.rs, during eBPF loading
   let pb = ProgressBar::new_spinner();
   pb.set_message("Loading eBPF programs...");
   
   let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
       env!("OUT_DIR"),
       "/panhandle"
   )))?;
   
   pb.finish_with_message("eBPF programs loaded");
   ```
4. Add progress for process scanning:
   ```rust
   // In procfs_helpers.rs
   let pb = ProgressBar::new(all_processes().unwrap().count() as u64);
   pb.set_message("Scanning processes...");
   
   for proc_res in all_processes().unwrap().flatten() {
       // ... process
       pb.inc(1);
   }
   
   pb.finish_with_message("Process scan complete");
   ```
5. Add progress for monitoring initialization:
   - CPU monitoring setup
   - Network monitoring setup
   - Shell monitoring setup
6. Add option to disable progress bars (for non-interactive use)

**Validation**:
- Test progress bars with various operations
- Verify progress is accurate
- Check that progress bars don't interfere with output

---

### 9.3 Error Message Improvements

#### Task 9.3.1: Enhance Error Messages
**Priority**: 🟢 Medium
**Effort**: 8-12 hours
**Dependencies**: Task 1.2.1
**Files Affected**: All source files

**Implementation Steps**:
1. Add context to all error messages:
   - What operation failed
   - What was being processed
   - Suggested actions to resolve
2. Use anyhow for better error context:
   ```toml
   [dependencies]
   anyhow = "1.0"
   ```
3. Replace simple error messages with contextual ones:
   ```rust
   // Before:
   Err("Failed to load configuration".into())
   
   // After:
   Err(anyhow::anyhow!(
       "Failed to load configuration from '{}'. \
        Please check that the file exists and is valid YAML or JSON. \
        Error: {}",
       path,
       e
   ))
   ```
4. Add error codes for common errors:
   ```rust
   #[derive(Debug, thiserror::Error)]
   pub enum PanhandleError {
       #[error("Configuration error: {0}")]
       ConfigurationError(String),
       
       #[error("eBPF error: {0}")]
       EbpfError(String),
       
       #[error("Permission error: {0}")]
       PermissionError(String),
       
       #[error("I/O error: {0}")]
       IoError(#[from] std::io::Error),
       
       #[error("Network error: {0}")]
       NetworkError(String),
   }
   ```
5. Add error handling utilities:
   ```rust
   pub fn context_error<T, E: std::error::Error + 'static>(
       result: Result<T, E>,
       context: &str,
   ) -> Result<T, anyhow::Error> {
       result.map_err(|e| anyhow::anyhow!("{}: {}", context, e))
   }
   ```
6. Add user-friendly error messages:
   - Remove internal details from user-facing errors
   - Provide actionable suggestions
   - Include links to documentation
7. Add error logging for debugging:
   ```rust
   match some_operation() {
       Ok(result) => result,
       Err(e) => {
           error!("Operation failed: {:#?}", e);
           return Err(anyhow::anyhow!("Operation failed. See logs for details."));
       }
   }
   ```

**Validation**:
- Test error messages with various error scenarios
- Verify error messages are helpful
- Check that sensitive information is not exposed

---

## 10. Refactoring Tasks 🔵

### 10.1 Code Organization

#### Task 10.1.1: Split Large Source Files
**Priority**: 🔵 Low
**Effort**: 16-24 hours
**Dependencies**: None
**Files Affected**: `panhandle/src/helpers.rs`, `panhandle/src/main.rs`, `panhandle/src/input_configs.rs`

**Implementation Steps**:
1. Split helpers.rs into smaller modules:
   ```
   panhandle/src/helpers/
   ├── mod.rs
   ├── event_processing.rs    // consume_shell_ebpf_map, consume_execve_ebpf_map
   ├── output.rs              // send_http_post, send_syslog, output_message
   ├── validation.rs          // validate_syslog, validate_url
   ├── path_helpers.rs        // get_canonical_executable_list
   └── network.rs             // network-related helpers
   ```
2. Split main.rs into smaller modules:
   ```
   panhandle/src/
   ├── main.rs                // Main entry point, high-level logic
   ├── config.rs              // Configuration loading and merging
   ├── monitoring/
   │   ├── mod.rs
   │   ├── setup.rs           // Monitoring setup (eBPF programs, maps)
   │   ├── execve.rs          // Execve monitoring
   │   ├── shell.rs           // Shell monitoring (bash, zsh)
   │   ├── cpu.rs             // CPU monitoring
   │   ├── memory.rs          // Memory monitoring
   │   └── network.rs         // Network monitoring
   └── output/
       ├── mod.rs
       ├── file.rs            // File output
       ├── syslog.rs          // Syslog output
       └── http.rs            // HTTP output
   ```
3. Split input_configs.rs into smaller modules:
   ```
   panhandle/src/input_configs/
   ├── mod.rs
   ├── cli.rs                // CLI argument definitions
   ├── config.rs             // Configuration file loading
   ├── merging.rs            // Argument merging logic
   └── validation.rs         // Configuration validation
   ```
4. Update imports and module declarations
5. Update documentation for new modules
6. Ensure all tests still pass

**Validation**:
- Verify all modules compile correctly
- Check that all functionality is preserved
- Ensure tests still pass
- Verify code organization is improved

---

#### Task 10.1.2: Restructure Project Directory
**Priority**: 🔵 Low
**Effort**: 8-12 hours
**Dependencies**: None
**Files Affected**: All project files

**Implementation Steps**:
1. Current structure:
   ```
   /home/dmcgee/panhandle/panhandle/
   ├── Cargo.toml
   ├── panhandle/
   │   ├── Cargo.toml
   │   └── src/
   ├── panhandle-common/
   │   ├── Cargo.toml
   │   └── src/
   └── panhandle-ebpf/
       ├── Cargo.toml
       └── src/
   ```
2. Proposed structure:
   ```
   /home/dmcgee/panhandle/
   ├── Cargo.toml            // Workspace root
   ├── panhandle/            // Main binary crate
   │   ├── Cargo.toml
   │   ├── build.rs
   │   └── src/
   ├── panhandle-common/    // Common types and constants
   │   ├── Cargo.toml
   │   └── src/
   ├── panhandle-ebpf/      // eBPF programs
   │   ├── Cargo.toml
   │   ├── build.rs
   │   └── src/
   └── files/                // Configuration and deployment files
   ```
3. Move files to new locations:
   - Move `/panhandle/panhandle/Cargo.toml` to `/panhandle/panhandle/Cargo.toml`
   - Move `/panhandle/panhandle/src/` to `/panhandle/panhandle/src/`
   - Move `/panhandle/panhandle-ebpf/` to `/panhandle/panhandle-ebpf/`
   - Move `/panhandle/panhandle-common/` to `/panhandle/panhandle-common/`
4. Update workspace Cargo.toml:
   ```toml
   [workspace]
   resolver = "2"
   members = ["panhandle", "panhandle-common", "panhandle-ebpf"]
   default-members = ["panhandle"]
   ```
5. Update all file references:
   - build.rs files
   - CI configurations
   - Documentation
6. Update git repository structure
7. Test build with new structure

**Validation**:
- Verify build succeeds with new structure
- Check that all tests pass
- Ensure all functionality works
- Verify git history is preserved

---

### 10.2 Cleanup Tasks

#### Task 10.2.1: Clean Up Archive Directory
**Priority**: 🔵 Low
**Effort**: 2-4 hours
**Dependencies**: None
**Files Affected**: `archive/` directory

**Implementation Steps**:
1. Review contents of archive/ directory:
   - SLES-Basic-Containerfile
   - SLES-Containerfile.yaml
   - test_results/
2. For each file:
   - Determine if it's still needed
   - If needed, move to appropriate location
   - If not needed, document and remove
3. Create ARCHIVE.md to document historical files:
   ```markdown
   # Archive
   
   This directory contains historical files that are no longer actively maintained.
   
   ## Test Results
   - `test_results/` - Historical test results
     - `pav_test.md` - PAV test results
     - `Panhandle_Test_Plan.docx` - Original test plan
   
   ## SLES Configuration Files
   - `SLES-Basic-Containerfile` - Basic SLES build configuration (2023)
   - `SLES-Containerfile.yaml` - SLES build configuration (2023)
   
   ## Status
   These files are kept for historical reference but may be outdated.
   For current configurations, see the main project files.
   ```
4. Move valuable files to appropriate locations:
   - SLES configuration files to `files/` directory
   - Test plans to `docs/` directory
5. Remove or archive remaining files
6. Update .gitignore if needed

**Validation**:
- Verify no important files are lost
- Check that historical information is preserved
- Ensure repository size is reasonable

---

#### Task 10.2.2: Clean Up Test Configurations
**Priority**: 🔵 Low
**Effort**: 2-4 hours
**Dependencies**: None
**Files Affected**: `test-configs/` directory

**Implementation Steps**:
1. Review test configurations:
   - all-bools.yaml, all-bools.json
   - default.yaml, default.json
   - invalid.yaml, invalid.json
   - invalid.xml
   - non-bools.yaml, non-bools.json
2. Move test configurations to standard location:
   ```
   panhandle/tests/configs/
   ├── all-bools.yaml
   ├── all-bools.json
   ├── default.yaml
   ├── default.json
   ├── invalid.yaml
   ├── invalid.json
   ├── invalid.xml
   ├── non-bools.yaml
   └── non-bools.json
   ```
3. Update test files to use new paths:
   ```rust
   // Before:
   let config_path = "../../test-configs/default.yaml";
   
   // After:
   let config_path = "../tests/configs/default.yaml";
   ```
4. Update test-configs references in documentation
5. Remove old test-configs directory
6. Add new test configurations:
   - Edge cases
   - Error cases
   - Performance cases

**Validation**:
- Verify all tests still pass
- Check that all test configurations are accessible
- Ensure no broken references

---

## Summary

### Task Count by Priority

| Priority | Count | Estimated Effort |
|----------|-------|------------------|
| 🔴 Critical | 8 | 80-120 hours |
| 🟡 High | 30 | 300-400 hours |
| 🟢 Medium | 40 | 320-440 hours |
| 🔵 Low | 20 | 160-240 hours |
| **Total** | **98** | **860-1240 hours** |

### Recommended Implementation Order

1. **Critical Security Tasks** (1-2 weeks)
   - Add HTTPS/TLS support
   - Fix memory safety issues in eBPF
   - Address integer overflow potential
   - Fix TOCTOU issues
   - Implement proper resource cleanup
   - Replace unwrap() calls
   - Implement consistent panic handling

2. **High Priority Code Quality Tasks** (3-4 weeks)
   - Refactor consume_* functions
   - Eliminate magic numbers
   - Improve type safety
   - Remove unused code
   - Add comprehensive unit tests
   - Add integration tests
   - Add eBPF-specific tests
   - Add performance tests

3. **Documentation Tasks** (2-3 weeks)
   - Add comprehensive doc comments
   - Generate and publish API documentation
   - Create ARCHITECTURE.md
   - Create DESIGN.md
   - Create CONFIGURATION.md
   - Update man page
   - Create DEPLOYMENT.md
   - Update README.md
   - Create CONTRIBUTING.md
   - Create ROADMAP.md
   - Create SECURITY.md

4. **Performance Optimization Tasks** (1-2 weeks)
   - Optimize string formatting
   - Reduce memory allocations
   - Make buffer sizes configurable
   - Implement HTTP client pooling
   - Implement adaptive polling

5. **eBPF-Specific Tasks** (2-3 weeks)
   - Review and enhance unsafe blocks
   - Add eBPF verification
   - Add eBPF unit tests
   - Add eBPF integration tests
   - Add kernel version compatibility checks

6. **Configuration and Deployment Tasks** (2-3 weeks)
   - Define formal configuration schema
   - Add environment variable support
   - Add configuration reloading
   - Improve RPM packaging
   - Update SBOM

7. **Project Infrastructure Tasks** (1-2 weeks)
   - Update dependencies
   - Improve build configuration
   - Enhance GitHub Actions workflow
   - Add GitLab CI configuration
   - Update changelog

8. **User Experience Tasks** (1-2 weeks)
   - Restructure CLI with subcommands
   - Add shell completion support
   - Enhance verbose output
   - Add progress feedback
   - Enhance error messages

9. **Refactoring Tasks** (1-2 weeks)
   - Split large source files
   - Restructure project directory
   - Clean up archive directory
   - Clean up test configurations

### Milestone Recommendations

**Milestone 1: Critical Security (2 weeks)**
- All 🔴 Critical tasks
- Basic unit tests

**Milestone 2: Code Quality (4 weeks)**
- All 🟡 High priority code quality tasks
- Comprehensive testing
- Documentation updates

**Milestone 3: Production Ready (6 weeks)**
- All 🟡 High priority tasks
- Performance optimizations
- Complete documentation
- CI/CD improvements

**Milestone 4: Enhancements (4 weeks)**
- All 🟢 Medium priority tasks
- User experience improvements
- Additional features

---

## Next Steps

1. **Review and Prioritize**: Review this task list with the team and adjust priorities as needed.

2. **Assign Tasks**: Assign tasks to team members based on expertise and availability.

3. **Create Issues**: Create GitHub/GitLab issues for each task or group of related tasks.

4. **Set Up Project Board**: Set up a project board to track progress on tasks.

5. **Start Implementation**: Begin with the highest priority tasks (Critical Security).

6. **Regular Reviews**: Conduct regular code reviews and task progress reviews.

7. **Update Documentation**: Keep this TODO.md and REVIEW.md up to date as tasks are completed.

---

## Maintenance

- Update this document as tasks are completed
- Add new tasks as they are identified
- Adjust priorities and estimates as needed
- Review and update the REVIEW.md document periodically
- Conduct regular code reviews to identify new issues

---

*This task list was created on June 16, 2026, based on the comprehensive review in REVIEW.md.*
