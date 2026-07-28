---
name: hpc-monitoring
description: Use when implementing user activity monitoring for HPC systems. Covers HPC-specific monitoring patterns, performance considerations, and panhandle project conventions.
license: MIT
---

# HPC Monitoring Skill for Panhandle

## When to Use
Use this skill when:
- Implementing monitoring for High Performance Computing environments
- Designing user activity tracking systems
- Optimizing for minimal performance impact (<1% overhead target)
- Deploying monitoring on HPC clusters
- Handling diverse kernel versions across nodes
- Resolving merge conflicts between monitoring branches

## Version Compatibility
**Current Target**: Aya v0.14.0 with synchronous PerfEventArray API  
**Minimum Kernel**: 4.3 (for PerfEventArray support)  
**Rust**: nightly + stable toolchains

## HPC Environment Considerations

### Cluster Characteristics
- **Scale**: Hundreds to thousands of nodes
- **Diversity**: Mixed hardware and kernel versions
- **Performance**: Low overhead is critical
- **Reliability**: High availability requirements
- **Security**: Multi-user environment considerations

### Kernel Version Compatibility
- **CO-RE (Compile Once, Run Everywhere)**: Use BTF for portability
- **Feature Detection**: Check for kernel features at runtime
- **Fallback Mechanisms**: Graceful degradation for older kernels
- **Version Testing**: Test on minimum supported kernel version

## Monitoring Patterns

### User Activity Monitoring (Updated for Aya v0.14.0)
- **Process Monitoring**: Track bash/zsh command execution via UProbe attachments
- **System Call Tracing**: Monitor sys_enter_execve via TracePoint
- **Network Monitoring**: Track TCP state transitions via BtfTracePoint
- **File Access**: Monitor file operations (implementation pending)
- **Resource Usage**: Track CPU, memory, I/O, GPU usage via procfs

### Event Types Currently Implemented
1. **Shell Commands**: bash readline, zsh zlentry via UProbe
2. **Process Execution**: sys_enter_execve via TracePoint
3. **Network State**: inet_sock_set_state via BtfTracePoint
4. **Resource Metrics**: CPU, memory, I/O, GPU via procfs polling

### Aya v0.14.0 Synchronous Processing
```rust
// Panhandle's current event processing pattern
use aya::maps::perf::{PerfEventArray, PerfEventArrayBuffer};

// 1. Get the perf event array map
let events = PerfEventArray::try_from(ebpf.take_map("events").unwrap())?;

// 2. Process events for each CPU
for cpu in online_cpus().unwrap() {
    let buf = events.open(cpu, Some(32))?;  // Returns PerfEventArrayBuffer
    
    // 3. Synchronous processing with for_each
    buf.for_each(|event| {
        match event {
            PerfEvent::Sample { head, tail } => {
                let bytes = [head.to_vec(), tail.to_vec()].concat();
                let ptr: *const EventType = bytes.as_ptr() as *const EventType;
                let data: &EventType = unsafe { &*ptr };
                // Process event...
            }
            PerfEvent::Lost { count } => {
                error!("Lost {} events", count);
            }
        }
    });
}
```

### Generic Event Processing (From Merge Resolution)
Panhandle now uses a unified approach for handling different event types:

```rust
pub fn consume_ebpf_map<T: EbpfEvent + Copy>(
    client: &Client,
    buf: PerfEventArrayBuffer<aya::maps::MapData>,
    executable_vec: Vec<String>,
    // ... other parameters
) {
    buf.for_each(|event| {
        let data: &T = parse_event(event);
        
        // Use trait methods for common operations
        if should_filter(data.get_filter_key(), &executable_vec) {
            return;
        }
        
        output_event(data);
    });
}
```

## Panhandle-Specific Implementation

### Output Formatting
- **JSON Format**: Structured output for SIEM systems
- **Text Format**: Human-readable output for console
- **Multiple Outputs**: Support for HTTP, syslog, file, console
- **Batch Processing**: Efficient event batching for high volume

### Performance Optimization
**Target**: <1% overhead on monitored systems

#### **Industry Benchmarks**
| Component | Overhead Target | Achieved |
|-----------|----------------|----------|
| eBPF Programs | <0.1% CPU | ✅ Verified |
|PerfEventArray Processing | <0.5% CPU | ✅ Verified |
| Userspace Processing | <0.5% CPU | ✅ Verified |
| **Total Target** | **<1%** | **✅ Achieved** |

#### **Efficient Data Structures**
**Map Type Selection Guide:**
```
HashMap:      Medium-sized datasets, O(1) access
PerCpuArray:  Per-CPU data, lock-free access
Array:        Fixed-size, indexed data, O(1) access
ProgramArray: Array of program file descriptors
RingBuf:      Large data streaming with userspace
```

**Panhandle Usage:**
- `HashMap<_, u32, [u32; UID_COUNT]>` for UID filtering lists
- `PerCpuArray<_, u64>` for CPU time tracking
- `Array<_, u8>` for configuration flags
- `PerfEventArray<_, Event>` for event streaming

#### **Batch Processing Techniques**
**Problem**: High volume of events → userspace kernel transitions → performance overhead  
**Solution**: Use efficient synchronous processing from Aya v0.14.0:

```rust
// ✅ GOOD: Synchronous processing with for_each
buf.for_each(|event| {
    // Process each event sequentially
    // No await, no async overhead
    process_event(event);
});

// ❌ AVOID: Async processing (not needed for Aya v0.14.0)
// while let Some(event) = buf.read_events().await {
//     process_event(event).await;
// }
```

#### **Sampling for High-Volume Events**
```rust
// Implementation pattern for sampling
const SAMPLE_RATE: usize = 10;  // Sample 1 in 10 events
static COUNTER: AtomicUsize = AtomicUsize::new(0);

buf.for_each(|event| {
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    if count % SAMPLE_RATE == 0 {
        process_event(event);
    }
});
```

**Note**: Panhandle currently processes all events (no sampling) for comprehensive monitoring. Sampling can be added as a feature flag for extremely high-volume environments.

### Deployment Patterns
- **Systemd Service**: Integration with system management
- **RPM Packaging**: Distribution for RHEL-based systems
- **Configuration**: YAML-based configuration files
- **Log Rotation**: Integration with logrotate

## Configuration Management

### Configuration Files
- **Main Config**: Relative path `panhandle/panhandle.yaml` or `/opt/panhandle/panhandle.yaml`
- **Output Config**: Define outputs and their formats
- **Filter Config**: Event filtering rules
- **Performance Config**: Tuning parameters

### Example Configuration (Updated)
```yaml
# panhandle.yaml - All paths can be relative or absolute
outputs:
   - type: syslog
     format: json
     address: /dev/log  # or unix:///dev/log
     facility: local0
     level: info
   - type: file
     path: ./logs/panhandle.log  # Relative path recommended
     format: text
     max_size: 100MB
     max_files: 5
   - type: http
     url: https://siem.example.com/api/events
     use_https: true

events:
   bash: true              # Monitor bash commands
   zsh: true               # Monitor zsh commands
   syscall_execve: true    # Monitor process executions
   socket: true            # Monitor network state changes
   cpu: true               # Monitor CPU usage
   memory: true            # Monitor memory usage
   io: true                # Monitor I/O usage
   gpu: true               # Monitor GPU usage

filters:
   exclude_min_uid: 1      # Minimum UID to monitor
   exclude_max_uid: 999    # Maximum UID to monitor
   executable_include: ["/bin/bash", "/bin/zsh"]  # Only monitor these

performance:
   poll_interval: 10       # Seconds between polling cycles
   use_json: true          # JSON output format
```

### Configuration Best Practices
1. **Use Relative Paths** for portability across systems
2. **Environment-Specific Overrides** via environment variables
3. **Validation** on startup to catch errors early
4. **Hot Reload** support for configuration changes without restart

## Troubleshooting

### Common Issues
- **Verifier Errors**: Check eBPF program for safety violations
- **Permission Denied**: Check capabilities and permissions
- **Missing Events**: Verify program attachment points
- **Performance Impact**: Profile eBPF program overhead
- **Kernel Compatibility**: Check BTF and kernel features

### Debugging Tools
- **dmesg**: Check kernel logs for eBPF verifier errors
- **bpftool**: Inspect loaded eBPF programs, maps, and attachments
  - `bpftool prog show` - List loaded programs
  - `bpftool map show` - List loaded maps
  - `bpftool cgroup show` - Show cgroup attachments
- **perf**: Profile eBPF program performance
  - `perf event -t bpftrace:*` - Monitor eBPF events
- **strace**: Trace system calls for userspace debugging
- **RUST_LOG=debug**: Enable debug logging for userspace errors

### Aya v0.14.0 Specific Debugging
```bash
# Check Aya synchronization
RUST_LOG=aya=debug cargo run --release

# Monitor PerfEventArray operations
RUST_LOG=aya::maps::perf=debug cargo run --release

# Verify eBPF program loading
bpftool prog | grep panhandle

# Check map sizes and types
bpftool map | grep panhandle
```

## Aya Version Compatibility & Merge Resolution

### Version-Specific Patterns
**Current**: Aya v0.14.0 with synchronous PerfEventArray API

#### **API Evolution**
| Feature | Aya v0.13.x | Aya v0.14.0 | Migration Path |
|---------|-------------|-------------|----------------|
| PerfEventArray | Async | Synchronous | Replace `.read_events().await` with `.for_each()` |
| UProbe.attach() | 4 parameters | 3 parameters + scope | Use `UProbeScope::AllProcesses` |
| Btf availability | Optional | Required for BTF programs | Use BTF features from aya-github reference |

#### **Merge Resolution Patterns from Main + opcode-tailoring**
**Problem**: Main branch used async API, opencode-tailoring used sync API  
**Solution**: Standardized on Aya v0.14.0 synchronous API  
**Key Files Modified:**
- `panhandle/src/helpers.rs` - Use synchronous PerfEventArrayBuffer
- `panhandle/src/main.rs` - Import PerfEventArray, fix attach() calls
- `panhandle-ebpf/build.rs` - Add PathBuf import
- `panhandle-ebpf/src/*` - Use ctx.ret() safely

**Pattern for Future Merges:**
```rust
// ✅ Check Aya version at compile time
#[cfg(aya_version = "0.14")]
use aya::maps::perf::PerfEventArrayBuffer;

#[cfg(aya_version = "0.13")]  
use aya::maps::perf::AsyncPerfEventArrayBuffer;

// ✅ Conditional compilation for API differences
#[cfg(aya_version = "0.14")]
fn process_events(buf: PerfEventArrayBuffer<_>) {
    buf.for_each(|event| { /* sync processing */ })
}

#[cfg(aya_version = "0.13")]
async fn process_events(buf: AsyncPerfEventArrayBuffer<_>) {
    while let Some(event) = buf.read_events().await {
        // async processing
    }
}
```

### Version Compatibility Matrix
| Kernel Version | Aya Version | panhandle Support | Notes |
|----------------|-------------|-------------------|-------|
| 4.3+ | v0.13.x | ⚠️ Partial | May need async API |
| 4.3+ | v0.14.0 | ✅ Full | Current target |
| 5.0+ | v0.15.x | 🔄 Future | Migration planned |

## Security Considerations

### Multi-User Environment
- **Isolation**: Ensure monitoring doesn't affect other users
- **Privacy**: Respect user privacy and data protection
- **Permissions**: Use appropriate Linux capabilities
- **Audit**: Log monitoring activities for accountability

### Data Protection
- **Sensitive Data**: Avoid capturing sensitive information
- **Data Minimization**: Only collect necessary data
- **Access Control**: Restrict access to monitoring data
- **Encryption**: Encrypt data in transit and at rest

### Linux Capabilities for HPC
Recommended capabilities for panhandle:
```bash
# Check current capabilities
capsh --print

# Required capabilities
CAP_SYS_ADMIN      # For eBPF program loading
CAP_BPF           # For eBPF operations (if available)
CAP_PERFMON       # For performance monitoring
CAP_DAC_READ_SEARCH # For reading procfs

# Grant capabilities via systemd
[Service]
AmbientCapabilities=CAP_SYS_ADMIN CAP_PERFMON CAP_DAC_READ_SEARCH
```

## Best Practices

### Development
- Test on non-production systems first
- Use comprehensive logging for debugging
- Implement proper error handling
- Write automated tests

### Deployment
- Test on representative HPC systems
- Monitor performance impact
- Implement rollback procedures
- Document configuration changes

### Maintenance
- Monitor for kernel updates (especially new LTS releases)
- Test with new kernel versions in staging environment
- Update dependencies regularly (cargo update)
- Review security patches and CVEs
- Monitor Aya library releases for new features

### Kernel Compatibility Testing
Panhandle should be tested on:
- **RHEL 8**: Kernel 4.18+ with backported eBPF features
- **RHEL 9**: Kernel 5.14+ with full BTF support
- **RHEL 10**: Kernel 6.x+ (future)
- **SLES**: Latest supported versions
- **Ubuntu**: Latest LTS releases

**Compatibility Test Matrix:**
```bash
# Test on multiple kernel versions using containers
podman run --rm -it --privileged \
    -v $(pwd):/panhandle:Z \
    quay.io/centos/centos:stream9 \
    /bin/bash -c 'cd /panhandle && cargo build --release'

# Test kernel compatibility
uname -r  # Check kernel version
ls /sys/kernel/btf/vmlinux  # Check BTF availability
```

## Resources

### HPC Resources
- [OpenHPC](https://openhpc.community/)
- [Linux HPC Documentation](https://www.kernel.org/doc/)
- [Slurm Workload Manager](https://slurm.schedmd.com/)

### Monitoring Resources
- [Prometheus](https://prometheus.io/)
- [Grafana](https://grafana.com/)
- [ELK Stack](https://www.elastic.co/what-is/elk-stack)

### Panhandle Resources
- [Panhandle README](../README.md)
- [Panhandle Architecture](docs/architecture.md)
- [Panhandle Configuration Guide](docs/configuration.md)
