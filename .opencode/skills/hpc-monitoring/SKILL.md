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
- Optimizing for minimal performance impact
- Deploying monitoring on HPC clusters
- Handling diverse kernel versions across nodes

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

### User Activity Monitoring
- **Process Monitoring**: Track process creation, execution, termination
- **System Call Tracing**: Monitor syscalls for user activity
- **Network Monitoring**: Track network connections and traffic
- **File Access**: Monitor file opens, reads, writes, deletes
- **Resource Usage**: Track CPU, memory, I/O usage

### Event Types to Monitor
1. **Process Events**: execve, execveat, exit, fork, clone
2. **System Calls**: open, read, write, close, connect, accept
3. **Network Events**: socket creation, connections, data transfer
4. **File Events**: file operations, directory changes
5. **Resource Events**: CPU usage, memory allocation, I/O operations

## Panhandle-Specific Implementation

### Output Formatting
- **JSON Format**: Structured output for SIEM systems
- **Text Format**: Human-readable output for console
- **Multiple Outputs**: Support for HTTP, syslog, file, console
- **Batch Processing**: Efficient event batching for high volume

### Performance Optimization
- **Minimal Overhead**: eBPF programs should add <1% overhead
- **Efficient Data Structures**: Use appropriate map types
- **Batch Processing**: Reduce userspace-kernel transitions
- **Sampling**: Consider sampling for high-volume events

### Deployment Patterns
- **Systemd Service**: Integration with system management
- **RPM Packaging**: Distribution for RHEL-based systems
- **Configuration**: YAML-based configuration files
- **Log Rotation**: Integration with logrotate

## Configuration Management

### Configuration Files
- **Main Config**: `/opt/panhandle/panhandle.yaml`
- **Output Config**: Define outputs and their formats
- **Filter Config**: Event filtering rules
- **Performance Config**: Tuning parameters

### Example Configuration
```yaml
# panhandle.yaml example
outputs:
  - type: syslog
    format: json
    facility: local0
    level: info
  - type: file
    path: /var/log/panhandle/panhandle.log
    format: text
    max_size: 100MB
    max_files: 5

events:
  - type: process
    exec: true
    exit: true
  - type: syscall
    names: ["open", "read", "write", "connect"]

performance:
  batch_size: 100
  batch_timeout: 100ms
```

## Troubleshooting

### Common Issues
- **Verifier Errors**: Check eBPF program for safety violations
- **Permission Denied**: Check capabilities and permissions
- **Missing Events**: Verify program attachment points
- **Performance Impact**: Profile eBPF program overhead
- **Kernel Compatibility**: Check BTF and kernel features

### Debugging Tools
- **dmesg**: Check kernel logs for eBPF errors
- **bpftool**: Inspect loaded eBPF programs and maps
- **perf**: Profile eBPF program performance
- **strace**: Trace system calls for debugging

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
- Monitor for kernel updates
- Test with new kernel versions
- Update dependencies regularly
- Review security patches

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
