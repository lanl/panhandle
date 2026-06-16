# Panhandle OpenCode Configuration

This directory contains the OpenCode configuration tailored specifically for the **panhandle** project - an eBPF-based user activity monitoring system for HPC environments using the Aya library.

## Project Overview

**Panhandle** provides user activity monitoring for High Performance Computing systems with minimal performance impact, using:
- **Rust** programming language
- **Aya** library for eBPF development
- **eBPF** for kernel-level monitoring

## Configuration Files

### `opencode.json`
Main configuration file with:
- **Provider**: circe-keys with LANL models
- **Agents**: Specialized agents for panhandle development
  - `build`: Primary coding agent for Rust/Aya development
  - `plan`: Architecture and design planning
  - `review`: Code review with eBPF safety focus
  - `research`: Documentation and best practices research
  - `general`, `explore`, `scout`: Supporting agents
- **Commands**: Custom commands for panhandle workflow
  - `code`: Default coding command
  - `plan`: Create implementation plans
  - `review`: Safety-focused code review
  - `research`: Research eBPF and Aya topics
  - `aya-help`: Consult the Aya expert
- **References**: GitHub repositories and documentation
- **Permissions**: RHEL-optimized with cargo check support

### `agents/aya-expert.md`
Expert Aya eBPF agent with:
- Deep knowledge of aya-rs/aya GitHub repository
- Latest Aya library features and APIs
- Panhandle-specific monitoring expertise
- HPC environment considerations
- eBPF safety and reliability focus

### `package.json`
Node.js configuration for OpenCode plugins:
- RHEL-compatible dependencies
- Panhandle-specific metadata
- RHEL detection scripts

## RHEL-Specific Optimizations

### Permissions
- `cargo check *` allowed for all Rust agents
- `cargo *` allowed for build operations
- `git *` allowed for version control
- `make *` allowed for build systems
- Enhanced external directory access for RHEL paths

### Node Modules
- Optimized for RHEL enterprise environments
- @opencode-ai/plugin with RHEL detection
- Panhandle project metadata

## Usage

### Start OpenCode with Panhandle Configuration
```bash
cd /home/dmcgee/panhandle
opencode
```

### Use Custom Commands
```
# Get coding help
/code your request here

# Create implementation plan
/plan your feature idea

# Review code with eBPF focus
/review path/to/file.rs

# Research Aya library
/research how to use tracepoints in Aya

# Consult Aya expert
/aya-help how to monitor process execution with Aya
```

### Agent Specialization
- **Build Agent**: Uses panhandle-specific context for Rust/Aya development
- **Aya Expert**: Consult for latest Aya library features from GitHub
- **Review Agent**: Focuses on eBPF safety and HPC compatibility

## References

### Integrated References (accessible via @ mentions)
- `aya-github`: Official Aya library GitHub (aya-rs/aya)
- `aya-docs`: Aya Book and documentation
- `kernel-bpf-docs`: Linux kernel eBPF documentation
- `panhandle`: Local panhandle project

### External Resources
- [Aya GitHub](https://github.com/aya-rs/aya)
- [Aya Book](https://aya-rs.dev/book)
- [Linux eBPF Docs](https://www.kernel.org/doc/html/latest/bpf)
- [Panhandle README](../README.md)

## RHEL Compatibility

This configuration is optimized for:
- **RHEL 8+** and compatible distributions (CentOS, Rocky, AlmaLinux)
- **Enterprise environments** with security restrictions
- **HPC clusters** with diverse kernel versions
- **Production monitoring** with reliability requirements

## Customization

To modify the configuration:
1. Edit files in `.opencode/` directory
2. Restart OpenCode for changes to take effect
3. Test with panhandle-specific workflows

## Notes

- All eBPF code should be reviewed for safety before production deployment
- Kernel compatibility must be considered for HPC environments
- Performance impact should be minimized for monitoring systems
- The Aya expert agent stays current with the latest GitHub developments
