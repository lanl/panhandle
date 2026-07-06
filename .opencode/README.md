# Panhandle OpenCode Configuration v2.0

This directory contains the comprehensive OpenCode configuration tailored specifically for the **panhandle** project - an eBPF-based user activity monitoring system for HPC environments using the Aya library.

## Project Overview

**Panhandle** provides user activity monitoring for High Performance Computing systems with minimal performance impact, using:
- **Rust** programming language
- **Aya** library for eBPF development
- **eBPF** for kernel-level monitoring

## Configuration Files

### `opencode.json`
Main configuration file with:
- **Provider**: circe-keys with LANL models
- **References**: GitHub repositories and local project paths
- **Permissions**: Comprehensively configured for panhandle development
  - **Bash commands**: All cargo operations, git, make, rust tooling
  - **External directories**: Cargo cache, system paths, project directories
  - **Security restrictions**: Blocked dangerous commands (rm -rf, sudo, dd, etc.)
  - **Ask mode**: Unclassified commands require confirmation
- **Tool Output**: Increased limits for large files
- **Experimental**: Primary tools and extended timeouts

### `package.json`
Enhanced Node.js configuration with:
- **Project metadata**: Panhandle-specific paths and references
- **Validation scripts**: Comprehensive environment checking
- **Specialized agents**: Defined agent configurations for panhandle
- **Recommended tools**: LSP and code analysis tools

### Skills Directory
Domain-specific expertise:
- **`aya-ebpf`**: Aya library expertise and eBPF development patterns
- **`panhandle`**: Project conventions and development workflows
- **`rust-ebpf`**: Rust eBPF-specific patterns and safety
- **`hpc-monitoring`**: HPC-specific monitoring patterns and considerations

## Permissions Configuration

### Bash Command Permissions
**Allowed Commands:**
- `cargo *`: All cargo operations (build, check, test, bench, doc, audit, etc.)
- `git *`: All git operations
- `make *`: All make operations
- `rustc *`, `clippy *`, `fmt *`: Rust tooling
- `check *`, `build *`, `test *`, `bench *`, `doc *`: Specific operations
- `tarpaulin *`: Test coverage tool
- `bpf-linker *`: eBPF compilation tool

**Denied Commands:**
- `rm -rf *`: Prevent mass deletion
- `; *`: Prevent command chaining
- `sudo *`: Prevent privilege escalation
- `dd *`: Prevent disk operations
- `mkfs *`: Prevent filesystem creation
- `mv * /`, `cp * /`: Prevent system directory modification

**Ask Mode Commands:**
- `* > *`: File redirection requires confirmation
- `* >> *`: File append requires confirmation
- `*`: All other commands require confirmation

### External Directory Access
**Allowed Paths:**
- `~/.cargo/**`: Cargo cache and configuration
- `~/.rustup/**`: Rust toolchain management
- `~/.local/share/opencode/**`: OpenCode repositories and data
- `/usr/lib/**`, `/usr/share/**`, `/usr/local/**`, `/usr/bin/**`, `/usr/include/**`: System paths
- `/opt/**`: Optional software directory
- `/var/log/panhandle/**`: Panhandle log directory
- `/etc/panhandle/**`: Panhandle configuration
- `/etc/logrotate.d/panhandle`: Logrotate configuration
- `/usr/lib/systemd/system/panhandle.service`: Systemd service file

**Ask Mode Paths:**
- `*`: All other external directories require confirmation

## Project Paths

The configuration includes comprehensive access to all panhandle project directories:

**Workspace Roots:**
- `/home/dmcgee/panhandle` - Main project directory
- `/home/dmcgee/panhandle/panhandle` - Rust workspace

**Source Directories:**
- `/home/dmcgee/panhandle/panhandle/panhandle/src` - Main application
- `/home/dmcgee/panhandle/panhandle/panhandle-ebpf/src` - eBPF programs
- `/home/dmcgee/panhandle/panhandle/panhandle-common/src` - Shared code
- `/home/dmcgee/panhandle/panhandle/panhandle/tests` - Test suite

**Build and Output:**
- `/home/dmcgee/panhandle/panhandle/target` - Build artifacts
- `/home/dmcgee/panhandle/rpmbuild` - RPM packaging
- `/home/dmcgee/panhandle/files` - Packaging files

**Configuration and Documentation:**
- `/home/dmcgee/panhandle/test-configs` - Test configurations
- `/home/dmcgee/panhandle/scripts` - Utility scripts
- `/home/dmcgee/panhandle/.dist` - Distribution files
- `/home/dmcgee/panhandle/archive` - Archived results

## Usage

### Start OpenCode with Panhandle Configuration
```bash
cd /home/dmcgee/panhandle
opencode
```

### Use Custom Commands
```
# Get coding help with panhandle context
/code Implement HTTPS support for HTTP output

# Create implementation plan for critical tasks
/plan Add input validation and rate limiting

# Review code with eBPF safety focus
/review panhandle/src/helpers.rs

# Research Aya library from GitHub
/research Latest tracepoint APIs in aya-rs/aya

# Consult Aya expert for specific issues
/aya-help How to handle memory safety in eBPF programs

# Consult panhandle expert for project patterns
/panhandle How to add new monitoring features

# Consult HPC monitoring expert
/hpc-monitoring Best practices for minimal overhead monitoring
```

### Agent Specialization
- **Build Agent**: Uses panhandle-specific context for Rust/Aya development
- **Aya Expert**: Consult for latest Aya library features from GitHub
- **Review Agent**: Focuses on eBPF safety and HPC compatibility
- **Panhandle Expert**: Project conventions and development patterns
- **Rust eBPF Expert**: Rust-specific eBPF patterns and safety
- **HPC Expert**: HPC-specific monitoring patterns

### Recommended Workflows

**Development Workflow:**
1. Load project skill: `skill(name="panhandle")`
2. Explore codebase: `codegraph_codegraph_explore(query="main.rs helpers.rs")`
3. Make changes with appropriate agent and skills
4. Test changes: Use bash tools for cargo test
5. Verify with LSP: `lsp_diagnostics(filePath="path/to/modified.rs")`

**eBPF Development:**
1. Load aya-ebpf skill: `skill(name="aya-ebpf")`
2. Consult GitHub reference: Use `aya-github` reference
3. Explore eBPF programs: `codegraph_codegraph_explore(query="panhandle-ebpf")`
4. Test with bpf-linker and cargo

**Research and Learning:**
1. Use librarian agents for external documentation
2. Consult reference implementations from GitHub
3. Review Aya library changes and best practices

## References

### Integrated References (accessible via @ mentions)
- `aya-github`: Official Aya library GitHub (aya-rs/aya) at `/home/dmcgee/.local/share/opencode/repos/github.com/aya-rs/aya`
- `panhandle`: Local panhandle project at `/home/dmcgee/panhandle`

### External Resources
- [Aya GitHub](https://github.com/aya-rs/aya)
- [Aya Book](https://aya-rs.dev/book)
- [Linux eBPF Docs](https://www.kernel.org/doc/html/latest/bpf)
- [Panhandle README](../README.md)
- [Rust Documentation](https://doc.rust-lang.org/)

## RHEL Compatibility

This configuration is optimized for:
- **RHEL 8+** and compatible distributions (CentOS, Rocky, AlmaLinux, SLES)
- **Enterprise environments** with security restrictions
- **HPC clusters** with diverse kernel versions
- **Production monitoring** with reliability requirements

### RHEL-Specific Features:
- Enhanced system path access for RHEL directory structure
- Support for RPM packaging workflows
- Systemd service management integration
- Logrotate configuration support

## Security Considerations

The configuration includes multiple layers of security:

**Command Restrictions:**
- Dangerous commands are explicitly denied
- Unclassified commands require confirmation
- File system modifications are controlled

**Directory Access:**
- Only necessary system paths are allowed
- Project directories have full access
- External access requires confirmation

**Best Practices:**
- Always review suggested commands before execution
- Use the ask mode to understand what commands will run
- Regularly update configuration based on new requirements
- Document any security exceptions or overrides

## Validation and Testing

The package.json includes validation scripts:

```bash
# Validate configuration
npm run validate

# Run tests
npm run test

# Lint configuration
npm run lint

# Check RHEL compatibility
npm run check-rhel

# Check dependencies
npm run check-dependencies

# Full validation suite
npm run full-validation
```

## Customization

To modify the configuration:
1. Edit files in `.opencode/` directory
2. Update permissions based on new requirements
3. Add new references as needed
4. Test changes with panhandle-specific workflows
5. Document changes in this README

When adding new accesses:
1. **Principle of Least Privilege**: Only grant necessary permissions
2. **Documentation**: Update this README with new accesses
3. **Testing**: Verify new permissions work as expected
4. **Security Review**: Assess potential risks of new accesses

## Troubleshooting

### Common Issues
- **Permission Denied**: Add the specific command or path to the allowed list
- **Command Not Found**: Ensure the command is in the system PATH
- **Reference Not Available**: Add the reference to opencode.json
- **Timeout Issues**: Adjust timeout settings in experimental section

### Debugging Tips
1. Check OpenCode logs for permission denials
2. Use ask mode to understand what's being blocked
3. Gradually add permissions based on requirements
4. Test with specific workflows to identify missing accesses

## Notes

- All eBPF code should be reviewed for safety before production deployment
- Kernel compatibility must be considered for HPC environments
- Performance impact should be minimized for monitoring systems
- The Aya expert agent stays current with the latest GitHub developments
- Security is paramount - only necessary accesses should be granted

## Changelog

### v2.0.0
- Added comprehensive permission configuration
- Updated package.json with project metadata
- Enhanced README with detailed documentation
- Added GitHub reference to aya-rs/aya
- Increased tool output limits
- Added recommended tools and agents
- Improved security restrictions

### v1.0.0
- Initial configuration
- Basic permissions for cargo, git, make
- RHEL compatibility optimizations
