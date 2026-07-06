# Panhandle OpenCode Configuration Guide

## Overview

This guide provides comprehensive documentation for the OpenCode configuration tailored for the **panhandle** project - an eBPF-based user activity monitoring system for HPC environments.

## Configuration Structure

```
.opencode/
├── opencode.json          # Main OpenCode configuration
├── package.json          # Node.js and project metadata
├── README.md             # Configuration documentation
├── CHANGELOG.md          # Configuration changes history
├── CONFIGURATION_GUIDE.md # This guide
├── validate-config.sh    # Full validation script (color output)
├── validate-simple.sh    # Simple validation script
└── skills/
    ├── aya-ebpf/
    │   └── SKILL.md       # Aya eBPF expertise
    ├── hpc-monitoring/
    │   └── SKILL.md       # HPC monitoring patterns
    ├── panhandle/
    │   └── SKILL.md       # Project-specific conventions
    └── rust-ebpf/
        └── SKILL.md       # Rust eBPF patterns
```

## Quick Start

### Starting OpenCode

```bash
cd /home/dmcgee/panhandle
opencode
```

OpenCode will automatically load the configuration from `.opencode/opencode.json`.

### Validating Configuration

```bash
# Simple validation
./.opencode/validate-simple.sh

# Full validation with colors (requires bash 4+)
./.opencode/validate-config.sh
```

## Configuration Files

### 1. `opencode.json` - Main Configuration

The main configuration file contains all OpenCode settings for the panhandle project.

#### Key Sections:

**References:**
```json
{
  "references": {
    "panhandle": {
      "path": ".",
      "description": "Panhandle project - eBPF user activity monitoring for HPC"
    },
    "aya-github": {
      "path": "/home/dmcgee/.local/share/opencode/repos/github.com/aya-rs/aya",
      "description": "Official Aya library GitHub repository"
    }
  }
}
```

**Permissions:**
```json
{
  "permission": {
    "edit": "allow",
    "bash": {
      "cargo *": "allow",
      "git *": "allow",
      "make *": "allow",
      "rm -rf *": "deny",
      "sudo *": "deny",
      "*": "ask"
    },
    "external_directory": {
      "~/.cargo/**": "allow",
      "~/.rustup/**": "allow",
      "/usr/lib/**": "allow",
      "*": "ask"
    }
  }
}
```

**Tool Output:**
```json
{
  "tool_output": {
    "max_lines": 500,
    "max_bytes": 32768
  }
}
```

**Experimental:**
```json
{
  "experimental": {
    "primary_tools": ["edit", "read", "glob", "grep", "bash", "lsp_diagnostics"],
    "mcp_timeout": 120000
  }
}
```

### 2. `package.json` - Project Metadata and Configuration

Enhanced package.json with panhandle-specific configuration.

#### Key Sections:

**Project Paths:**
```json
{
  "panhandle": {
    "project_root": "/home/dmcgee/panhandle",
    "rust_workspace": "/home/dmcgee/panhandle/panhandle",
    "ebpf_sources": "/home/dmcgee/panhandle/panhandle/panhandle-ebpf/src",
    "common_sources": "/home/dmcgee/panhandle/panhandle/panhandle-common/src",
    "main_sources": "/home/dmcgee/panhandle/panhandle/panhandle/src",
    "test_directory": "/home/dmcgee/panhandle/panhandle/panhandle/tests",
    "config_directory": "/home/dmcgee/panhandle/panhandle",
    "build_artifacts": "/home/dmcgee/panhandle/rpmbuild",
    "test_configs": "/home/dmcgee/panhandle/test-configs",
    "scripts": "/home/dmcgee/panhandle/scripts",
    "files": "/home/dmcgee/panhandle/files"
  }
}
```

**OpenCode Configuration:**
```json
{
  "opencode": {
    "recommended_tools": [
      "edit", "read", "glob", "grep", "bash",
      "lsp_diagnostics", "codegraph_codegraph_explore",
      "codegraph_codegraph_callers", "lsp_symbols",
      "lsp_find_references", "lsp_goto_definition"
    ],
    "specialized_agents": [
      {
        "name": "aya-expert",
        "description": "Aya eBPF library expert",
        "skills": ["aya-ebpf"]
      },
      {
        "name": "panhandle-expert",
        "description": "Panhandle project expert",
        "skills": ["panhandle"]
      }
    ]
  }
}
```

## Permissions Configuration

### Bash Command Permissions

The bash permissions section controls which shell commands can be executed.

**Permission Levels:**
- `"allow"` - Command can always run
- `"deny"` - Command is always blocked
- `"ask"` - User must confirm before execution

**Allowed Commands:**

**Build Tools:**
- `cargo *` - All cargo operations
- `make *` - All make operations
- `rustc *` - Rust compiler

**Code Quality:**
- `clippy *` - Clippy linter
- `fmt *` - Code formatting
- `check *` - Code checking
- `audit *` - Security auditing

**Testing and Benchmarking:**
- `test *` - Test operations
- `bench *` - Benchmark operations
- `tarpaulin *` - Test coverage tool

**Documentation:**
- `doc *` - Documentation generation

**eBPF Tools:**
- `bpf-linker *` - eBPF compilation tool

**Text Processing:**
- `wc *` - Word count
- `sed *` - Stream editing
- `head *` - File header
- `tail *` - File tail

**Version Control:**
- `git *` - All git operations

**Denied Commands:**

**Dangerous Operations:**
- `rm -rf *` - Prevent mass deletion
- `:; *` - Prevent command chaining
- `sudo *` - Prevent privilege escalation

**System Operations:**
- `dd *` - Prevent disk operations
- `mkfs *` - Prevent filesystem creation
- `mv * /` - Prevent system directory modification
- `cp * /` - Prevent system directory copying

**Ask Mode Commands:**
- `* > *` - File redirection requires confirmation
- `* >> *` - File append requires confirmation
- `*` - All other commands require confirmation

### External Directory Permissions

Controls access to directories outside the project root.

**Allowed Paths:**

**User Directories:**
- `~/.cargo/**` - Cargo cache and configuration
- `~/.rustup/**` - Rust toolchain management
- `~/.local/share/opencode/**` - OpenCode repositories and data

**System Paths:**
- `/usr/lib/**` - System libraries
- `/usr/share/**` - Shared data
- `/usr/local/**` - Local software
- `/usr/bin/**` - System executables
- `/usr/include/**` - Header files

**Software Paths:**
- `/opt/**` - Optional software

**Panhandle-Specific Paths:**
- `/var/log/panhandle/**` - Panhandle logs
- `/etc/panhandle/**` - Panhandle configuration
- `/etc/logrotate.d/panhandle` - Logrotate configuration
- `/usr/lib/systemd/system/panhandle.service` - Systemd service

**Ask Mode Paths:**
- `*` - All other external directories require confirmation

## Skill Configuration

The skills directory contains domain-specific expertise for panhandle development.

### Available Skills

**1. `panhandle` Skill**
- **When to Use**: Working on panhandle codebase, following project conventions
- **Focus**: Project structure, build system, testing, deployment
- **File**: `.opencode/skills/panhandle/SKILL.md`

**2. `aya-ebpf` Skill**
- **When to Use**: Developing eBPF programs with Aya library
- **Focus**: Aya library APIs, eBPF program development, HPC monitoring patterns
- **File**: `.opencode/skills/aya-ebpf/SKILL.md`

**3. `rust-ebpf` Skill**
- **When to Use**: Writing Rust code for eBPF context
- **Focus**: Unsafe Rust patterns, FFI, memory safety, eBPF optimizations
- **File**: `.opencode/skills/rust-ebpf/SKILL.md`

**4. `hpc-monitoring` Skill**
- **When to Use**: Implementing monitoring for HPC environments
- **Focus**: HPC-specific patterns, performance considerations, deployment patterns
- **File**: `.opencode/skills/hpc-monitoring/SKILL.md`

### Using Skills

Skills can be loaded programmatically in tasks:

```javascript
task(category="deep", load_skills=["panhandle", "aya-ebpf"], prompt="Implement new eBPF monitoring feature")
```

Or manually through skill invocation:

```
skill(name="panhandle")
```

## Development Workflows

### General Development

1. **Start OpenCode**:
   ```bash
   cd /home/dmcgee/panhandle
   opencode
   ```

2. **Explore Codebase**:
   ```javascript
   codegraph_codegraph_explore(query="main.rs helpers.rs input_configs.rs")
   ```

3. **Make Changes**:
   - Edit files using `edit` tool
   - Load relevant skills for domain expertise
   - Use LSP tools for code navigation

4. **Test Changes**:
   ```bash
   cargo test
   cargo check
   ```

5. **Validate**:
   ```bash
   lsp_diagnostics(filePath="panhandle/src/main.rs")
   ```

### eBPF Development

1. **Load Aya Skill**:
   ```javascript
   skill(name="aya-ebpf")
   ```

2. **Explore eBPF Programs**:
   ```javascript
   codegraph_codegraph_explore(query="panhandle-ebpf")
   ```

3. **Consult GitHub**:
   - Use `aya-github` reference for latest Aya features
   - Research implementation patterns from official repository

4. **Build and Test**:
   ```bash
   cargo build --release
   cargo test --features bpf
   ```

### Research and Learning

1. **Use Librarian Agents**:
   ```javascript
   task(subagent_type="librarian", run_in_background=true, prompt="Find Aya tracepoint usage examples")
   ```

2. **Consult References**:
   - Access `aya-github` for real implementation examples
   - Check `panhandle` reference for project-specific patterns

3. **Review Code**:
   ```javascript
   task(subagent_type="oracle", prompt="Review this eBPF program for safety issues")
   ```

## Security Considerations

### Security Principles

1. **Principle of Least Privilege**: Only grant necessary permissions
2. **Defense in Depth**: Multiple layers of security (deny + ask mode)
3. **Explicit Configuration**: All accesses are explicitly configured
4. **Regular Auditing**: Review configuration regularly

### Security Features

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

### Security Validation

Run the validation scripts to ensure security configuration:

```bash
# Check that dangerous commands are blocked
./.opencode/validate-simple.sh | grep "denied"

# Check all security restrictions
./.opencode/validate-simple.sh | grep -E "(denied|Denied)"
```

## Troubleshooting

### Common Issues

**Permission Denied Errors:**
- **Cause**: Command or directory access is not configured
- **Solution**: Add the specific command or path to the allowed list

**Command Not Found:**
- **Cause**: Command is not in system PATH
- **Solution**: Use full path or install the command

**Reference Not Available:**
- **Cause**: Reference is not configured or path is incorrect
- **Solution**: Check reference configuration in `opencode.json`

**Timeout Issues:**
- **Cause**: Operation takes longer than configured timeout
- **Solution**: Adjust timeout settings in experimental section

### Debugging Tips

1. **Check OpenCode Logs**: Look for permission denial messages
2. **Use Ask Mode**: Understand what's being blocked
3. **Gradual Permission Addition**: Add permissions based on requirements
4. **Test Specific Workflows**: Identify missing accesses for your workflow

### Adding New Permissions

When new tools or paths are needed:

1. **Identify the Requirement**: What command or path is needed?
2. **Assess the Risk**: What's the security impact?
3. **Choose Permission Level**: allow, deny, or ask?
4. **Update Configuration**: Add to `opencode.json`
5. **Test**: Verify the new permission works
6. **Document**: Update CHANGELOG and documentation

**Example: Adding a new tool**

```json
{
  "permission": {
    "bash": {
      "new-tool *": "allow"
    }
  }
}
```

**Example: Adding a new path**

```json
{
  "permission": {
    "external_directory": {
      "/new/path/**": "allow"
    }
  }
}
```

## Validation and Testing

### Running Validation

```bash
# Simple validation (recommended)
./.opencode/validate-simple.sh

# Full validation with colors
./.opencode/validate-config.sh

# Check specific aspect
./.opencode/validate-simple.sh | grep "JSON"
```

### Validation Checks

The validation scripts check:
- JSON syntax validity
- Required file existence
- Property structure completeness
- Security restriction configuration
- Project path accessibility

### Testing Configuration

After making changes:

1. **Validate Syntax**: Ensure JSON files are valid
2. **Test Permissions**: Try the newly allowed commands
3. **Test Denials**: Ensure dangerous commands are still blocked
4. **Test Workflows**: Verify development workflows work
5. **Document Changes**: Update CHANGELOG and documentation

## Configuration Management

### Version Control

All configuration files are under version control. Changes should be:
- Documented in CHANGELOG.md
- Reviewed for security implications
- Tested before committing

### Updating Configuration

1. **Identify Changes**: What needs to be added or modified?
2. **Assess Impact**: How will this affect security and workflows?
3. **Make Changes**: Edit the appropriate configuration files
4. **Validate**: Run validation scripts to ensure correctness
5. **Test**: Test the changes with real workflows
6. **Document**: Update CHANGELOG and any relevant documentation
7. **Commit**: Commit changes with descriptive messages

### Rollback Procedure

If configuration changes cause issues:

1. **Identify the Issue**: What's not working?
2. **Check Recent Changes**: Review CHANGELOG for recent modifications
3. **Revert Changes**: Use git to revert problematic commits
4. **Test Rollback**: Ensure rollback resolves the issue
5. **Investigate**: Understand the root cause
6. **Fix**: Implement a better solution

## Advanced Configuration

### Custom Commands

Create custom commands in `package.json` scripts section:

```json
{
  "scripts": {
    "custom-command": "echo 'Custom command' && some-operation",
    "full-validation": "npm run validate && npm run test && npm run lint"
  }
}
```

### Environment-Specific Configuration

For different development environments, consider:
- Multiple configuration files with different permissions
- Environment variable-based configuration
- Platform-specific overrides

### Integration with CI/CD

Consider adding configuration validation to CI/CD pipelines:

```yaml
# .github/workflows/validate-config.yml
name: Validate OpenCode Configuration
on: [push, pull_request]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Validate configuration
        run: ./opencode/validate-simple.sh
```

## Resources

### Documentation
- [OpenCode Documentation](https://opencode.ai/docs)
- [Panhandle Project README](../README.md)
- [Aya Library Documentation](https://aya-rs.dev/)

### External References
- [Aya GitHub Repository](https://github.com/aya-rs/aya)
- [Linux eBPF Documentation](https://www.kernel.org/doc/html/latest/bpf/)
- [Rust Documentation](https://doc.rust-lang.org/)

### Community
- OpenCode Discord/Slack channels
- GitHub Issues and Discussions
- Rust eBPF Working Group

## Support

### Getting Help

1. **Documentation**: Check this guide and README.md
2. **Validation**: Run validation scripts to identify issues
3. **Community**: Ask in OpenCode or panhandle community channels
4. **Configuration**: Review current configuration for missing permissions

### Reporting Issues

When reporting configuration issues:
1. **Describe the Problem**: What's not working?
2. **Expected Behavior**: What should happen?
3. **Actual Behavior**: What actually happens?
4. **Configuration**: Share relevant configuration sections
5. **Environment**: OpenCode version, platform, etc.
6. **Steps to Reproduce**: How to reproduce the issue?

## Best Practices

### For Users
- Use the ask mode to understand what commands will run
- Review permission denials to understand security boundaries
- Suggest missing permissions through proper channels
- Keep configuration updated with new requirements

### For Maintainers
- Regularly review and audit configuration
- Document all changes in CHANGELOG
- Test configuration changes thoroughly
- Follow principle of least privilege
- Keep skills updated with latest project conventions

### For Security Reviewers
- Regularly audit configuration files
- Ensure sensitive paths are protected
- Review dangerous command permissions
- Test security restrictions
- Monitor for configuration drift

---

This configuration provides a comprehensive, secure foundation for panhandle development with OpenCode, balancing the need for development flexibility with robust security controls.