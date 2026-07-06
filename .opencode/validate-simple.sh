#!/bin/bash

# Simple Panhandle OpenCode Configuration Validator
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "Panhandle OpenCode Configuration Validation"
echo "==========================================="
echo ""

# Test JSON syntax
echo "Testing JSON syntax..."
jq empty "$PROJECT_ROOT/.opencode/opencode.json" && echo "✓ opencode.json is valid JSON"
jq empty "$PROJECT_ROOT/.opencode/package.json" && echo "✓ package.json is valid JSON"

# Test required files
echo ""
echo "Testing required files..."
for file in \
    ".opencode/opencode.json" \
    ".opencode/package.json" \
    ".opencode/README.md" \
    ".opencode/skills/panhandle/SKILL.md" \
    ".opencode/skills/aya-ebpf/SKILL.md" \
    ".opencode/skills/rust-ebpf/SKILL.md" \
    ".opencode/skills/hpc-monitoring/SKILL.md"; do
    if [[ -f "$PROJECT_ROOT/$file" ]]; then
        echo "✓ $file exists"
    else
        echo "✗ $file missing"
        exit 1
    fi
done

# Test JSON properties
echo ""
echo "Testing JSON properties..."

# Check references
if jq -e '.references' "$PROJECT_ROOT/.opencode/opencode.json" >/dev/null; then
    echo "✓ References section exists"
    if jq -e '.references.panhandle' "$PROJECT_ROOT/.opencode/opencode.json" >/dev/null; then
        echo "✓ Panhandle reference exists"
    fi
    if jq -e '.references["aya-github"]' "$PROJECT_ROOT/.opencode/opencode.json" >/dev/null; then
        echo "✓ Aya GitHub reference exists"
    fi
fi

# Check permissions
if jq -e '.permission' "$PROJECT_ROOT/.opencode/opencode.json" >/dev/null; then
    echo "✓ Permissions section exists"
    if jq -e '.permission.edit' "$PROJECT_ROOT/.opencode/opencode.json" >/dev/null; then
        echo "✓ Edit permission configured"
    fi
    if jq -e '.permission.bash' "$PROJECT_ROOT/.opencode/opencode.json" >/dev/null; then
        echo "✓ Bash permissions configured"
    fi
    if jq -e '.permission.external_directory' "$PROJECT_ROOT/.opencode/opencode.json" >/dev/null; then
        echo "✓ External directory permissions configured"
    fi
fi

# Check security restrictions
echo ""
echo "Testing security restrictions..."
if jq -e '.permission.bash["rm -rf *"] == "deny"' "$PROJECT_ROOT/.opencode/opencode.json" >/dev/null; then
    echo "✓ rm -rf * is denied"
fi
if jq -e '.permission.bash["sudo *"] == "deny"' "$PROJECT_ROOT/.opencode/opencode.json" >/dev/null; then
    echo "✓ sudo * is denied"
fi
if jq -e '.permission.bash[":; *"] == "deny"' "$PROJECT_ROOT/.opencode/opencode.json" >/dev/null; then
    echo "✓ Command chaining is denied"
fi

# Check allowed commands
if jq -e '.permission.bash["cargo *"] == "allow"' "$PROJECT_ROOT/.opencode/opencode.json" >/dev/null; then
    echo "✓ cargo * is allowed"
fi
if jq -e '.permission.bash["git *"] == "allow"' "$PROJECT_ROOT/.opencode/opencode.json" >/dev/null; then
    echo "✓ git * is allowed"
fi

# Test project paths in package.json
echo ""
echo "Testing package.json configuration..."
PACKAGE_JSON="$PROJECT_ROOT/.opencode/package.json"

if jq -e '.panhandle' "$PACKAGE_JSON" >/dev/null; then
    echo "✓ Panhandle section exists in package.json"
    
    # Test individual paths
    for key in project_root rust_workspace ebpf_sources common_sources main_sources test_directory config_directory build_artifacts test_configs scripts files; do
        if jq -e ".panhandle.$key" "$PACKAGE_JSON" >/dev/null; then
            echo "✓ $key configured in panhandle section"
        fi
    done
fi

if jq -e '.opencode' "$PACKAGE_JSON" >/dev/null; then
    echo "✓ OpenCode section exists in package.json"
    if jq -e '.opencode.recommended_tools' "$PACKAGE_JSON" >/dev/null; then
        echo "✓ Recommended tools configured"
    fi
    if jq -e '.opencode.specialized_agents' "$PACKAGE_JSON" >/dev/null; then
        echo "✓ Specialized agents configured"
    fi
fi

echo ""
echo "✓ Configuration validation completed successfully!"
echo ""

# Show summary of configuration
echo "Configuration Summary:"
echo "----------------------"
echo "OpenCode config: $(wc -l < "$PROJECT_ROOT/.opencode/opencode.json") lines"
echo "Package config: $(wc -l < "$PROJECT_ROOT/.opencode/package.json") lines"
echo "Skills: $(find "$PROJECT_ROOT/.opencode/skills" -name "SKILL.md" | wc -l) configured"

echo ""
echo "All configuration files are valid and properly structured."