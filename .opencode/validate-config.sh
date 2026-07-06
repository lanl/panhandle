#!/bin/bash

# Panhandle OpenCode Configuration Validation Script
# This script validates that all configured paths and permissions are correct

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "============================================"
echo "Panhandle OpenCode Configuration Validator"
echo "============================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

function pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((PASS_COUNT++))
}

function fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((FAIL_COUNT++))
}

function warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    ((WARN_COUNT++))
}

function info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

function check_file() {
    local file_path="$1"
    local description="$2"
    
    if [[ -f "$file_path" ]]; then
        pass "$description exists: $file_path"
        return 0
    else
        fail "$description missing: $file_path"
        return 1
    fi
}

function check_dir() {
    local dir_path="$1"
    local description="$2"
    
    if [[ -d "$dir_path" ]]; then
        pass "$description exists: $dir_path"
        return 0
    else
        fail "$description missing: $dir_path"
        return 1
    fi
}

function check_executable() {
    local cmd="$1"
    local description="$2"
    
    if command -v "$cmd" >/dev/null 2>&1; then
        pass "$description available: $cmd"
        return 0
    else
        warn "$description not available: $cmd"
        return 1
    fi
}

function check_json_property() {
    local file="$1"
    local property="$2"
    local description="$3"
    
    if jq -e ".$property" "$file" >/dev/null 2>&1; then
        pass "$description property exists in $file"
        return 0
    else
        fail "$description property missing from $file"
        return 1
    fi
}

echo "Testing Project Structure..."
echo "----------------------------"

# Check main project structure
check_dir "$PROJECT_ROOT" "Project root directory"
check_dir "$PROJECT_ROOT/.opencode" "OpenCode configuration directory"
check_dir "$PROJECT_ROOT/panhandle" "Rust workspace directory"
check_dir "$PROJECT_ROOT/panhandle/panhandle" "Main panhandle crate"
check_dir "$PROJECT_ROOT/panhandle/panhandle-ebpf" "eBPF crate"
check_dir "$PROJECT_ROOT/panhandle/panhandle-common" "Common crate"

# Check source directories
check_dir "$PROJECT_ROOT/panhandle/panhandle/src" "Main source directory"
check_dir "$PROJECT_ROOT/panhandle/panhandle-ebpf/src" "eBPF source directory"
check_dir "$PROJECT_ROOT/panhandle/panhandle-common/src" "Common source directory"
check_dir "$PROJECT_ROOT/panhandle/panhandle/tests" "Test directory"

# Check configuration files
check_file "$PROJECT_ROOT/.opencode/opencode.json" "Main OpenCode configuration"
check_file "$PROJECT_ROOT/.opencode/package.json" "Package configuration"
check_file "$PROJECT_ROOT/.opencode/README.md" "Configuration documentation"

# Check skill files
check_file "$PROJECT_ROOT/.opencode/skills/panhandle/SKILL.md" "Panhandle skill"
check_file "$PROJECT_ROOT/.opencode/skills/aya-ebpf/SKILL.md" "Aya eBPF skill"
check_file "$PROJECT_ROOT/.opencode/skills/rust-ebpf/SKILL.md" "Rust eBPF skill"
check_file "$PROJECT_ROOT/.opencode/skills/hpc-monitoring/SKILL.md" "HPC monitoring skill"

echo ""
echo "Testing Configuration Files..."
echo "------------------------------"

# Check opencode.json structure
check_json_property "$PROJECT_ROOT/.opencode/opencode.json" "references" "References section"
check_json_property "$PROJECT_ROOT/.opencode/opencode.json" "permission" "Permissions section"
check_json_property "$PROJECT_ROOT/.opencode/opencode.json" "tool_output" "Tool output section"
check_json_property "$PROJECT_ROOT/.opencode/opencode.json" "experimental" "Experimental section"

# Check references
check_json_property "$PROJECT_ROOT/.opencode/opencode.json" "references.panhandle" "Panhandle reference"
check_json_property "$PROJECT_ROOT/.opencode/opencode.json" "references['aya-github']" "Aya GitHub reference"

# Check permission sections
check_json_property "$PROJECT_ROOT/.opencode/opencode.json" "permission.edit" "Edit permission"
check_json_property "$PROJECT_ROOT/.opencode/opencode.json" "permission.bash" "Bash permissions"
check_json_property "$PROJECT_ROOT/.opencode/opencode.json" "permission.external_directory" "External directory permissions"

echo ""
echo "Testing Rust Toolchain..."
echo "--------------------------"

# Check Rust toolchain
check_executable "cargo" "Cargo build system"
check_executable "rustc" "Rust compiler"
check_executable "git" "Git version control"
check_executable "make" "Make build tool"

# Check optional tools
check_executable "clippy" "Clippy linter" || true
check_executable "rustfmt" "Rust formatter" || true
check_executable "cargo-audit" "Cargo audit" || true
check_executable "cargo-tarpaulin" "Test coverage tool" || true
check_executable "bpf-linker" "BPF linker" || true

echo ""
echo "Testing Project Paths..."
echo "------------------------"

# Test all project paths mentioned in package.json
PACKAGE_JSON="$PROJECT_ROOT/.opencode/package.json"

# Extract paths from panhandle section
PROJECT_ROOT_CONFIG=$(jq -r '.panhandle.project_root' "$PACKAGE_JSON" 2>/dev/null || echo "")
RUST_WORKSPACE=$(jq -r '.panhandle.rust_workspace' "$PACKAGE_JSON" 2>/dev/null || echo "")
EBPF_SOURCES=$(jq -r '.panhandle.ebpf_sources' "$PACKAGE_JSON" 2>/dev/null || echo "")
COMMON_SOURCES=$(jq -r '.panhandle.common_sources' "$PACKAGE_JSON" 2>/dev/null || echo "")
MAIN_SOURCES=$(jq -r '.panhandle.main_sources' "$PACKAGE_JSON" 2>/dev/null || echo "")
TEST_DIRECTORY=$(jq -r '.panhandle.test_directory' "$PACKAGE_JSON" 2>/dev/null || echo "")
CONFIG_DIRECTORY=$(jq -r '.panhandle.config_directory' "$PACKAGE_JSON" 2>/dev/null || echo "")
BUILD_ARTIFACTS=$(jq -r '.panhandle.build_artifacts' "$PACKAGE_JSON" 2>/dev/null || echo "")
TEST_CONFIGS=$(jq -r '.panhandle.test_configs' "$PACKAGE_JSON" 2>/dev/null || echo "")
SCRIPTS=$(jq -r '.panhandle.scripts' "$PACKAGE_JSON" 2>/dev/null || echo "")
FILES=$(jq -r '.panhandle.files' "$PACKAGE_JSON" 2>/dev/null || echo "")

if [[ -n "$PROJECT_ROOT_CONFIG" ]]; then
    check_dir "$PROJECT_ROOT_CONFIG" "Project root from config"
fi

if [[ -n "$RUST_WORKSPACE" ]]; then
    check_dir "$RUST_WORKSPACE" "Rust workspace from config"
fi

if [[ -n "$EBPF_SOURCES" ]]; then
    check_dir "$EBPF_SOURCES" "eBPF sources from config"
fi

if [[ -n "$COMMON_SOURCES" ]]; then
    check_dir "$COMMON_SOURCES" "Common sources from config"
fi

if [[ -n "$MAIN_SOURCES" ]]; then
    check_dir "$MAIN_SOURCES" "Main sources from config"
fi

if [[ -n "$TEST_DIRECTORY" ]]; then
    check_dir "$TEST_DIRECTORY" "Test directory from config"
fi

if [[ -n "$CONFIG_DIRECTORY" ]]; then
    check_dir "$CONFIG_DIRECTORY" "Config directory from config"
fi

if [[ -n "$BUILD_ARTIFACTS" ]]; then
    check_dir "$BUILD_ARTIFACTS" "Build artifacts directory from config"
fi

if [[ -n "$TEST_CONFIGS" ]]; then
    check_dir "$TEST_CONFIGS" "Test configs directory from config"
fi

if [[ -n "$SCRIPTS" ]]; then
    check_dir "$SCRIPTS" "Scripts directory from config"
fi

if [[ -n "$FILES" ]]; then
    check_dir "$FILES" "Files directory from config"
fi

echo ""
echo "Testing Cargo Workspace..."
echo "--------------------------"

# Test cargo configuration
cd "$PROJECT_ROOT/panhandle" || {
    warn "Cannot change to panhandle directory"
} || {
    if check_file "$PROJECT_ROOT/panhandle/Cargo.toml" "Workspace Cargo.toml"; then
        pass "Found workspace Cargo.toml"
    fi
    
    if check_file "$PROJECT_ROOT/panhandle/panhandle/Cargo.toml" "Main crate Cargo.toml"; then
        pass "Found main crate Cargo.toml"
    fi
    
    if check_file "$PROJECT_ROOT/panhandle/panhandle-ebpf/Cargo.toml" "eBPF crate Cargo.toml"; then
        pass "Found eBPF crate Cargo.toml"
    fi
    
    if check_file "$PROJECT_ROOT/panhandle/panhandle-common/Cargo.toml" "Common crate Cargo.toml"; then
        pass "Found common crate Cargo.toml"
    fi
}

echo ""
echo "Testing External References..."
echo "-----------------------------"

# Check Aya GitHub reference
AYA_GITHUB_PATH=$(jq -r '.references["aya-github"].path' "$PROJECT_ROOT/.opencode/opencode.json" 2>/dev/null || echo "")
if [[ -n "$AYA_GITHUB_PATH" ]]; then
    if [[ -d "$AYA_GITHUB_PATH" ]]; then
        pass "Aya GitHub reference path: $AYA_GITHUB_PATH"
    else
        warn "Aya GitHub reference path not found: $AYA_GITHUB_PATH"
        info "This is expected if aya-rs/aya is not cloned locally"
    fi
fi

echo ""
echo "Testing Security Configuration..."
echo "---------------------------------"

# Check that dangerous commands are blocked
OPECODE_JSON="$PROJECT_ROOT/.opencode/opencode.json"

# Check for denied commands
if jq -e '.permission.bash["rm -rf *"] == "deny"' "$OPECODE_JSON" >/dev/null 2>&1; then
    pass "Dangerous command 'rm -rf *' is denied"
else
    fail "Dangerous command 'rm -rf *' should be denied"
fi

if jq -e '.permission.bash["sudo *"] == "deny"' "$OPECODE_JSON" >/dev/null 2>&1; then
    pass "Privilege escalation 'sudo *' is denied"
else
    fail "Privilege escalation 'sudo *' should be denied"
fi

if jq -e '.permission.bash[":; *"] == "deny"' "$OPECODE_JSON" >/dev/null 2>&1; then
    pass "Command chaining ':; *' is denied"
else
    fail "Command chaining ':; *' should be denied"
fi

# Check for allowed commands
if jq -e '.permission.bash["cargo *"] == "allow"' "$OPECODE_JSON" >/dev/null 2>&1; then
    pass "Cargo commands are allowed"
else
    fail "Cargo commands should be allowed"
fi

if jq -e '.permission.bash["git *"] == "allow"' "$OPECODE_JSON" >/dev/null 2>&1; then
    pass "Git commands are allowed"
else
    fail "Git commands should be allowed"
fi

echo ""
echo "Testing External Directory Permissions..."
echo "----------------------------------------"

# Check external directory permissions
EXTERNAL_DIRS=(
    "~/.cargo/**"
    "~/.rustup/**"
    "/usr/lib/**"
    "/usr/share/**"
    "/usr/local/**"
    "/usr/bin/**"
    "/usr/include/**"
    "/opt/**"
    "/var/log/panhandle/**"
    "/etc/panhandle/**"
)

for dir_pattern in "${EXTERNAL_DIRS[@]}"; do
    # Convert glob pattern to a simple check
    if jq -e --arg pattern "$dir_pattern" '.permission.external_directory[$pattern] == "allow"' "$OPECODE_JSON" >/dev/null 2>&1; then
        pass "External directory access allowed: $dir_pattern"
    else
        warn "External directory access not configured: $dir_pattern"
    fi
done

echo ""
echo "============================================"
echo "Validation Summary"
echo "============================================"
echo -e "${GREEN}Passed: $PASS_COUNT${NC}"
echo -e "${RED}Failed: $FAIL_COUNT${NC}"
echo -e "${YELLOW}Warnings: $WARN_COUNT${NC}"
echo ""

if [[ $FAIL_COUNT -eq 0 ]]; then
    echo -e "${GREEN}✓ Configuration validation passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Configuration validation failed!${NC}"
    exit 1
fi