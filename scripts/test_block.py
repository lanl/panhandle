#!/usr/bin/env python3
# run from panhandle dir with sudo env "PATH=$PATH" python3 ../../scripts/test_block.py
import os
import sys
import time
import subprocess
import tempfile
import ctypes

def child_worker():
    """Child process that cycles through different syscalls."""
    pid = os.getpid()
    print(f"[CHILD {pid}] Starting syscall rotation...\n", flush=True)
    
    # Create test files
    test_file = "/tmp/test_block.txt"
    test_script = "/tmp/test_script.sh"
    
    with open(test_file, 'w') as f:
        f.write("test content\n")
    
    with open(test_script, 'w') as f:
        f.write("#!/bin/bash\necho 'executed'\n")
    os.chmod(test_script, 0o755)
    
    attempt = 0
    syscalls = [
        ("open", lambda: test_open(test_file)),
        ("openat", lambda: test_openat(test_file)),
        ("creat", lambda: test_creat()),
        ("execve", lambda: test_execve(test_script)),
    ]
    
    while True:
        attempt += 1
        syscall_name, syscall_func = syscalls[attempt % len(syscalls)]
        
        try:
            syscall_func()
            print(f"[CHILD {pid}] Attempt {attempt:3d} [{syscall_name:8s}]: SUCCESS", flush=True)
        except PermissionError:
            print(f"[CHILD {pid}] Attempt {attempt:3d} [{syscall_name:8s}]: BLOCKED", flush=True)
        except Exception as e:
            print(f"[CHILD {pid}] Attempt {attempt:3d} [{syscall_name:8s}]: ERROR - {e}", flush=True)
        
        time.sleep(0.5)

def test_open(filename):
    """Trigger open() syscall"""
    with open(filename, 'r') as f:
        f.read()

def test_openat(filename):
    """Trigger openat() syscall"""
    dirfd = os.open("/tmp", os.O_RDONLY | os.O_DIRECTORY)
    try:
        fd = os.open("test_block.txt", os.O_RDONLY, dir_fd=dirfd)
        os.close(fd)
    finally:
        os.close(dirfd)

def test_creat():
    """Trigger creat() syscall"""
    path = f"/tmp/test_creat_{os.getpid()}.tmp"
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o644)
    os.close(fd)
    os.unlink(path)

def test_execve(script):
    """Trigger execve() syscall"""
    # Fork to avoid replacing current process
    pid = os.fork()
    if pid == 0:
        os.execve(script, [script], os.environ)
    else:
        os.waitpid(pid, 0)

def main():
    # Fork child process
    pid = os.fork()
    if pid == 0:
        child_worker()
        sys.exit(0)
    
    print(f"Child PID: {pid}")
    print("=" * 70)
    print("SYSCALL ROTATION TEST")
    print("=" * 70)
    print("\nCycling through:")
    print("  • open     - Standard file opening")
    print("  • openat   - Open relative to directory fd")
    print("  • creat    - Create/truncate file")
    print("  • execve   - Execute binary")
    print("\nWaiting 5 seconds (should see SUCCESS)...\n")
    time.sleep(5)
    
    print(f"\n{'='*70}")
    print(f"Starting Panhandle to block PID {pid}...")
    print(f"{'='*70}\n")
    
    # Run with cargo
    subprocess.run([
        "cargo", "run", "--",
        "--syscalls", "open",
        "--pid-black", str(pid)
    ])

if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit("Must run as root: sudo python3 test_block.py")
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nStopped by user")
        sys.exit(0)