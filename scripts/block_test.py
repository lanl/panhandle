#!/usr/bin/env python3
# script to test process blocking feature

import os
import sys
import time
import subprocess
import tempfile
import signal
import atexit
import shutil

# Global temp directory for cleanup
TEMP_DIR = None

def cleanup():
    # Clean up temporary directory on exit
    global TEMP_DIR
    if TEMP_DIR and os.path.exists(TEMP_DIR):
        try:
            shutil.rmtree(TEMP_DIR)
        except:
            pass

def child_worker(temp_dir):
    # Child process that cycles through different syscalls
    pid = os.getpid()
    print(f"[CHILD {pid}] Starting syscall rotation...\n", flush=True)
    
    # Create test files in our temporary directory
    test_file = os.path.join(temp_dir, "test_block.txt")
    test_script = os.path.join(temp_dir, "test_script.sh")
    
    # Create test file
    with open(test_file, 'w') as f:
        f.write("test content\n")
    
    # Create test script
    with open(test_script, 'w') as f:
        f.write("#!/bin/bash\necho 'executed'\n")
    os.chmod(test_script, 0o755)
    
    attempt = 0
    syscalls = [
        ("open", lambda: test_open(test_file)),
        ("openat", lambda: test_openat(temp_dir, "test_block.txt")),
        ("creat", lambda: test_creat(temp_dir)),
        ("execve", lambda: test_execve(test_script)),
    ]
    
    while True:
        attempt += 1
        syscall_name, syscall_func = syscalls[attempt % len(syscalls)]
        
        try:
            syscall_func()
            print(f"[CHILD {pid}] Attempt {attempt:3d} [{syscall_name:8s}]: SUCCESS")
        except PermissionError:
            print(f"[CHILD {pid}] Attempt {attempt:3d} [{syscall_name:8s}]: BLOCKED")
        except Exception as e:
            print(f"[CHILD {pid}] Attempt {attempt:3d} [{syscall_name:8s}]: ERROR - {e}")
        
        time.sleep(0.5)

def test_open(filename):
    """Trigger open() syscall"""
    with open(filename, 'r') as f:
        f.read()

def test_openat(dirpath, filename):
    """Trigger openat() syscall"""
    dirfd = os.open(dirpath, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fd = os.open(filename, os.O_RDONLY, dir_fd=dirfd)
        os.close(fd)
    finally:
        os.close(dirfd)

def test_creat(temp_dir):
    """Trigger creat() syscall"""
    path = os.path.join(temp_dir, f"test_creat_{os.getpid()}.tmp")
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o644)
    os.close(fd)
    try:
        os.unlink(path)
    except:
        pass

def test_execve(script):
    """Trigger execve() syscall"""
    # Fork to avoid replacing current process
    subprocess.run([script], timeout=1)

def main():
    global TEMP_DIR
    
    # Create temporary directory for test files
    TEMP_DIR = tempfile.mkdtemp(prefix="panhandle_test_")
    atexit.register(cleanup)
    
    print(f"Using temporary directory: {TEMP_DIR}\n")
    
    # Fork child process
    pid = os.fork()
    if pid == 0:
        # Child process
        try:
            child_worker(TEMP_DIR)
        except KeyboardInterrupt:
            pass
        finally:
            sys.exit(0)
    
    # Parent process
    print(f"Child PID: {pid}")
    print(f"Child process name: python3")
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
    print(f"Starting Panhandle to block process 'python3'...")
    print(f"{'='*70}\n")
    
    try:
        # Run panhandle with blocking parameters
        subprocess.run([
            "cargo", "run", "--",
            "--syscalls", "open",
            "--comm-black", "python3",
        ])
    except KeyboardInterrupt:
        print("\nStopping Panhandle...")
    finally:
        # Kill child process
        try:
            os.kill(pid, signal.SIGTERM)
            os.waitpid(pid, 0)
        except:
            pass

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nStopped by user")
        sys.exit(0)