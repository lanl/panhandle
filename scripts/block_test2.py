#!/usr/bin/env python3
# script to test process blocking feature. Runs indefinitely, repeatedly trying open, openat, creat, and execve operations on /usr/bin/su until ctrl+c
# To block using panhandle, run "cargo run -- --syscalls open --comm-deny python3"
# To specifically block /usr/bin/su operations using panhandle, run "cargo run -- --syscalls open --comm-deny python3 --block-paths /usr/bin/su"

import os
import sys
import time
import subprocess
import atexit
import shutil

# Global temp directory for cleanup
TEMP_DIR = "/tmp/block_test"

def cleanup():
    """Clean up temporary directory on exit"""
    if os.path.exists(TEMP_DIR):
        try:
            shutil.rmtree(TEMP_DIR)
        except:
            pass

def test_open():
    """Test open() syscall on /usr/bin/su"""
    target = "/usr/bin/su"
    try:
        with open(target, 'rb') as f:
            f.read(100)
        return "SUCCESS", target
    except PermissionError:
        return "BLOCKED", target
    except FileNotFoundError:
        return "ERROR - Not found", target
    except Exception as e:
        return f"ERROR - {type(e).__name__}", target

def test_openat():
    """Test openat() syscall on /usr/bin/su"""
    target = "/usr/bin/su"
    try:
        dirfd = os.open("/usr/bin", os.O_RDONLY | os.O_DIRECTORY)
        try:
            fd = os.open("su", os.O_RDONLY, dir_fd=dirfd)
            os.close(fd)
            return "SUCCESS", target
        finally:
            os.close(dirfd)
    except PermissionError:
        return "BLOCKED", target
    except FileNotFoundError:
        return "ERROR - Not found", target
    except Exception as e:
        return f"ERROR - {type(e).__name__}", target

def test_creat():
    """Test creat() syscall"""
    target = os.path.join(TEMP_DIR, "benign_file.tmp")
    try:
        fd = os.open(target, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o644)
        os.close(fd)
        try:
            os.unlink(target)
        except:
            pass
        return "SUCCESS", target
    except PermissionError:
        return "BLOCKED", target
    except Exception as e:
        return f"ERROR - {type(e).__name__}", target

def test_execve():
    """Test execve() syscall on /usr/bin/su"""
    target = "/usr/bin/su"
    try:
        # Use Popen for more direct control and better error handling
        proc = subprocess.Popen(
            [target, "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        # Wait briefly for process to start
        try:
            proc.wait(timeout=1)
            return "SUCCESS", target
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            return "SUCCESS", target
    except PermissionError:
        return "BLOCKED", target
    except OSError as e:
        # Check if it's a permission error (errno 1 = EPERM)
        if e.errno == 1:
            return "BLOCKED", target
        return f"ERROR - OSError({e.errno})", target
    except FileNotFoundError:
        return "ERROR - Not found", target
    except Exception as e:
        return f"ERROR - {type(e).__name__}", target

def main():
    # Create temporary directory for test files
    os.makedirs(TEMP_DIR, exist_ok=True)
    atexit.register(cleanup)
    
    pid = os.getpid()
    print(f"Process PID: {pid}")
    print(f"Process name: python3")
    print(f"Temp directory: {TEMP_DIR}")
    print("=" * 70)
    print("MALICIOUS OPERATION TEST")
    print("=" * 70)
    print("\nCycling through:")
    print("open: Standard file opening (/usr/bin/su)")
    print("openat: Open relative to directory fd (/usr/bin/su)")
    print("creat: Create/truncate file (temp directory)")
    print("execve: Execute binary (/usr/bin/su)")
    print("\nBefore blocking: Should see SUCCESS")
    print("After blocking: Should see BLOCKED")
    print("\nPress Ctrl+C to stop\n")
    print("=" * 70 + "\n")
    
    syscalls = [
        ("open", test_open),
        ("openat", test_openat),
        ("creat", test_creat),
        ("execve", test_execve),
    ]
    
    attempt = 0
    
    try:
        while True:
            attempt += 1
            syscall_name, syscall_func = syscalls[attempt % len(syscalls)]
            
            result, target = syscall_func()
            
            # Format the output to show the file being accessed
            print(f"[{syscall_name:8s} \"{target}\"]: {result}", flush=True)
            
            time.sleep(0.5)
            
    except KeyboardInterrupt:
        print(f"\n\nStopped after {attempt} attempts")
        sys.exit(0)

if __name__ == "__main__":
    main()