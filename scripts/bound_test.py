#!/usr/bin/env python3
"""
Simple TCP client/server test to exercise tcp_recvmsg blocking.

Runs a server thread that waits several seconds before sending each
message, and a client that blocks in recv() waiting for that data.
Every recv() call should register as one "Network Wait" event for
this process's PID in your eBPF-based bound monitor.

Usage:
    python3 net_test.py [delay_seconds] [iterations]

Then watch your tool's output for this PID's "Network Wait Count" /
"Network Wait Time MS" fields incrementing.
"""
import socket
import sys
import threading
import time
import os

HOST = "127.0.0.1"
PORT = 54545
DELAY = float(sys.argv[1]) if len(sys.argv) > 1 else 2.0
ITERATIONS = int(sys.argv[2]) if len(sys.argv) > 2 else 30


def server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(1)
    conn, _ = srv.accept()
    for i in range(ITERATIONS):
        time.sleep(DELAY)  # forces the client's recv() to actually block
        conn.sendall(f"message {i}\n".encode())
    conn.close()
    srv.close()


def client():
    time.sleep(0.5)  # let the server start listening first
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    for i in range(ITERATIONS):
        data = sock.recv(1024)  # <-- this is the call that blocks in tcp_recvmsg
        print(f"received: {data.decode().strip()}")
    sock.close()


if __name__ == "__main__":
    print(f"PID: {os.getpid()}")
    print(f"Sending {ITERATIONS} messages, {DELAY}s apart, over 127.0.0.1:{PORT}")

    t = threading.Thread(target=server, daemon=True)
    t.start()
    client()
    t.join()