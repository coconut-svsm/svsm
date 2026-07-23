#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
Simple vsock server for SVSM integration tests.

Start a vsock server that accepts one connection, sends the port to the
guest through a named pipe (e.g. connected to a QEMU serial port) so it
knows where to connect, and sends "hello_world" on the vsock connection.

Usage: test_vsock_server.py <port> <guest-pipe>
"""

import socket
import struct
import sys


def main():
    port = int(sys.argv[1])
    pipe_in = sys.argv[2]

    with open(pipe_in, "wb") as pipe:
        try:
            sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
            sock.bind((socket.VMADDR_CID_ANY, port))
            sock.listen(1)
        except Exception as e:
            print(f"vsock server failed: {e}", file=sys.stderr)
            # use VMADDR_PORT_ANY to signal the guest that an error has occurred
            pipe.write(struct.pack(">I", socket.VMADDR_PORT_ANY))
            sys.exit(0)
        # send the port to the guest as big-endian u32 so it knows where to connect
        pipe.write(struct.pack(">I", port))

    conn, _ = sock.accept()
    sock.close()

    try:
        conn.sendall(b"hello_world")
        # virtio-vsock in SVSM does not handle half-duplex connections,
        # so keep the connection open until the peer closes it.
        while conn.recv(1024):
            pass
    except OSError:
        pass

    conn.close()


if __name__ == "__main__":
    main()
