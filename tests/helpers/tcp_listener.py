"""A TCP listener for the namespace lab: run inside the target namespace, it
accepts on PORT over IPv4 and IPv6 and appends each peer's address and port,
one per line, to LOG. Started in the background by CI.

    sudo ip netns exec ptg python3 tcp_listener.py LOG PORT
"""
import select
import socket
import sys

log, port = sys.argv[1], int(sys.argv[2])
servers = []
for family, host in ((socket.AF_INET, "10.78.9.9"), (socket.AF_INET6, "fd78:9::9")):
    s = socket.socket(family, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(16)
    servers.append(s)
while True:
    ready, _, _ = select.select(servers, [], [])
    for s in ready:
        conn, peer = s.accept()
        with open(log, "a") as out:
            out.write(f"{peer[0]} {peer[1]}\n")
        conn.close()
