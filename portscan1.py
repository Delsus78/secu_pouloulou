#!/usr/bin/python
import socket

# instantiate a socket object with TCP protocol and IPv4
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

host = "127.0.0.1"
port = 443


def portscanner(port):
    if s.connect_ex((host, port)):
        print("Port %d is closed" % (port))
    else:
        print("Port %d is open" % (port))


# scan port 1 to 1024
for port in range(1, 1025):
    portscanner(port)
