#!/usr/bin/python
import socket

# instantiate a socket object with TCP protocol and IPv4
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

host = "127.0.0.1"
port = 443


def portscanner(port):
    if s.connect_ex((host, port)):
        # print in color red
        print("\033[1;31;40m Port %d is closed \033[0;37;40m" % (port))
    else:
        # print in color green
        print("\033[1;32;40m Port %d is open \033[0;37;40m" % (port))


# scan port 1 to 1024
for port in range(1, 1025):
    portscanner(port)
