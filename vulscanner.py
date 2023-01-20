import optparse
import socket
import os
import sys
import threading


def main():
    parser = optparse.OptionParser('usage %prog -H <target host> -p <target port> -v <vuln file>')
    parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
    parser.add_option('-p', dest='tgtPort', type='string', help='specify target port[s] separated by comma')
    parser.add_option('-v', dest='vulnFile', type='string', help='specify vuln file')

    (options, args) = parser.parse_args()
    tgtHost = options.tgtHost
    if str(options.tgtPort).find(':') != -1:
        tgtPorts = str(options.tgtPort).split(':')
        tgtPorts = range(int(tgtPorts[0]), int(tgtPorts[1]))
    else:
        tgtPorts = str(options.tgtPort).split(',')
    vulnFile = options.vulnFile

    if (tgtHost == None) | (tgtPorts[0] == None) | (vulnFile == None):
        print(parser.usage)
        exit(0)

    # test si le fichier existe
    if not os.path.isfile(vulnFile):
        print(f'[-] {vulnFile} does not exist.')
        exit(0)

    # a les droits de lecture
    if not os.access(vulnFile, os.R_OK):
        print(f'[-] {vulnFile} access denied.')
        exit(0)

    with open(vulnFile, 'r') as f:
        vulns = f.readlines()

    for port in tgtPorts:
        portScan(tgtHost, port, vulns)

def portScan(host, ports, vulns):
    try:
        tgtIP = socket.gethostbyname(host)
    except:
        print('Unknown host %s' % host)
        return

    try:
        tgtName = socket.gethostbyaddr(tgtIP)
        print('Scan Results for: ' + tgtName[0])
    except:
        print('Scan Results for: ' + tgtIP)
    socket.setdefaulttimeout(1)
    for port in ports:
        t = threading.Thread(target=portscanner, args=(host, int(port), vulns))
        t.start()

def portscanner(host, port, vulns):
    print(f'Scanning port {port}')
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if s.connect_ex((host, port)):
        # print in color red
        print(f"\033[1;31;40m Port {port} is closed \033[0;37;40m")
    else:
        # print in color green
        print(f"\033[1;32;40m Port {port} is open : \nBanner : {retBanner(host, port, vulns)} \033[0;37;40m")

def retBanner(host, port, vulns):
    try:
        socket.setdefaulttimeout(2)
        s = socket.socket()
        s.connect((host, port))
        banner = s.recvfrom(4096)

        if banner:
            for vuln in vulns:
                if vuln in banner:
                    return "Found Vulnerable Banner : " + str(banner)
                else:
                    return "No Vulnerability Found" + str(banner)

        return "No Banner Found"
    except:
        print('[-] Error in retBanner')
        return