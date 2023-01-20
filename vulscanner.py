import optparse
import socket
import os
import sys
import threading


def main():
    # parsing command line arguments
    parser = optparse.OptionParser('usage %prog -H <target host> -p <target port> -v <vuln file>')
    parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
    parser.add_option('-p', dest='tgtPort', type='string', help='specify target port[s] separated by comma')
    parser.add_option('-v', dest='vulnFile', type='string', help='specify vuln file')

    (options, args) = parser.parse_args()
    tgtHost = options.tgtHost

    # parsing port list with range or comma separated
    if str(options.tgtPort).find(':') != -1:
        tgtPorts = str(options.tgtPort).split(':')
        tgtPorts = [portToScan for portToScan in range(int(tgtPorts[0]), int(tgtPorts[1]))]
        print(tgtPorts)
    else:
        tgtPorts = str(options.tgtPort).split(',')

    # parsing vuln file
    vulnFile = options.vulnFile

    if not validation(parser, tgtHost, tgtPorts, vulnFile):
        exit(0)

    with open(vulnFile, 'r') as f:
        vulns = f.readlines()

    # getting host by ip / hostname
    try:
        tgtIP = socket.gethostbyname(tgtHost)
    except:
        print('Unknown host %s' % tgtHost)
        return

    # get host by address and print name
    try:
        tgtName = socket.gethostbyaddr(tgtIP)
        print('Scan Results for: ' + tgtName[0])
    except:
        print('Scan Results for: ' + tgtIP)

    # set default timeout
    socket.setdefaulttimeout(1)

    # scan ports
    for port in tgtPorts:
        t = threading.Thread(target=portscanner, args=(tgtHost, int(port), vulns))
        t.start()


def validation(parser, tgtHost, tgtPorts, vulnFile) -> bool:
    """
    Validation of command line arguments
    :param parser:
    :param tgtHost:
    :param tgtPorts:
    :param vulnFile:
    :return:
    """
    valid = True
    if (tgtHost == None) | (tgtPorts == None or tgtPorts == []) | (vulnFile == None):
        print(parser.usage)
        valid = False

    # test si le fichier existe
    if not os.path.isfile(vulnFile):
        print(f'[-] {vulnFile} does not exist.')
        valid = False

    # a les droits de lecture
    if not os.access(vulnFile, os.R_OK):
        print(f'[-] {vulnFile} access denied.')
        valid = False

    return valid


def portscanner(host, port, vulns):
    print(f'Scanning port {port}')
    print(f"with {vulns}\n------------------")
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

if __name__ == '__main__':
    main()
