#!/usr/bin/python

import socket
import optparse
import threading

import chardet


def main():
    socket.setdefaulttimeout(2)

    parser = optparse.OptionParser('usage %prog -H <target host> -p <target port>')
    parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
    parser.add_option('-p', dest='tgtPort', type='string', help='specify target port[s] separated by comma')
    (options, args) = parser.parse_args()
    tgtHost = options.tgtHost
    tgtPorts = str(options.tgtPort).split(',')
    if (tgtHost == None) | (tgtPorts[0] == None):
        print(parser.usage)
        exit(0)
    portScan(tgtHost, tgtPorts)


def portScan(host, ports):
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
        t = threading.Thread(target=portscanner, args=(host, int(port)))
        t.start()


def portscanner(host, port):
    print(f'Scanning port {port}')
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((host, port))
        # print in color green
        print(f"\033[1;32;40mPort {port} is open : \nBanner : {retBanner(s)} \033[0;37;40m")

    except:
        # print in color red
        print(f"\033[1;31;40mPort {port} is closed \033[0;37;40m")


# Améliorer votre programme, en ajoutant la fonction retBanner() qui permet d'afficher la version des services qui utilisent les ports ouverts (banners). Utilisez la méthode recv() de la bibliothèque socket
def retBanner(s):
    try:
        banner = s.recv(1024)
        return banner
    except:
        return "Error in banner"


if __name__ == '__main__':
    main()
