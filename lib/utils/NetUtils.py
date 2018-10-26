# -*- coding: utf-8 -*-
###
### Utils > WebUtils
###
import socket
import ipaddress
import time
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException


class NetUtils:

    @staticmethod
    def is_valid_ip(string):
        """
        Check if given string represents a valid IP address 
        """
        try:
            ipaddress.ip_address(string)
            return True
        except:
            return False


    @staticmethod
    def is_valid_ip_range(string):
        """
        Check if given string represents a valid IP range
        Accepted format: like 1.1.1.1/24
        """
        try:
            ipaddress.ip_network(string, strict=False)
            return True
        except:
            return False


    @staticmethod
    def is_valid_port(string):
        """
        Check if given string represents a valid port number
        """
        try:
            port = int(string)
            return (0 <= port <= 65535)
        except:
            return False


    @staticmethod
    def is_valid_port_range(string):
        """
        Check if given string represents a valid port range
        Accepted format: like 80-100
        """
        if string.count('-') == 1:
            minport, maxport = string.split('-')
            return NetUtils.is_valid_port(minport) and \
                   NetUtils.is_valid_port(maxport) and \
                   minport <= maxport
        else:
            return False


    @staticmethod
    def is_tcp_port_open(ip, port):
        """
        Check if given TCP port is open
        """
        # try:
        #     socket.setdefaulttimeout(3)
        #     s = socket.socket()
        #     s.connect((ip, int(port)))
        #     banner = s.recv(1024)
        #     return True
        # # Handle Timeout and connection refuse error
        # except:
        #     return False

        for i in range(10):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                s.connect((ip, int(port)))
                return True
            except:
                time.sleep(1)
            finally:
                #s.shutdown(socket.SHUT_RDWR)
                s.close()
        return False


    @staticmethod
    def is_udp_port_open(ip, port):
        """
        Check if given UDP port is open
        """
        # TODO
        return True


    @staticmethod
    def grab_banner_nmap(ip, port):
        report = None
        nmproc = NmapProcess(ip, '-sT -sV -Pn -p '+str(port))
        rc = nmproc.run()
        if rc != 0:
            print("nmap scan failed: {0}".format(nmproc.stderr))
            return None
        #print(type(nmproc.stdout))

        try:
            report = NmapParser.parse(nmproc.stdout)
        except NmapParserException as e:
            #print("Exception raised while parsing scan: {0}".format(e.msg))
            return None

        if len(report.hosts):
            if len(report.hosts[0].services):
                return report.hosts[0].services[0].banner

        return None


    @staticmethod
    def grab_banner_simple(ip, port):
        """
        Get the banner of a service located at ip:port
        """
        try:
            socket.setdefaulttimeout(2)
            s = socket.socket()
            s.connect((ip, int(port)))
            banner = s.recv(1024)
            return banner
            # Handle Timeout and connection refuse error
        except:
            return None


    @staticmethod
    def dns_lookup(host):
        """
        Get IP corresponding to a given hostname 
        Return the first IPv4 in the list of IPs if available, otherwise the first IPv6
        """
        ip_list = list()
        try:
            ip_list = list(set(str(i[4][0]) for i in socket.getaddrinfo(host, 80)))
        except:
            return None
        if len(ip_list) == 0:
            return None

        for ip in ip_list:
            if type(ipaddress.ip_address(ip)) == ipaddress.IPv4Address:
                return ip
        return ip_list[0]


    @staticmethod
    def reverse_dns_lookup(ip):
        """
        Get hostname from IP if reverse DNS entry exists
        """
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return ''


    @staticmethod
    def get_local_ip_address():
        """
        Get the IP address of whichever interface is used to connect to the network
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        except:
            return '127.0.0.1'