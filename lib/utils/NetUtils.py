#!/usr/bin/env python3
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
        """Check if given string represents a valid IP address"""
        try:
            ipaddress.ip_address(string)
            return True
        except:
            return False


    @staticmethod
    def is_valid_ip_range(string):
        """Check if given string represents a valid CIDR range (e.g. 1.1.1.1/24)"""
        try:
            ipaddress.ip_network(string, strict=False)
            return True
        except:
            return False


    @staticmethod
    def is_valid_port(string):
        """Check if given string represents a valid port number"""
        try:
            port = int(string)
            return (0 <= port <= 65535)
        except:
            return False


    @staticmethod
    def is_valid_port_range(string):
        """Check if given string represents a valid port range (e.g. 80-100)"""
        if string.count('-') == 1:
            minport, maxport = string.split('-')
            return NetUtils.is_valid_port(minport) and \
                   NetUtils.is_valid_port(maxport) and \
                   minport <= maxport
        else:
            return False


    @staticmethod
    def is_tcp_port_open(ip, port):
        """Check if given TCP port is open"""

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
        """Check if given UDP port is open"""
        nmproc = NmapProcess(ip, '-sU -T4 -p '+str(port))
        rc = nmproc.run()
        if rc != 0:
            print("Nmap scan failed (check if running as root): {0}".format(
                nmproc.stderr))
            return True

        try:
            report = NmapParser.parse(nmproc.stdout)
        except NmapParserException as e:
            print("Exception raised while parsing scan: {0}".format(e.msg))
            return False

        if len(report.hosts):
            host = report.hosts[0]
            if len(host.services):
                return 'open' in host.services[0].state
        
        return False


    @staticmethod
    def grab_nmap_info(ip, port):
        """
        Grab service info using Nmap:
            - Banner
            - OS
            - OS Vendor (Microsoft, Linux, Apple...)
            - OS Family (Windows, Linux, Mac OS...)
            - MAC address
            - Vendor name
            - Device type

        :param str ip: Target IP address
        :param int port: Port number
        :return: Dict with retrieved information or None if error or 
            port unreachable
        :rtype: dict|None
        """
        results = {
            'banner': '',
            'os': '',
            'os_vendor': '',
            'os_family': '',
            'mac': '',
            'vendor': '',
            'type': '',
        }
        report = None
        #nmproc = NmapProcess(ip, '-sT -sV -Pn -p '+str(port))
        nmproc = NmapProcess(ip, '-A -Pn -T4 -p '+str(port))
        rc = nmproc.run()
        if rc != 0:
            print("Nmap scan failed: {0}".format(nmproc.stderr))
            return None
        #print(type(nmproc.stdout))

        try:
            report = NmapParser.parse(nmproc.stdout)
        except NmapParserException as e:
            #print("Exception raised while parsing scan: {0}".format(e.msg))
            return None

        if len(report.hosts):
            host = report.hosts[0]
            if len(host.services):
                results['banner'] = host.services[0].banner
                results['mac'] = host.mac
                results['vendor'] = host.vendor
                if host.os_fingerprinted is True \
                        and host.os_match_probabilities() is not None:
                    os_matchs = host.os_match_probabilities()
                    if len(os_matchs) > 0:
                        results['os'] = os_matchs[0].name
                        if os_matchs[0].osclasses is not None \
                                and len(os_matchs[0].osclasses) > 0:
                            results['os_vendor'] = os_matchs[0].osclasses[0].vendor
                            results['os_family'] = os_matchs[0].osclasses[0].osfamily
                            results['type'] = NetUtils.get_device_type(
                                results['os'],
                                results['os_family'],
                                os_matchs[0].osclasses[0].type)

        return results


    @staticmethod
    def os_from_nmap_banner(banner):
        """
        Return OS name that might be contained inside Nmap banner.

        Some examples:
        - ostype: Windows
        - product: Microsoft HTTPAPI... : Microsoft -> Windows
        - product: IBM HTTP Server version: 6.1.0.47 extrainfo: Derived from 
            Apache 2.0.47; Unix -> Linux
        - product: Apache httpd version: 2.4.34 extrainfo: (Red Hat) -> Red Hat Linux
        """
        matches = {
            'Windows': [
                'ostype: windows',
                'microsoft',
            ],
            'Linux': [
                'ostype: linux',
                'ostype: unix',
                'Red Hat',
                'Unix',
            ]
        }

        for ostype in matches.keys():
            for string in matches[ostype]:
                if string.lower() in banner.lower():
                    return ostype

        return ''


    @staticmethod
    def get_device_type(os, os_family, nmap_device_type):

        # Device types matching between Nmap and Jok3r
        # List of device types supported by Nmap: 
        # https://nmap.org/book/osdetect-device-types.html
        DEVICE_TYPE_NMAP_TO_JOKER = {
            'general purpose':      'Server',
            'bridge':               'Device',
            'broadband router':     'Device',
            'firewall':             'Firewall',
            'game console':         'Game console',
            'hub':                  'Device',
            'load balancer':        'Device',
            'media device':         'Media',
            'PBX':                  'VoIP',
            'PDA':                  'PDA',
            'phone':                'Mobile',
            'power-device':         'Power device',
            'printer':              'Printer',
            'print server':         'Print server',
            'proxy server':         'Proxy server',
            'remote management':    'Management',
            'router':               'Device',
            'security-misc':        'Firewall',
            'specialized':          'Misc',
            'storage-misc':         'NAS',
            'switch':               'Device',
            'telecom-misc':         'VoIP',
            'terminal':             'Client',
            'terminal server':      'Server',
            'VoIP adapter':         'VoIP',
            'WAP':                  'Device',
            'webcam':               'Webcam',
        }

        # Nmap device type does not differentiate servers and desktops
        # in the category "general purpose". We try to distinguish desktop
        # based on the OS name. Far from being perfect, only handle Windows
        # and MacOS for now...
        os_patterns_desktops = [
            'Mac OS',
            'macOS',
            'Windows',
        ]
        if nmap_device_type == 'general purpose' \
            and os_family in os_patterns_desktops:
                if 'server' in os. lower():
                    return 'Server'
                else:
                    return 'Desktop'

        else:
            return DEVICE_TYPE_NMAP_TO_JOKER.get(nmap_device_type, 'Misc')


    @staticmethod
    def clean_nmap_banner(banner):
        """
        Make Nmap banner more readable:
            - Delete "product: "
            - Delete "version: "
        """
        return banner.replace('product: ', '').replace('version: ', '')


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
        """Get hostname from IP if reverse DNS entry exists"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return ip


    @staticmethod
    def get_local_ip_address():
        """Get the IP address of whichever interface is used to connect to the network"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        except:
            return '127.0.0.1'