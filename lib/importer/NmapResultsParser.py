#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Importer > NmapResultsParser
###
from libnmap.parser import NmapParser

from lib.core.Config import *
from lib.core.Target import Target
from lib.importer.Config import get_service_name
from lib.utils.FileUtils import FileUtils
from lib.utils.NetUtils import NetUtils
from lib.utils.OSUtils import OSUtils
from lib.utils.WebUtils import WebUtils
from lib.db.Host import Host
from lib.db.Option import Option
from lib.db.Service import Service, Protocol
from lib.output.Logger import logger
from lib.output.Output import Output


class NmapResultsParser:

    def __init__(self, nmap_file, services_config):
        """
        Initialize Nmap Parser from results file.

        :param str nmap_file: Nmap XML results file
        :param ServicesConfig services_config: Services configuration
        """
        self.nmap_file = nmap_file
        self.services_config = services_config


    #------------------------------------------------------------------------------------

    def parse(self, 
              http_recheck=True, 
              html_title_grabbing=True,
              nmap_banner_grabbing=False,
              web_technos_detection=True):
        """
        Parse the Nmap results

        :param bool http_recheck: If set to True, TCP ports are re-checked for HTTP(s)
        :param bool html_title_grabbing: If set to True, grab title of HTML page (text in
            <title> tags) and put it as comment for HTTP service
        :param bool nmap_banner_grabbing: If set to True, run Nmap to grab 
            service banner for each service where it is missing (might be useful if 
            imported Nmap results come from a scan run without -sV/-A)
        :param bool web_technos_detection: If set to True, try to detect web technos
            for HTTP service

        :return: Hosts 
        :rtype: list(Host)|None
        """
        try:
            nmap_report = NmapParser.parse_fromfile(self.nmap_file)
        except Exception as e:
            logger.error('Error when parsing the Nmap file: {0}'.format(e))
            return None

        results = list()
        host_id = 0
        for h in nmap_report.hosts:

            host_id += 1

            # Get the fingerprinted OS if available
            os = ''
            os_vendor = ''
            os_family = ''
            device_type = ''
            if h.os_fingerprinted is True \
                    and h.os_match_probabilities() is not None \
                    and len(h.os_match_probabilities()) > 0:
                os_matchs = h.os_match_probabilities()
                if len(os_matchs) > 0:
                    os = os_matchs[0].name
                    if os_matchs[0].osclasses is not None \
                            and len(os_matchs[0].osclasses) > 0:
                        os_vendor = os_matchs[0].osclasses[0].vendor
                        os_family = os_matchs[0].osclasses[0].osfamily
                        device_type = OSUtils.get_device_type(
                            os,
                            os_family,
                            os_matchs[0].osclasses[0].type)

            # Create Host object
            host = Host(ip=h.ipv4, 
                        hostname=h.hostnames[0] if h.hostnames else h.ipv4,
                        os=os,
                        os_vendor=os_vendor,
                        os_family=os_family,
                        mac=h.mac,
                        vendor=h.vendor,
                        type=device_type)
            logger.info('[File {file} | Host {current_host}/{total_host}] ' \
                'Parsing host: {ip}{hostname} ...'.format(
                    file=FileUtils.extract_filename(self.nmap_file),
                    current_host=host_id,
                    total_host=len(nmap_report.hosts),
                    ip=host.ip, 
                    hostname=' ('+host.hostname+')' if host.hostname != host.ip else ''))

            # Loop over open ports
            port_id = 0
            for p in h.get_open_ports():
                port_id += 1
                s = h.get_service(p[0], protocol=p[1])
                name = get_service_name(s.service)
                url = ''
                comment = ''
                html_title = ''

                # Print current processed service
                print()
                logger.info('[File {file} | Host {current_host}/{total_host} | ' \
                    'Service {current_svc}/{total_svc}] Parsing service: ' \
                    'host {ip} | port {port}/{proto} | service {service} ...'.format(
                        file=FileUtils.extract_filename(self.nmap_file),
                        current_host=host_id,
                        total_host=len(nmap_report.hosts),
                        current_svc=port_id,
                        total_svc=len(h.get_open_ports()),
                        ip=h.ipv4, 
                        port=s.port, 
                        proto=s.protocol, 
                        service=name))

                # Get URL for http services
                if name == 'http':
                    if 'https' in s.service \
                       or 'ssl' in s.service \
                       or s.tunnel in ('ssl', 'tls'):
                        proto = 'https'
                    else:
                        proto = 'http'
                    url = '{proto}://{host}:{port}'.format(
                        proto=proto, host=host.hostname, port=s.port)

                # Recheck for HTTP/HTTPS for services undetermined by Nmap
                if http_recheck \
                   and s.protocol == 'tcp' \
                   and not self.services_config.is_service_supported(name, multi=False):

                    url = WebUtils.is_returning_http_data(host.ip, s.port)
                    if url:
                        logger.success('{url} seems to return HTTP data, marking it ' \
                            'as http service'.format(url=url))
                        name = 'http'

                # Only keep services supported by Jok3r
                if not self.services_config.is_service_supported(name, multi=False):
                    logger.warning('Service not supported: host {ip} | port ' \
                        '{port}/{proto} | service {service}'.format(
                            ip = h.ipv4, port=s.port, proto=s.protocol, service=name))
                    continue

                # # Deduce OS from banner if possible
                # if not os:
                #     host.os = OSUtils.os_from_nmap_banner(s.banner)
                #     if host.os:
                #         host.os_vendor = OSUtils.get_os_vendor(host.os)
                #         host.os_family = OSUtils.get_os_family(host.os)

                # Clean Nmap banner
                banner = NetUtils.clean_nmap_banner(s.banner)

                # Create Service object
                service = Service(
                    name=name,
                    name_original=s.service,
                    port=s.port,
                    protocol={'tcp': Protocol.TCP,'udp': Protocol.UDP}.get(s.protocol),
                    url=url,
                    up=True,
                    banner=banner,
                    comment=comment,
                    html_title=html_title)
                host.services.append(service)

                # Target smart check:
                # - Nmap banner grabbing if specified by user and banner is missing in 
                #   imported results;
                # - HTML title and HTTP response headers grabbing for HTTP service;
                # - Web technologies detection for HTTP service, except if disabled by
                #   user;
                # - Initialize the context of the target via SmartModules, based on the
                #   information already known (i.e. banner, web technologies...)
                target = Target(service, self.services_config)
                up = target.smart_check(
                    reverse_dns_lookup=False, # Done by Nmap 
                    availability_check=False, # Done by Nmap
                    nmap_banner_grabbing=nmap_banner_grabbing, # Default: False
                    html_title_grabbing=html_title_grabbing,
                    web_technos_detection=web_technos_detection, # Default: True
                    smart_context_initialize=True)
                if not up:
                    logger.warning('Service not reachable')

            if host.services:
                results.append(host)

        return results
