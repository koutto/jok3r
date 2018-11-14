#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Core > NmapResultsParser
###
from libnmap.parser import NmapParser

from lib.core.Config import *
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
        self.results = None


    #------------------------------------------------------------------------------------

    def parse(self, http_recheck):
        """
        Parse the Nmap results

        :param bool http_recheck: If set to True, TCP ports are re-checked for HTTP(s)
        :return: Hosts 
        :rtype: list(Host)|None
        """
        try:
            nmap_report = NmapParser.parse_fromfile(self.nmap_file)
        except Exception as e:
            logger.error('Error when parsing the Nmap file: {0}'.format(e))
            return None

        results = list()
        for h in nmap_report.hosts:

            # Get the fingerprinted OS if available
            os = ''
            if h.os_fingerprinted is True and h.os_match_probabilities() is not None:
                os_matchs = h.os_match_probabilities()
                os = os_matchs[0].name if len(os_matchs) > 0 else ''

            # Create Host object
            host = Host(ip = h.ipv4, 
                        hostname = h.hostnames[0] if h.hostnames else '',
                        os = os)
            logger.info('Parsing host: {ip}{hostname} ...'.format(
                ip=host.ip, hostname=' ('+host.hostname+')' if host.hostname else ''))

            # Loop over open ports
            for p in h.get_open_ports():
                s = h.get_service(p[0], protocol=p[1])
                name = NmapResultsParser.nmap_to_joker_service_name(s.service)
                url = ''
                comment = ''

                # Get URL for http services
                if name == 'http':
                    if 'https' in s.service \
                       or 'ssl' in s.service \
                       or s.tunnel in ('ssl', 'tls'):
                        proto = 'https'
                    else:
                        proto = 'http'
                    url = '{proto}://{host}:{port}'.format(
                        proto=proto, host=host.ip, port=s.port)

                # Recheck for HTTP/HTTPS for services undetermined by Nmap
                if http_recheck \
                   and s.protocol == 'tcp' \
                   and not services_config.is_service_supported(name, multi=False):

                    url = WebUtils.is_returning_http_data(host.hostname or host.ip, 
                                                          s.port)
                    if url:
                        logger.success('{url} seems to return HTTP data, marking it ' \
                            'as http service'.format(url=url))
                        name = 'http'

                # Grab page title for HTTP services 
                if name == 'http'
                    comment = WebUtils.grab_html_title(url)


                # Only keep services supported by Jok3r
                if not self.services_config.is_service_supported(name, multi=False):
                    logger.info('Service not supported: host {ip} | port ' \
                        '{port}/{proto} | service {service}'.format(
                            ip = h.ipv4, port=s.port, proto=s.protocol, service=name))
                    continue
                else:
                    logger.info('Parsing service: host {ip} | port {port}/{proto} ' \
                        '| service {service}'.format(
                            ip = h.ipv4, port=s.port, proto=s.protocol, service=name))

                # Create Service object
                service = Service(
                    name     = name,
                    port     = s.port,
                    protocol = {'tcp': Protocol.TCP,'udp': Protocol.UDP}.get(s.protocol),
                    url      = url,
                    up       = True,
                    banner   = s.banner,
                    comment  = comment)

                if name == 'http' and url.startswith('https://'):
                    service.options.append(Option(name='https', value='true'))

                host.services.append(service)

            if host.services:
                results.append(host)

        return results


    #------------------------------------------------------------------------------------

    @staticmethod
    def nmap_to_joker_service_name(nmap_service):
        """
        Convert Nmap service name to Jok3r name if there is a match.

        :param str nmap_service: Service name as given by Nmap
        :return: Service name compliant with Jok3r naming convention
        :rtype: str
        """
        if nmap_service in SERVICES_NMAP_TO_JOKER.keys():
            return SERVICES_NMAP_TO_JOKER[nmap_service]
        else:
            return nmap_service