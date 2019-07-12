#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Core > ShodanResultsParser
###
from lib.core.Config import *
from lib.utils.NetUtils import NetUtils
from lib.utils.WebUtils import WebUtils
from lib.db.Host import Host
from lib.db.Option import Option
from lib.db.Service import Service, Protocol
from lib.output.Logger import logger
from lib.output.Output import Output
from shodan import Shodan

class ShodanResultsParser:

    def __init__(self, ip, services_config):
        """
        Initialize Shodan Parser from results file.

        :param str shodan_ip: ip address
        :param ServicesConfig services_config: Services configuration
        """

        self.shodan_ip = ip
        self.services_config = services_config
        self.results = None
        self.api = Shodan(SHODAN_SETTINGS['api_key'])


    #------------------------------------------------------------------------------------

    def parse(self, http_recheck=True, grab_html_title=True):
        """
        Parse the Nmap results

        :param bool http_recheck: If set to True, TCP ports are re-checked for HTTP(s)
        :param bool grab_html_title: If set to True, grab title of HTML page (text in
            <title> tags) and put it as comment for HTTP service.
        :return: Hosts 
        :rtype: list(Host)|None
        """


        # Lookup the host
        try:
            host_report = self.api.host(self.shodan_ip)
        except Exception as e:
            logger.error('Error when quering shodan: {0}'.format(e))
            return None

        results = list()

        ip=self.shodan_ip
        os = host_report.get('os', '')
        os_vendor = host_report.get('org', '')
        os_family = ''
        device_type = ''
        hostname = host_report.get('hostnames', '')[0]
        ports = host_report['data']


        # Create Host object
        host = Host(ip=ip, 
                    hostname=hostname,
                    os=os,
                    os_vendor=os_vendor,
                    os_family=os_family,
                    mac='',
                    vendor=os_vendor,
                    type=device_type)

        logger.info('Parsing host: {ip}{hostname} ...'.format(
            ip=host.ip, hostname=' ('+host.hostname+')' if host.hostname else ''))
        
        # Loop over services
        for p in ports:
            name = p['_shodan']['module']
            port = p.get('port', None)
            protocol = p.get('transport', None)
            url = ''
            comment = ''
            html_title = ''
            banner = p.get('data', '')

            # Get URL for http services
            if name in ('http', 'https'):
                url = '{proto}://{host}:{port}'.format(
                    proto=name, host=ip, port=port)

            # Recheck for HTTP/HTTPS for services undetermined by Shodan
            if http_recheck \
                and protocol == 'tcp' \
                and not self.services_config.is_service_supported(name, multi=False):

                url = WebUtils.is_returning_http_data(hostname or ip, port)
                if url:
                    logger.success('{url} seems to return HTTP data, marking it ' \
                        'as http service'.format(url=url))
                    name = 'http'

            # Grab page title for HTTP services 
            if grab_html_title and 'http' in name:
                html_title = WebUtils.grab_html_title(url)
   
            # Only keep services supported by Jok3r
            if not self.services_config.is_service_supported(name, multi=False):
                logger.info('Service not supported: host {ip} | port ' \
                    '{port}/{proto} | service {service}'.format(ip = ip, port=port, proto=protocol, service=name))
                continue
            else:
                logger.info('Parsing service: host {ip} | port {port}/{proto} ' \
                    '| service {service}'.format(ip = ip, port=port, proto=protocol, service=name))

            # Create Service object
            if protocol and port:
                service = Service(
                    name       = name,
                    port       = port,
                    protocol   = {'tcp': Protocol.TCP,'udp': Protocol.UDP}.get(protocol),
                    url        = url,
                    up         = True,
                    banner     = banner,
                    comment    = comment,
                    html_title = html_title)

                host.services.append(service)

        if host.services:
            results.append(host)

        return results


    #------------------------------------------------------------------------------------

    @staticmethod
    def shodan_to_joker_service_name(shodan_service):
        """
        Convert Shodan service name to Jok3r name if there is a match.

        :param str nmap_service: Service name as given by Nmap
        :return: Service name compliant with Jok3r naming convention
        :rtype: str
        """
        if shodan_service in SERVICES_SHODAN_TO_JOKER.keys():
            return SERVICES_SHODAN_TO_JOKER[shodan_service]
        else:
            return shodan_service