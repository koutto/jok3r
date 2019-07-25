#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Importer > ShodanResultsParser
### API key needs to be store in apikeys.py
###
from shodan import Shodan

from lib.core.Config import *
from lib.core.Target import Target
from lib.importer.Config import get_service_name
from lib.utils.FileUtils import *
from lib.utils.NetUtils import NetUtils
from lib.utils.OSUtils import OSUtils
from lib.utils.WebUtils import WebUtils
from lib.db.Host import Host
from lib.db.Option import Option
from lib.db.Service import Service, Protocol
from lib.output.Logger import logger
from lib.output.Output import Output
from apikeys import API_KEYS


class ShodanResultsParser:
    def __init__(self, ips_list, services_config):
        """
        Initialize Shodan Parser from results file.

        :param list(str) ips_list: list of ip addresses
        :param ServicesConfig services_config: Services configuration
        """

        self.services_config = services_config
        self.api = None
        self.api_key = None
        self.ips_list = ips_list

        # config = os.path.expanduser("~/.shodan_api_key")
        # if not FileUtils.can_read(config):
        #     logger.error("Shodan key file doesn't exists in {0}".format(config))
        # else:    
        #     self.api_key = FileUtils.read(config).rstrip()
        #     if self.api_key is not None \
        #         or self.api_key is not '':
        #             self.api = Shodan(self.api_key)
        #     else:
        #         logger.error("Error missing shodan api key in {0}".format(config))
        #         return
        if 'shodan' in API_KEYS.keys() and API_KEYS['shodan']:
            self.api_key = API_KEYS['shodan']
            self.api = Shodan(self.api_key)
        else:
            logger.error('Shodan API key is missing in "apikeys.py"')
            return None

    # ------------------------------------------------------------------------------------

    def parse(self, http_recheck=True):
        """
        Parse the Shodan results

        :param bool http_recheck: If set to True, TCP ports are re-checked for HTTP(s)

        :return: Hosts 
        :rtype: list(Host)|None
        """


        results = list()
        host_id = 0

        for ip in self.ips_list:
            host_id += 1

            # Lookup the host
            query = None
            try:
                query = self.api.host(ip)
            except Exception as e:
                logger.error("Error when querying shodan for IP {ip}: {exc}".format(
                    ip=ip, exc=e))
                return None

            logger.info('Importing Shodan results from https://www.shodan.io/host/' \
                    '{ip}'.format(ip=ip))

            #print(query)

            # Get host information
            hostname = query["hostnames"][0] if query["hostnames"] else ip
            os = query.get("os", '') # Shodan is often missing OS detection in my tests...
            os_vendor = ''
            os_family = ''
            if os:
                os_vendor = OSUtils.get_os_vendor(os)
                os_family = OSUtils.get_os_family(os)
            device_type = ''

            services = query["data"]

            # Create Host object
            host = Host(
                ip=ip,
                hostname=hostname,
                os=os,
                os_vendor=os_vendor,
                os_family=os_family,
                mac='',
                vendor='',
                type=device_type,
            )

            logger.info('[Host {current_host}/{total_host}] Parsing host: ' \
                '{ip}{hostname} ...'.format(
                    current_host=host_id,
                    total_host=len(self.ips_list),
                    ip=host.ip, 
                    hostname=' ('+host.hostname+')' if host.hostname != host.ip else ''))

            # Loop over ports/services
            port_id = 0
            for service in services:
                port_id += 1
                module = service["_shodan"]["module"]
                name = get_service_name(module)
                port = service.get("port", None)
                protocol = service.get("transport", None)
                url = ''
                comment = ''
                html_title = ''
                http_headers = ''

                # Print current processed service
                print()
                logger.info('[Host {current_host}/{total_host} | ' \
                    'Service {current_svc}/{total_svc}] Parsing service: ' \
                    'host {ip} | port {port}/{proto} | service {service} ...'.format(
                        current_host=host_id,
                        total_host=len(self.ips_list),
                        current_svc=port_id,
                        total_svc=len(services),
                        ip=host.ip, 
                        port=port, 
                        proto=protocol, 
                        service=name))

                # Get banner
                product_name = service.get('product', '')
                product_version = service.get('version', '')
                banner = '{name}{version}'.format(
                    name=product_name,
                    version=' {}'.format(product_version) if product_version else '')

                # # Deduce OS from banner if possible
                # if not host.os:
                #     host.os = OSUtils.os_from_nmap_banner(banner)
                #     if host.os:
                #         host.os_vendor = OSUtils.get_os_vendor(host.os)
                #         host.os_family = OSUtils.get_os_family(host.os)

                # Get URL for http services
                if name == 'http':
                    if 'https' in module or 'ssl' in module:
                        proto = 'https'
                    else:
                        proto = 'http'

                    url = "{proto}://{host}:{port}".format(
                        proto=proto, host=hostname, port=port
                    )

                # Recheck for HTTP/HTTPS for services undetermined by Shodan
                if http_recheck \
                    and protocol == "tcp" \
                    and not self.services_config.is_service_supported(name, multi=False):
                    url = WebUtils.is_returning_http_data(ip, port)
                    if url:
                        logger.success("{url} seems to return HTTP data, marking it " \
                            "as http service".format(url=url))
                        name = "http"

                # Get page title and HTTP headers for HTTP services
                if "http" in name:
                    if 'http' in service:
                        html_title = service['http'].get('title', '')
                    http_headers = service.get('data', '')

                # Only keep services supported by Jok3r
                if not self.services_config.is_service_supported(name, multi=False):
                    logger.warning(
                        "Service not supported: host {ip} | port "
                        "{port}/{proto} | service {service}".format(
                            ip=ip, port=port, proto=protocol, service=name
                        )
                    )
                    continue

                # Create Service object
                if protocol and port:
                    service = Service(
                        name=name,
                        name_original=module,
                        port=port,
                        protocol={"tcp": Protocol.TCP, "udp": Protocol.UDP}.get(protocol),
                        url=url,
                        up=True,
                        banner=banner,
                        comment=comment,
                        html_title=html_title,
                        http_headers=http_headers,
                    )

                    host.services.append(service)

                    # Target smart check:
                    # - Check if service is still reachable (possible that it has been 
                    #   shut down since Shodan scan)
                    # - Perform web technologies detection: We could use the technologies
                    #   returned by Shodan API in host['data'][id]['http']['components'],
                    #   however it does not detect the version if it is possible
                    # - Initialize the context of the target via SmartModules, based on the
                    #   information already known (i.e. banner, web technologies...)
                    target = Target(service, self.services_config)
                    up = target.smart_check(
                        reverse_dns_lookup=False, # Done by Shodan
                        availability_check=True, # Check if service is still reachable
                        nmap_banner_grabbing=False, # Done by Shodan
                        html_title_grabbing=False, # Done by Shodan
                        web_technos_detection=True,
                        smart_context_initialize=True)
                        # TODO: Add an option to disable web technos detections by Jok3r
                        # and only use technos names returned by Shodan (to speed up import
                        # if needed)
                    if not up:
                        logger.warning('Service not reachable')

            if host.services:
                results.append(host)

        return results

