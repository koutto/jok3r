#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Importer > ListImporter
###

from lib.output.Logger import logger
from lib.output.Output import Output
from lib.requester.ServicesRequester import ServicesRequester
from lib.utils.NetUtils import NetUtils
from lib.utils.WebUtils import WebUtils
from lib.webui.api.WebsocketCallable import WebsocketCallable


class ListImporter(WebsocketCallable):

    def __init__(self, 
                 list_targets, 
                 services_config,
                 sqlsession, 
                 current_mission,
                 called_from_websocket=False):
        """
        Import services from a list.
        Each element of this list must comply with the following syntax:
            - For any service: <IP/HOST>:<PORT>,<SERVICE>
            - For HTTP service: <URL> (must begin with http(s)://)

        :param list(str) list_targets: List of string describing services to import
        :param ServicesConfig services_config: Services configuration
        :param Session sqlsession: SQLAlchemy session
        :param str current_mission: Name of selected mission (into which we import)
        :param bool called_from_websocket: Boolean indicating if called when using WEB UI
        """
        self.list_targets = list_targets
        self.services_config = services_config
        self.req = ServicesRequester(sqlsession)
        self.req.select_mission(current_mission)
        super().__init__(called_from_websocket, 'log-import-list')


    def run(self,
            reverse_dns_lookup=True,
            html_title_grabbing=True,
            nmap_banner_grabbing=True,
            web_technos_detection=True,
            take_screenshot=True):
        """
        Parse the list of service to import.

        :param bool reverse_dns_lookup: If set to True, perform reverse DNS lookup
        :param bool html_title_grabbing: If set to True, grab title of HTML page (text in
            <title> tags) and put it as comment for HTTP service
        :param bool nmap_banner_grabbing: If set to True, run Nmap to grab 
            service banner for each service (recommended)
        :param bool web_technos_detection: If set to True, try to detect web technos
            for HTTP service
        :param bool take_screenshot: If set to True, take web page screenshot for
            HTTP service

        :return: None
        :rtype: None
        """
        lines = self.list_targets.splitlines()
        nb_new_services = 0

        if len(lines) == 0:
            self.log('warning', 'List is empty, nothing to import')
            return

        # Process all lines
        i = 1
        for l in lines:
            if i > 1:
                print()
            self.log(
                'info', 
                'Processing line [{i}/{total}]: "{line}" ...'.format(
                    i=i, total=len(lines), line=l))
            i += 1

            # For line with syntax: <URL>
            if l.lower().startswith('http://') or l.lower().startswith('https://'):

                if not WebUtils.is_valid_url(l):
                    self.log(
                        'error', 
                        'URL is invalid, line skipped.')
                else:
                    # Add the URL in current mission scope
                    service, reason = self.req.add_url(
                        l,
                        self.services_config,
                        reverse_dns_lookup=reverse_dns_lookup,
                        availability_check=not nmap_banner_grabbing,
                        nmap_banner_grabbing=nmap_banner_grabbing,
                        html_title_grabbing=html_title_grabbing,
                        web_technos_detection=web_technos_detection,
                        take_screenshot=take_screenshot)

            # For line with syntax: <IP/HOST>:<PORT>[,<SERVICE>]
            else:
                if ',' in l:
                    ip_port, service = l.split(',', maxsplit=1)
                    if not self.services_config.is_service_supported(service, multi=False):
                        self.log(
                            'error', 
                            'Service {name} is not valid/supported, ' \
                            'line skipped'.format(name=service.lower()))
                        continue
                elif ':' in l:
                    ip_port = l
                    service = '' # service unspecified, should be determined
                                 # in Target.smart_check() if possible
                else:
                    self.log('error', 'Incorrect syntax, line skipped')
                    continue

                ip, port = ip_port.split(':', maxsplit=1)
                if not NetUtils.is_valid_port(port):
                    self.log(
                        'error', 
                        'Port is invalid, not in range [0-65535], line skipped')
                    continue

                # Add the service in current mission scope
                service, reason = self.req.add_service(
                    ip, 
                    port, 
                    self.services_config.get_protocol(service),
                    service, 
                    self.services_config,
                    nmap_banner_grabbing=nmap_banner_grabbing,
                    reverse_dns_lookup=reverse_dns_lookup, 
                    availability_check=not nmap_banner_grabbing, # done by Nmap
                    html_title_grabbing=html_title_grabbing,
                    web_technos_detection=web_technos_detection,
                    take_screenshot=take_screenshot)


            # Handle errors/success
            if not service:
                if reason == 'target-init-error':
                    self.logweb('error', 'Error during target initialization')
                elif reason == 'service-existing':
                    self.logweb('warning', 'Service is already present in database')
                elif reason == 'no-ip':
                    self.logweb('error', 'DNS lookup failed (cannot resolve to an IP)')
                elif reason == 'unreachable':
                    self.logweb('error', 'Service is unreachable, skipped')
                elif reason == 'unsupported':
                    self.logweb('warning', 'Service is unsupported, skipped')
                elif reason == 'unspecified-service':
                    self.logweb('error', 'Cannot determine service (should re-run with ' \
                        'Nmap service detection enabled)')
            else:
                self.logweb('success', 'Service {line} added in database'.format(line=l))
                nb_new_services += 1

        return nb_new_services
