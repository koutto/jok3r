#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Web-UI > Backend > Models
###
from lib.db.Service import Protocol
from lib.db.Screenshot import ScreenStatus
from lib.webui.api.Api import api

class Mission:
    def __init__(self, mission):
        self.id = mission.id
        self.name = mission.name
        self.comment = mission.comment
        self.creation_date = mission.creation_date
        self.hosts_count = len(mission.hosts)
        self.services_count = mission.get_nb_services()
        self.creds_count = mission.get_nb_credentials(single_username=False)
        self.users_count = mission.get_nb_credentials(single_username=True)
        self.products_count = mission.get_nb_products()
        self.vulns_count = mission.get_nb_vulns()
        self.hosts = mission.hosts


class Host:
    def __init__(self, host):
        self.id = host.id
        self.ip = host.ip
        self.hostname = host.hostname
        self.os = host.os
        self.os_vendor = host.os_vendor
        self.os_family = host.os_family
        self.mac = host.mac
        self.vendor = host.vendor
        self.type = host.type
        self.comment = host.comment
        self.tcp_count = host.get_nb_services(Protocol.TCP)
        self.udp_count = host.get_nb_services(Protocol.UDP)
        self.creds_count = host.get_nb_credentials(single_username=False)
        self.users_count = host.get_nb_credentials(single_username=True)
        self.vulns_count = host.get_nb_vulns()
        self.services_list = list()
        for service in host.services:
            self.services_list.append([ 
                service.port, 
                { 
                    'Protocol.TCP': 'tcp',
                    'Protocol.UDP': 'udp'
                }.get(service.protocol, 'tcp'),
                service.name ])
        self.mission_id = host.mission_id
        self.services = host.services


class Service:
    def __init__(self, service):
        self.id = service.id
        self.name = service.name
        self.name_original = service.name_original
        self.host_ip = service.host.ip 
        self.port = service.port
        self.protocol = service.protocol
        self.encrypted = service.is_encrypted()
        self.url = service.url
        self.up = service.up
        self.banner = service.banner
        self.html_title = service.html_title
        self.web_technos = service.web_technos
        self.comment = service.comment
        self.credentials = service.credentials
        self.options = service.options
        self.products = service.products
        self.vulns = service.vulns
        self.creds_count = service.get_nb_credentials(single_username=False)
        self.users_count = service.get_nb_credentials(single_username=True)
        self.vulns_count = len(service.vulns)
        self.checks_categories = service.get_checks_categories()
        self.host_id = service.host_id
        self.screenshot = ''
        self.screenshot_thumb = ''
        if service.screenshot is not None \
                and service.screenshot.status == ScreenStatus.OK:
            url = '{base_url}services/{id}/screenshot'.format(
                base_url=api.base_url,
                id=service.id)
            self.screenshot = '{}/large'.format(url)
            self.screenshot_thumb = '{}/thumb'.format(url)