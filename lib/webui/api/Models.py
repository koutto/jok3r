#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Web-UI > Backend > Models
###
import ansi2html
import re

from lib.db.Service import Protocol
from lib.db.Screenshot import ScreenStatus
from lib.smartmodules.CpeMatchs import cpe_match
from lib.webui.api.Api import api, settings

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
        self.services_list = host.get_list_services()
        self.mission_id = host.mission_id
        self.services = host.services


class Service:
    def __init__(self, service):
        self.id = service.id
        self.name = service.name
        self.name_original = service.name_original
        self.host_ip = service.host.ip 
        self.host_hostname = service.host.hostname
        self.host_type = service.host.type
        self.host_os = service.host.os
        self.host_os_vendor = service.host.os_vendor
        self.host_os_family = service.host.os_family
        self.host_vendor = service.host.vendor
        self.host_comment = service.host.comment
        self.port = service.port
        self.protocol = service.protocol
        self.encrypted = service.is_encrypted()
        self.url = service.url
        self.up = service.up
        self.banner = service.banner
        self.html_title = service.html_title
        self.http_headers = service.http_headers
        self.web_technos = service.web_technos
        self.comment = service.comment
        #self.credentials = service.credentials
        self.options = service.get_options_no_encrypt() # Do not get encrypt options
        self.products = list(map(lambda x: Product(x), service.products))
        #self.vulns = service.vulns
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


class CommandOutput:
    def __init__(self, command_output):
        self.id = command_output.id
        self.cmdline = command_output.cmdline

        conv = ansi2html.Ansi2HTMLConverter(
            inline=True, scheme='solarized', linkify=True)
        output = conv.convert(command_output.output)

        # Warning: ansi2html generates HTML document with <html>, <style>...
        # tags. We only keep the content inside <pre> ... </pre>
        m = re.search('<pre class="ansi2html-content">(?P<output>.*)' \
            '</pre>\n</body>', output, re.DOTALL)
        if m:
            output = m.group('output')

        self.output = output    
        self.check = command_output.result.check
        check = settings.services[command_output.result.service.name]['checks'].get_check(
            self.check)
        self.check_description = check.description if check else ''
        self.category = command_output.result.category
        self.tool_used = command_output.result.tool_used


class Credential:
    def __init__(self, credential):
        self.id = credential.id
        self.type = credential.type
        self.username = credential.username
        self.password = credential.password
        self.comment = credential.comment
        self.host_ip = credential.service.host.ip
        self.host_hostname = credential.service.host.hostname
        self.service_id = credential.service.id
        self.service_name = credential.service.name
        self.service_port = credential.service.port
        self.service_protocol = credential.service.protocol
        self.service_url = credential.service.url
        self.check = credential.command_output.result.check
        self.category = credential.command_output.result.category
        self.tool_used = credential.command_output.result.tool_used
        self.command_output_id = credential.command_output.id

class Product:
    def __init__(self, product):
        self.id = product.id
        self.product_type = product.type
        self.product_name = product.name
        self.product_version = product.version
        cpe = cpe_match.get(product.name)
        if cpe:
            self.product_cpe = '{}{}'.format(
                cpe, ':{}'.format(product.version) if product.version else '')
        else:
            self.product_cpe = None
        self.host_ip = product.service.host.ip
        self.host_hostname = product.service.host.hostname
        self.service_id = product.service.id
        self.service_name = product.service.name
        self.service_port = product.service.port
        self.service_protocol = product.service.protocol
        self.service_url = product.service.url        


class Vuln:
    def __init__(self, vuln):
        self.id = vuln.id
        self.vuln_name = vuln.name
        self.vuln_location = vuln.location
        self.vuln_reference = vuln.reference
        self.vuln_score = vuln.score
        self.vuln_link = vuln.link
        self.vuln_exploit_available = vuln.exploit_available
        self.vuln_exploited = vuln.exploited
        self.host_ip = vuln.service.host.ip
        self.host_hostname = vuln.service.host.hostname
        self.service_id = vuln.service.id
        self.service_name = vuln.service.name
        self.service_port = vuln.service.port
        self.service_protocol = vuln.service.protocol
        self.service_url = vuln.service.url
        self.check = vuln.command_output.result.check
        self.category = vuln.command_output.result.category
        self.tool_used = vuln.command_output.result.tool_used
        self.command_output_id = vuln.command_output.id


class Result:
    def __init__(self, result):
        self.id = result.id
        self.category = result.category
        self.check = result.check
        check = settings.services[result.service.name]['checks'].get_check(self.check)
        self.check_description = check.description if check else ''
        self.tool_used = result.tool_used
        self.start_time = result.start_time
        self.end_time = result.end_time
        self.duration = result.duration
        self.command_outputs = list(map(lambda x: CommandOutput(x), result.command_outputs))


class ServiceWithAll(Service):
    def __init__(self, service):
        super().__init__(service)
        self.credentials = list(map(lambda x: Credential(x), service.credentials))
        self.vulns = list(map(lambda x: Vuln(x), service.vulns))
        self.results = list(map(lambda x: Result(x), service.results))
