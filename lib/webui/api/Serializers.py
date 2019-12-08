#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Web-UI > Backend > Serializers
###
from flask_restplus import fields

from lib.db.Service import Protocol
from lib.webui.api.Api import api


class ProtocolString(fields.Raw):
    def format(self, value):
        return { 
            'Protocol.TCP': 'tcp',
            'Protocol.UDP': 'udp'
        }.get(value, 'tcp')



mission = api.model('Mission', {
    'id': fields.Integer(readonly=True, description='The mission unique identifier'),
    'name': fields.String(required=True, description='Mission name'),
    'comment': fields.String(description='Mission comment'),
    'creation_date': fields.DateTime(description='Creation datetime of the mission'),
    'hosts_count': fields.Integer(description='Number of hosts in the mission'),
    'services_count': fields.Integer(description='Number of services in the mission'),
    'creds_count': fields.Integer(description='Credentials (username & password) count'),
    'users_count': fields.Integer(description='Single usernames count'),
    'products_count': fields.Integer(description='Detected products count'),
    'vulns_count': fields.Integer(description='Vulnerabilities count'),
})

service_short = api.model('ServiceShort', {
    'id': fields.Integer(description='Service identifier'),
    'port': fields.Integer(description='Port number'),
    'protocol': fields.String(description='Protocol'),
    'name': fields.String(description='Service name'),
})


host = api.model('Host', {
    'id': fields.Integer(readonly=True, description='The host unique identifier'),
    'ip': fields.String(required=True, description='Host IP address'),
    'hostname': fields.String(description='Hostname'),
    'os': fields.String(description='Host OS name'),
    'os_vendor': fields.String(description='Host OS vendor name'),
    'os_family': fields.String(description='Host OS family'),
    'mac': fields.String(description='Host MAC address'),
    'vendor': fields.String(description='Host vendor name'),
    'type': fields.String(description='Host type'),
    'comment': fields.String(description='Host comment'),
    'tcp_count': fields.Integer(description='TCP services count'),
    'udp_count': fields.Integer(description='UDP services count'),
    'creds_count': fields.Integer(description='Credentials (username & password) count'),
    'users_count': fields.Integer(description='Single usernames count'),
    'vulns_count': fields.Integer(description='Vulnerabilities count'),
    'services_list': fields.List(fields.Nested(service_short)),
    'mission_id': fields.Integer(description='Mission identifier'),
})

command_output = api.model('Command Output', {
    'id': fields.Integer(readonly=True, description='The command output unique identifier'),
    'cmdline': fields.String(description='Command line'),
    'output': fields.String(description='Command output'),
    'check': fields.String(description='Security check name'),
    'category': fields.String(description='Category name'),
    'tool_used': fields.String(description='Tool used for the check'),
})

result = api.model('Result', {
    'id': fields.Integer(readonly=True, description='The result unique identifier'),
    'category': fields.String(description='Category name'),
    'check': fields.String(description='Security check name'),
    'check_description': fields.String(description='Description of the check'),
    'tool_used': fields.String(description='Tool used for the check'),
    'start_time': fields.DateTime(description='Start time of check'),
    'end_time': fields.DateTime(description='End time of check'),
    'duration': fields.Integer(description='Duration of check (in seconds)'),
    'command_outputs': fields.List(fields.Nested(command_output)),
})


credential = api.model('Credential', {
    'id': fields.Integer(readonly=True, description='The credential unique identifier'),
    'type': fields.String(description='Credential type'),
    'username': fields.String(description='Username'),
    'password': fields.String(description='Password'),
    'comment': fields.String(description='Credential comment'),
    'host_ip': fields.String(description='Host IP address'),
    'host_hostname': fields.String(description='Hostname'),
    'service_id': fields.Integer(description='Service identifier'),
    'service_name': fields.String(description='Service name'),
    'service_port': fields.Integer(description='Port number'),
    'service_protocol': ProtocolString(attribute='protocol', description='Protocol (tcp/udp)', default='tcp', enum=['tcp', 'udp']),
    'service_url': fields.String(description='Service URL'),
    'check': fields.String(description='Check name'),
    'category': fields.String(description='Check category'),
    'tool_used': fields.String(description='Tool used'),
    'command_output_id': fields.Integer(description='Command output identifier'),
})

option = api.model('Option', {
    'id': fields.Integer(readonly=True, description='The option unique identifier'),
    'name': fields.String(description='Option name'),
    'value': fields.String(description='Option value'),
})

product = api.model('Product', {
    'id': fields.Integer(readonly=True, description='The product unique identifier'),
    'product_type': fields.String(description='Product type'),
    'product_name': fields.String(description='Product name'),
    'product_version': fields.String(description='Product version'), 
    'host_ip': fields.String(description='Host IP address'),
    'host_hostname': fields.String(description='Hostname'),
    'service_id': fields.Integer(description='Service identifier'),
    'service_name': fields.String(description='Service name'),
    'service_port': fields.Integer(description='Port number'),
    'service_protocol': ProtocolString(attribute='protocol', description='Protocol (tcp/udp)', default='tcp', enum=['tcp', 'udp']),
    'service_url': fields.String(description='Service URL'),
})

vuln = api.model('Vuln', {
    'id': fields.Integer(readonly=True, description='The vulnerability unique identifier'),
    'vuln_name': fields.String(description='Vulnerability name'),
    'vuln_location': fields.String(description='Vulnerability location'),
    'vuln_reference': fields.String(description='Vulnerability reference identifier'),
    'vuln_score': fields.Float(description='Vulnerability CVSS score'),
    'vuln_link': fields.String(description='Vulnerability information link'),
    'vuln_exploit_available': fields.Boolean(description='Boolean indicating if exploit is available', default=False),
    'vuln_exploited': fields.Boolean(description='Boolean indicating if vulnerability has been exploited', default=False),
    'host_ip': fields.String(description='Host IP address'),
    'host_hostname': fields.String(description='Hostname'),
    'service_id': fields.Integer(description='Service identifier'),
    'service_name': fields.String(description='Service name'),
    'service_port': fields.Integer(description='Port number'),
    'service_protocol': ProtocolString(attribute='protocol', description='Protocol (tcp/udp)', default='tcp', enum=['tcp', 'udp']),
    'service_url': fields.String(description='Service URL'),
    'check': fields.String(description='Check name'),
    'category': fields.String(description='Check category'),
    'tool_used': fields.String(description='Tool used'),
    'command_output_id': fields.Integer(description='Command output identifier'),
})

checks_category = api.model('ChecksCategory', {
    'name': fields.String(),
    'count': fields.Integer(),
})

service = api.model('Service', {
    'id': fields.Integer(readonly=True, description='The service unique identifier'),
    'name': fields.String(description='Service name'),
    'name_original': fields.String(description='Service original name (as given by Nmap/Shodan'),
    'host_ip': fields.String(description='Host IP address'),
    'host_hostname': fields.String(description='Hostname'),
    'host_type': fields.String(description='Host type'),
    'host_os': fields.String(description='Host OS name'),
    'host_os_vendor': fields.String(description='Host OS vendor name'),
    'host_os_family': fields.String(description='Host OS family'),
    'host_vendor': fields.String(description='Host device vendor'),
    'host_comment': fields.String(description='Host comment'),
    'port': fields.Integer(description='Port number'),
    'protocol': ProtocolString(attribute='protocol', description='Protocol (tcp/udp)', default='tcp', enum=['tcp', 'udp']),
    'encrypted': fields.Boolean(description='Boolean indicating if encrypted protocol (SSL/TLS)', default=False),
    'url': fields.String(description='Target URL (for HTTP(s))'),
    'up': fields.Boolean(description='Status', default=True),
    'banner': fields.String(description='Service banner'),
    'html_title': fields.String(description='HTML title (for HTTP(s))'),
    'http_headers': fields.String(description='HTTP Headers'),
    'web_technos': fields.String(description='Web technologies (for HTTP(s)) (unused)'),
    'comment': fields.String(description='Service comment'),
    #'credentials': fields.List(fields.Nested(credential)),
    'options': fields.List(fields.Nested(option)),
    'products': fields.List(fields.Nested(product)),
    #'vulns': fields.List(fields.Nested(vuln)),
    'creds_count': fields.Integer(description='Credentials (username & password) count'),
    'users_count': fields.Integer(description='Single usernames count'),
    'vulns_count': fields.Integer(description='Vulnerabilities count'),
    'checks_categories': fields.List(fields.Nested(checks_category)),
    'host_id': fields.Integer(description='Host identifier'),
    'screenshot': fields.String(description='Web screenshot'),
    'screenshot_thumb': fields.String(description='Web screenshot thumbnail'),
})


service_with_all = api.inherit('Service with all related data', service, {
    'credentials': fields.List(fields.Nested(credential)),
    'vulns': fields.List(fields.Nested(vuln)),
    'results': fields.List(fields.Nested(result)),
})

mission_with_hosts = api.inherit('Mission with hosts', mission, {
    'hosts': fields.List(fields.Nested(host))
})

mission_with_services = api.inherit('Mission with services', mission, {
    'services': fields.List(fields.Nested(service))
})

mission_with_web = api.inherit('Mission with HTTP services', mission, {
    'services': fields.List(fields.Nested(service)),
    'screenshots': fields.List(fields.Nested(api.model('Screenshot', {
        'caption': fields.String(description='Screenshot caption'),
        'source': fields.Nested(api.model('Screenshot source', {
            'regular': fields.String(description='Screenshot URL'),
            'thumbnail': fields.String(description='Screenshot thumbnail URL')
        }))
    })))
})

mission_with_options = api.inherit('Mission with options', mission, {
    'options': fields.List(fields.Nested(option))
})

mission_with_credentials = api.inherit('Mission with credentials', mission, {
    'credentials': fields.List(fields.Nested(credential))
})

mission_with_products = api.inherit('Mission with products', mission, {
    'products': fields.List(fields.Nested(product))
})

mission_with_vulns = api.inherit('Mission with vulns', mission, {
    'vulns': fields.List(fields.Nested(vuln))
})

host_with_services = api.inherit('Host with services', host, {
    'services': fields.List(fields.Nested(service))
})


tool = api.model('Tool', {
    'tool_name': fields.String(description='Tool name'),
    'target_service': fields.String(description='Targeted service name'),
    'is_installed': fields.Boolean(description='Installation status'),
    'last_update': fields.String(description='Last update date (if installed)'),
    'description': fields.String(description='Tool description'),
})


check = api.model('Security Check', {
    'check_name': fields.String(description='Security check name'),
    'category': fields.String(description='Category of check'),
    'service': fields.String(description='Service name targeted by the check'),
    'description': fields.String(description='Description of the check'),
    'tool': fields.String(description='Tool used by the check'),
    'nb_commands': fields.Integer(description='Number of commands run by the check'),
})

checks_with_supported_services = api.model('Security Checks and supported services', {
    'services': fields.List(fields.String(description='Service name')),
    'checks': fields.List(fields.Nested(check)),
})