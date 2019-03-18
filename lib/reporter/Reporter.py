#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Reporter > Reporter
###
import datetime

from lib.db.Service import Protocol
from lib.core.Config import *
from lib.output.Logger import logger
from lib.requester.ServicesRequester import ServicesRequester
from lib.requester.HostsRequester import HostsRequester
from lib.requester.OptionsRequester import OptionsRequester
from lib.utils.FileUtils import FileUtils
from lib.utils.StringUtils import StringUtils


class Reporter:

    def __init__(self, mission, sqlsession, output_path):
        """
        :param str mission: Mission for which the HTML report will be generated
        :param Session sqlsession: SQLAlchemy session
        :param str output_path: Output path where directory storing HTML files must
            be written
        """
        self.mission = mission
        self.sqlsession = sqlsession
        self.output_path = output_path


    def run(self):

        # Create report directory
        dirname = '{mission}-{datetime}'.format(
            mission=StringUtils.clean(self.mission.replace(' ','_'), 
                allowed_specials=('_', '-')),
            datetime=datetime.datetime.now().strftime('%Y%m%d%H%M%S'))
        report_dir = self.output_path + '/' + dirname

        if not FileUtils.create_directory(report_dir):
            logger.error('Unable to create report directory inside "{path}"'.format(
                path=self.output_path))
            return False

        # Create index.html
        index = self.__generate_index()
        if FileUtils.write(report_dir + '/index.html', index):
            logger.info('index.html file generated')
        else:
            logger.error('An error occured while generating index.html')
            return False

        logger.success('HTML Report written with success in: {path}'.format(
            path=report_dir))

        return True


    def __generate_index(self):
        """Generate HTML index file from template"""
        tpl = FileUtils.read(REPORT_TPL_DIR + '/index.tpl.html')

        tpl = tpl.replace('{{MISSION_NAME}}', self.mission)
        tpl = tpl.replace('{{TABLE_SERVICES_CONTENT}}', self.__generate_table_services())
        tpl = tpl.replace('{{TABLE_HOSTS_CONTENT}}', self.__generate_table_hosts())

        return tpl


    def __generate_table_services(self):
        """
        Generate the table with all services registered in the mission
        """

        req = ServicesRequester(self.sqlsession)
        req.select_mission(self.mission)
        services = req.get_results()

        if len(services) == 0:
            html = """
            <tr class="notfound">
                <td colspan="9">No record found</td>
            </tr>
            """
        else:
            html = ''
            for service in services:

                nb_userpass  = service.get_nb_credentials(single_username=False)
                nb_usernames = service.get_nb_credentials(single_username=True)
                nb_creds = '{}{}{}'.format(
                    '<span class="text-green">{}</span>'.format(str(nb_userpass)) \
                        if nb_userpass > 0 else '',
                    '/' if nb_userpass > 0 and nb_usernames > 0 else '',
                    '<span class="text-yellow">{}</span> user(s)'.format(
                        str(nb_usernames)) if nb_usernames > 0 else '')

                html += """
                <tr>
                    <td>{ip}</td>
                    <td>{port}</td>
                    <td>{proto}</td>
                    <td>{service}</td>
                    <td>{banner}</td>
                    <td>{url}</td>
                    <td>{comment}</td>
                    <td>{checks}</td>
                    <td>{creds}</td>
                </tr>
                """.format(
                    ip=service.host.ip,
                    port=service.port,
                    proto={Protocol.TCP: 'tcp', Protocol.UDP: 'udp'}.get(
                        service.protocol),
                    service=service.name,
                    banner=StringUtils.wrap(service.banner, 55),
                    url='<a href="{}" title="{}">{}</a>'.format(
                        service.url, service.url, StringUtils.shorten(service.url, 50)) \
                        if service.url else '',
                    comment=StringUtils.shorten(service.comment, 40),
                    checks=len(service.results),
                    creds=nb_creds)
        return html


    def __generate_table_hosts(self):
        """
        Generate the table with all hosts registered in the mission
        """
        
        req = HostsRequester(self.sqlsession)
        req.select_mission(self.mission)
        hosts = req.get_results()

        if len(hosts) == 0:
            html = """
            <tr class="notfound">
                <td colspan="5">No record found</td>
            </tr>
            """
        else:
            html = ''
            for host in hosts:

                html += """
                <tr>
                    <td>{ip}</td>
                    <td>{hostname}</td>
                    <td>{os}</td>
                    <td>{comment}</td>
                    <td>{nb_services}</td>
                </tr>
                """.format(
                    ip=host.ip,
                    hostname=host.hostname if host.hostname != str(host.ip) else '',
                    os=host.os,
                    comment=host.comment,
                    nb_services=len(host.services))

        return html


    def __generate_table_options(self):
        """
        Generate the table with all context-specific options registered in the mission
        """
        
        req = OptionsRequester(self.sqlsession)
        req.select_mission(self.mission)
        options = req.get_results()

        if len(hosts) == 0:
            html = """
            <tr class="notfound">
                <td colspan="7">No record found</td>
            </tr>
            """
        else:
            html = ''
            for host in hosts:

                html += """
                <tr>
                    <td>{ip}</td>
                    <td>{hostname}</td>
                    <td>{os}</td>
                    <td>{comment}</td>
                    <td>{nb_services}</td>
                </tr>
                """.format(
                    ip=host.ip,
                    hostname=host.hostname if host.hostname != str(host.ip) else '',
                    os=host.os,
                    comment=host.comment,
                    nb_services=len(host.services))

        return html