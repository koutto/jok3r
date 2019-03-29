#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Requester > Services
###
from six.moves.urllib.parse import urlparse
from sqlalchemy.orm import contains_eager

from lib.core.Target import Target
from lib.requester.Requester import Requester
from lib.utils.NetUtils import NetUtils
from lib.utils.StringUtils import StringUtils
from lib.utils.WebUtils import WebUtils
from lib.db.Credential import Credential
from lib.db.Host import Host
from lib.db.Mission import Mission
from lib.db.Service import Service, Protocol
from lib.output.Output import Output
from lib.output.Logger import logger


class ServicesRequester(Requester):

    def __init__(self, sqlsession):
        query = sqlsession.query(Service).join(Host).join(Mission)\
                          .options(contains_eager(Service.host))
        super().__init__(sqlsession, query)


    #------------------------------------------------------------------------------------

    def show(self):
        """Display selected services"""
        results = self.get_results()

        if not results:
            logger.warning('No service to display')
        else:
            data = list()
            columns = [
                'id',
                'IP',
                #'Hostname',
                'Port',
                'Proto',
                'Service',
                'Banner',
                'URL',
                'Comment/Title',
                'Checks',
                'Creds',
            ]
            for r in results:
                # Creds numbers
                nb_userpass  = r.get_nb_credentials(single_username=False)
                nb_usernames = r.get_nb_credentials(single_username=True)
                nb_creds = '{}{}{}'.format(
                    '{}'.format(Output.colored(str(nb_userpass),  color='green' \
                            if nb_userpass > 0 else None)) if nb_userpass > 0 else '',
                    '/' if nb_userpass > 0 and nb_usernames > 0 else '',
                    '{} user(s)'.format(Output.colored(str(nb_usernames), color='yellow' \
                            if nb_usernames > 0 else None)) if nb_usernames > 0 else '')

                # Col "Comment/Title" (title is for HTML title for HTTP)
                if r.html_title:
                    comment = r.html_title
                else:
                    comment = r.comment

                data.append([
                    r.id,
                    r.host.ip,
                    #r.host.hostname,
                    r.port,
                    {Protocol.TCP: 'tcp', Protocol.UDP: 'udp'}.get(r.protocol),
                    r.name,
                    StringUtils.wrap(r.banner, 55),
                    StringUtils.wrap(r.url, 50),
                    StringUtils.shorten(comment, 40),
                    len(r.results),
                    nb_creds,
                ])
            Output.table(columns, data, hrules=False)


    #------------------------------------------------------------------------------------
    
    def add_service(self, 
                    ip, 
                    port, 
                    protocol, 
                    service, 
                    services_config,
                    grab_banner_nmap=True,
                    reverse_dns=True, 
                    availability_check=True):
        """
        Add a service into the current mission scope in database.

        :param str ip: IP address to add
        :param str hostname: Hostname
        :param int port: Port number
        :param str protocol: Protocol (tcp/udp)
        :param str service: Service name
        :param bool grab_banner_nmap: If set to True, run Nmap to grab server banner
        :return: Status
        :rtype: bool
        """
        proto = {'tcp': Protocol.TCP, 'udp': Protocol.UDP}.get(protocol, Protocol.TCP)

        service = Service(
            port     = int(port),
            protocol = proto,
            name     = service)
        service.host = Host(ip=ip)
        try:
            target = Target(service, services_config)
        except Exception as e:
            logger.error(e)
            return False

        matching_service = self.sqlsess.query(Service).join(Host).join(Mission)\
                                       .filter(Mission.name == self.current_mission)\
                                       .filter(Host.ip == service.host.ip)\
                                       .filter(Service.port == int(port))\
                                       .filter(Service.protocol == proto).first()

        if matching_service:
            logger.warning('Service already present into database')
            return False

        else:

            up = target.smart_check(
                reverse_dns, 
                availability_check, 
                grab_banner_nmap)

            if up:
                # Add service in db (and host if not existing)
                matching_host = self.sqlsess.query(Host).join(Mission)\
                                        .filter(Mission.name == self.current_mission)\
                                        .filter(Host.ip == service.host.ip).first()
                new_host = Host(ip=service.host.ip, hostname=service.host.hostname)
                if matching_host:
                    matching_host.merge(new_host)
                    self.sqlsess.commit()
                    service.host = matching_host
                else:
                    mission = self.sqlsess.query(Mission)\
                                  .filter(Mission.name == self.current_mission).first()
                    new_host.mission = mission
                    service.host = new_host
                    self.sqlsess.add(new_host)

                self.sqlsess.add(service)
                self.sqlsess.commit()

                logger.success('Service added: host {ip} | port {port}/{proto} | ' \
                    'service {service}'.format(
                        ip=service.host.ip, 
                        port=port, 
                        proto=protocol, 
                        service=service.name))
                return True

            else:
                logger.error('Service is not reachable, therefore it is not added')
                return False


    #------------------------------------------------------------------------------------

    def add_url(self, 
                url,
                services_config,
                reverse_dns=True, 
                availability_check=True, 
                grab_banner_nmap=True,
                web_technos_detection=True):
        """
        Add a URL into the current mission scope in database.

        :param str url: URL to add
        :param bool grab_banner_nmap: If set to True, run Nmap to grab server banner
        :param bool grab_html_title:  If set to True, grab title of HTML page (text in
            <title> tags) and put it as comment for HTTP service
        :return: Status
        :rtype: bool
        """
        matching_service = self.sqlsess.query(Service).join(Host).join(Mission)\
                                       .filter(Mission.name == self.current_mission)\
                                       .filter(Service.url == url).first()
        if matching_service:
            logger.warning('URL already present into database')
            return False

        else:
            service = Service(
                name     = 'http',
                protocol = Protocol.TCP,
                url      = url)
            service.host = Host() # Update in target.smart_check()
            try:
                target = Target(service, services_config)
            except Exception as e:
                logger.error(e)
                return False

            up = target.smart_check(
                reverse_dns, 
                availability_check, 
                grab_banner_nmap,
                web_technos_detection)

            if up:
                matching_host = self.sqlsess.query(Host).join(Mission)\
                                            .filter(Mission.name == self.current_mission)\
                                            .filter(Host.ip == service.host.ip).first()
                new_host = Host(ip=service.host.ip, hostname=service.host.hostname)
                if matching_host:
                    matching_host.merge(new_host)
                    self.sqlsess.commit()
                    service.host = matching_host
                else:
                    mission = self.sqlsess.query(Mission)\
                                  .filter(Mission.name == self.current_mission).first()
                    new_host.mission = mission
                    service.host = new_host
                    self.sqlsess.add(new_host)

                self.sqlsess.add(service)
                self.sqlsess.commit()
                logger.success('Service/URL added: {url}'.format(url=url))
                return True

            else:
                logger.error('URL is not reachable, therefore it is not added')
                return False


    #------------------------------------------------------------------------------------

    def add_target(self, target):
        """
        Add a new service into the current mission scope in database from a Target 
        object.

        :param Target target: Target to add
        """
        mission = self.sqlsess.query(Mission)\
                      .filter(Mission.name == self.current_mission).first()

        matching_service = self.sqlsess.query(Service)\
                              .join(Host)\
                              .join(Mission)\
                              .filter(Host.ip == target.get_ip())\
                              .filter(Mission.name == self.current_mission)\
                              .filter(Service.name == target.get_service_name())\
                              .filter(Service.port == target.get_port())\
                              .filter(Service.protocol == target.get_protocol2())\
                              .filter(Service.url == target.get_url()).first()

        # If service already exists in db, update it if necessary
        if matching_service:
            logger.info('A matching service has been found in the database')
            matching_service.merge(target.service)
            self.sqlsess.commit()
            # Make sure to replace target info by newly created service
            target.service = matching_service 

        # Add host in db if it does not exist or update its info (merging)
        else:
            host = self.sqlsess.query(Host).join(Mission)\
                               .filter(Mission.name == self.current_mission)\
                               .filter(Host.ip == target.get_ip()).first()
            if host:
                host.merge(target.service.host)
                self.sqlsess.commit()
                target.service.host = host
            else:
                self.sqlsess.add(target.service.host)
                mission.hosts.append(target.service.host)                              
                self.sqlsess.commit()

            # Add service in db
            self.sqlsess.add(target.service)
            self.sqlsess.commit()

        logger.success('{action}: host {ip} | port {port}/{proto} | ' \
            'service {service}'.format(
            action  = 'Updated' if matching_service else 'Added',
            ip      = target.get_ip(),
            port    = target.get_port(),
            proto   = target.get_protocol(),
            service = target.get_service_name()))


    #------------------------------------------------------------------------------------

    def add_cred(self, username, password, auth_type=None):
        """
        Add new credential for selected service(s).

        :param str username: Username
        :param str password: Password (None if unknown)
        :param str auth_type: Authentication type for HTTP service
        """
        results = self.get_results()
        if not results:
            logger.error('No matching service')
        else:
            for r in results:
                cred = self.sqlsess.query(Credential).join(Service)\
                                   .filter(Service.id == r.id)\
                                   .filter(Credential.username == username)\
                                   .filter(Credential.password == password)\
                                   .filter(Credential.type == auth_type).first()
                if not cred:
                    cred = Credential(
                        username = username,
                        password = password,
                        type     = auth_type if r.name == 'http' else None)

                    self.sqlsess.add(cred)
                    r.credentials.append(cred)

                    username = '<empty>' if cred.username == '' else cred.username
                    password = {'': '<empty>', None: '<???>'}.get(
                        cred.password, cred.password)
                    auth_type = '('+str(auth_type)+')' if \
                        (auth_type and r.name == 'http') else ''
                    hostname = '('+r.host.hostname+')' if r.host.hostname else ''
                    protocol = {Protocol.TCP: 'tcp', Protocol.UDP: 'udp'}.get(r.protocol)

                    logger.success('Credential {username}/{password}{auth_type} ' \
                        'added to service {service} host={ip}{hostname} ' \
                        'port={port}/{proto}'.format(
                            username  = username,
                            password  = password,
                            auth_type = auth_type,
                            service   = r.name,
                            ip        = r.host.ip,
                            hostname  = hostname,
                            port      = r.port,
                            proto     = protocol))
            self.sqlsess.commit() 


    #------------------------------------------------------------------------------------

    def edit_comment(self, comment):
        """
        Edit comment of selected services.
        :param str comment: New comment
        """
        results = self.get_results()
        if not results:
            logger.error('No matching service')
        else:
            for r in results:
                r.comment = comment
            self.sqlsess.commit()
            logger.success('Comment edited')


    def switch_https(self):
        """Switch between HTTP and HTTPS on selected services"""
        results = self.get_results()
        if not results:
            logger.error('No matching service')
        else:
            for r in results:
                if r.url:
                    r.url = WebUtils.switch_http_https(r.url)
            self.sqlsess.commit()
            logger.success('Switch done')



    def delete(self):
        """Delete selected services"""
        results = self.get_results()
        if not results:
            logger.error('No matching service')
        else:
            for r in results:
                logger.info('Service {service} host={ip}{hostname} ' \
                    'port={port}/{proto} deleted'.format(
                    service  = r.name,
                    ip       = r.host.ip,
                    hostname = '('+r.host.hostname+')' if r.host.hostname else '',
                    port     = r.port,
                    proto    = {Protocol.TCP: 'tcp', Protocol.UDP: 'udp'}.get(
                        r.protocol)))

                self.sqlsess.delete(r)
                self.sqlsess.commit()

                # Delete host if no more service in it
                if len(r.host.services) == 0:
                    self.sqlsess.delete(r.host)



            


    #------------------------------------------------------------------------------------

    def order_by(self, column):
        """
        Add ORDER BY statement
        :param str column: Column name to order by
        """
        mapping = {
            'ip'       : Host.ip,
            'hostname' : Host.hostname,
            'port'     : Service.port,
            'proto'    : Service.protocol,
            'service'  : Service.name,
            'banner'   : Service.banner,
            'url'      : Service.url,
            'comment'  : Service.comment,
        }

        if column.lower() not in mapping.keys():
            logger.warning('Ordering by column {col} is not supported'.format(
                col=column.lower()))
            return

        super().order_by(mapping[column.lower()])


    #------------------------------------------------------------------------------------

    def are_only_http_services_selected(self):
        """Check if selected services are only HTTP services"""
        results = self.get_results()
        for service in results:
            if service.name != 'http':
                return False
        return True