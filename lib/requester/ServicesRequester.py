# -*- coding: utf-8 -*-
###
### Requester > Services
###
from six.moves.urllib.parse import urlparse
from sqlalchemy.orm import contains_eager

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
        query = sqlsession.query(Service).join(Host).join(Mission).options(contains_eager(Service.host))
        super().__init__(sqlsession, query)

    def show(self):
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
                'Comment',
                'Checks',
                'Creds',
            ]
            for r in results:
                nb_userpass  = r.get_nb_credentials(single_username=False)
                nb_usernames = r.get_nb_credentials(single_username=True)
                nb_creds = '{}{}{}'.format(
                    '{}'.format(Output.colored(str(nb_userpass),  color='green' \
                            if nb_userpass > 0 else None)) if nb_userpass > 0 else '',
                    '/' if nb_userpass > 0 and nb_usernames > 0 else '',
                    '{} users'.format(Output.colored(str(nb_usernames), color='yellow' \
                            if nb_usernames > 0 else None)) if nb_usernames > 0 else '')

                data.append([
                    r.id,
                    r.host.ip,
                    #r.host.hostname,
                    r.port,
                    {Protocol.TCP: 'tcp', Protocol.UDP: 'udp'}.get(r.protocol),
                    r.name,
                    StringUtils.wrap(r.banner, 65),
                    StringUtils.wrap(r.url, 50),
                    StringUtils.wrap(r.comment, 50),
                    len(r.results),
                    nb_creds,
                ])
            Output.table(columns, data, hrules=False)


    def edit_comment(self, comment):
        results = self.get_results()
        if not results:
            logger.error('No matching service')
        else:
            for r in results:
                r.comment = comment
            self.sqlsess.commit()
            logger.success('Comment edited')


    def switch_https(self):
        results = self.get_results()
        if not results:
            logger.error('No matching service')
        else:
            for r in results:
                if r.url:
                    r.url = WebUtils.switch_http_https(r.url)
            self.sqlsess.commit()
            logger.success('Switch done')


    def add_service(self, ip, hostname, port, protocol, service):
        protocol = {'tcp': Protocol.TCP, 'udp': Protocol.UDP}.get(protocol, Protocol.TCP)
        matching_service = self.sqlsess.query(Service).join(Host).join(Mission)\
                                       .filter(Mission.name == self.current_mission)\
                                       .filter(Host.ip == ip)\
                                       .filter(Service.port == int(port))\
                                       .filter(Service.protocol == protocol).first()
        if protocol == Protocol.TCP:
            up = NetUtils.is_tcp_port_open(ip, port)
        else:
            up = NetUtils.is_udp_port_open(ip, port)

        if matching_service:
            logger.warning('Service already present into database')
        else:
            if not up:
                logger.warning('Port seems to be closed !')
            host = self.sqlsess.query(Host).join(Mission)\
                               .filter(Mission.name == self.current_mission)\
                               .filter(Host.ip == ip).first()
            if not host:
                mission = self.sqlsess.query(Mission).filter(Mission.name == self.current_mission).first()
                host = Host(ip=ip, hostname=hostname)
                host.mission = mission
                self.sqlsess.add(host)
            self.sqlsess.add(Service(name     = service,
                                     port     = int(port),
                                     protocol = protocol,
                                     up       = up,
                                     host     = host))
            self.sqlsess.commit()
            logger.success('Service added')


    def add_url(self, url):
        matching_service = self.sqlsess.query(Service).join(Host).join(Mission)\
                                       .filter(Mission.name == self.current_mission)\
                                       .filter(Service.url == url).first()
        if matching_service:
            logger.warning('URL already present into database')
        else:
            is_reachable, status, resp_headers = WebUtils.is_url_reachable(url)
            http_headers = '\n'.join("{}: {}".format(key,val) for (key,val) in resp_headers.items())

            if is_reachable:
                comment = WebUtils.grab_html_title(url)
                logger.info('HTTP Headers:')
                print(http_headers)
                logger.info('Title: {}'.format(comment))
            else:
                comment = 'Not reachable'
                logger.warning('URL seems not to be reachable')

            parsed = urlparse(url)
            if NetUtils.is_valid_ip(parsed.hostname):
                ip = parsed.hostname
                hostname = NetUtils.reverse_dns_lookup(parsed.hostname)
            else:
                ip = NetUtils.dns_lookup(parsed.hostname)
                if not ip:
                    logger.warning('Host cannot be resolved')
                    return
                hostname = parsed.hostname
            port = WebUtils.get_port_from_url(url)

            # Add host in db if it does not exist
            host = self.sqlsess.query(Host).filter(Host.ip == ip).first()
            if not host:
                mission = self.sqlsess.query(Mission).filter(Mission.name == self.current_mission).first()
                host = Host(ip=ip, hostname=hostname)
                host.mission = mission
                self.sqlsess.add(host)

            # Add service in db
            self.sqlsess.add(Service(name         = 'http',
                                     port         = port,
                                     protocol     = Protocol.TCP,
                                     url          = url,
                                     up           = is_reachable,
                                     http_headers = http_headers,
                                     comment      = comment,
                                     host         = host))
            self.sqlsess.commit()
            logger.success('Service/URL added')


    def add_target(self, target):
        mission = self.sqlsess.query(Mission).filter(Mission.name == self.current_mission).first()

        matching_service = self.sqlsess.query(Service)\
                              .join(Host)\
                              .join(Mission)\
                              .filter(Host.ip == target.get_ip())\
                              .filter(Mission.name == self.current_mission)\
                              .filter(Service.name == target.get_service_name())\
                              .filter(Service.port == target.get_port())\
                              .filter(Service.protocol == target.get_protocol2())\
                              .filter(Service.url == target.get_url()).first()

        if matching_service:
            # If service exists in db, update it if necessary
            logger.info('A matching service has been found in the database')
            matching_service.merge(target.service)
            self.sqlsess.commit()
            target.service = matching_service # make sure to replace target info by newly created service
        else:
            # Add host in db if it does not exist or update its info (merging)
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
        logger.success('{action}: host {ip} | port {port}/{proto} | service {service}'.format(
            action  = 'Updated' if matching_service else 'Added',
            ip      = target.get_ip(),
            port    = target.get_port(),
            proto   = target.get_protocol(),
            service = target.get_service_name()))


    def add_cred(self, username, password, auth_type=None):
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
                    cred = Credential(username = username,
                                      password = password,
                                      type     = auth_type if r.name == 'http' else None) # auth type relevant only for http
                    self.sqlsess.add(cred)
                    r.credentials.append(cred)
                    logger.success('Credential {username}/{password}{auth_type} added to service {service} '\
                        'host={ip}{hostname} port={port}/{proto}'.format(
                            username  = '<empty>' if cred.username == '' else cred.username,
                            password  = {'': '<empty>', None: '<???>'}.get(cred.password, cred.password),
                            auth_type = '('+str(auth_type)+')' if (auth_type and r.name == 'http') else '',
                            service   = r.name,
                            ip        = r.host.ip,
                            hostname  = '('+r.host.hostname+')' if r.host.hostname else '',
                            port      = r.port,
                            proto     = {Protocol.TCP: 'tcp', Protocol.UDP: 'udp'}.get(r.protocol)))
            self.sqlsess.commit() 


    def delete(self):
        results = self.get_results()
        if not results:
            logger.error('No matching service')
        else:
            for r in results:
                logger.info('Service {service} host={ip}{hostname} port={port}/{proto} deleted'.format(
                    service  = r.name,
                    ip       = r.host.ip,
                    hostname = '('+r.host.hostname+')' if r.host.hostname else '',
                    port     = r.port,
                    proto    = {Protocol.TCP: 'tcp', Protocol.UDP: 'udp'}.get(r.protocol)))
                self.sqlsess.delete(r)
            self.sqlsess.commit()


    def order_by(self, column):
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
            logger.warning('Ordering by column {col} is not supported'.format(col=column.lower()))
            return
        super().order_by(mapping[column.lower()])


    def are_only_http_services_selected(self):
        results = self.get_results()
        for service in results:
            if service.name != 'http':
                return False
        return True