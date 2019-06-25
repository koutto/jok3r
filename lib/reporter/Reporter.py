#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Reporter > Reporter
###
import ansi2html
import ast
import base64
import datetime
import re
import webbrowser

from lib.db.Screenshot import ScreenStatus
from lib.db.Service import Protocol
from lib.core.Config import *
from lib.core.Constants import *
from lib.output.Logger import logger
from lib.output.Output import Output
from lib.requester.Condition import Condition
from lib.requester.CredentialsRequester import CredentialsRequester
from lib.requester.Filter import Filter
from lib.requester.HostsRequester import HostsRequester
from lib.requester.OptionsRequester import OptionsRequester
from lib.requester.ProductsRequester import ProductsRequester
from lib.requester.ResultsRequester import ResultsRequester
from lib.requester.ServicesRequester import ServicesRequester
from lib.requester.VulnsRequester import VulnsRequester
from lib.screenshoter.ScreenshotsProcessor import ScreenshotsProcessor
from lib.utils.FileUtils import FileUtils
from lib.utils.ImageUtils import ImageUtils
from lib.utils.StringUtils import StringUtils


class Reporter:

    def __init__(self, mission, sqlsession, output_path, do_screens=True):
        """
        :param str mission: Mission for which the HTML report will be generated
        :param Session sqlsession: SQLAlchemy session
        :param str output_path: Output path where directory storing HTML files must
            be written
        :param bool do_screens: Boolean indicating if web page screenshots must be
            taken or not
        """
        self.mission = mission
        self.sqlsession = sqlsession
        self.output_path = output_path
        self.do_screens = do_screens


    def run(self):

        # Create report directory
        dirname = '{mission}-{datetime}'.format(
            mission=StringUtils.clean(self.mission.replace(' ','_'), 
                allowed_specials=('_', '-')),
            datetime=datetime.datetime.now().strftime('%Y%m%d%H%M%S'))
        self.output_path = self.output_path + '/' + dirname

        if not FileUtils.create_directory(self.output_path):
            logger.error('Unable to create report directory: "{path}"'.format(
                path=self.output_path))
            return False

        # Retrieve all services in selected mission
        req = ServicesRequester(self.sqlsession)
        req.select_mission(self.mission)
        services = req.get_results()

        # Generate screenshots 
        processor = ScreenshotsProcessor(self.mission, self.sqlsession)
        processor.run()

        screens_dir = self.output_path + '/screenshots'
        if not FileUtils.create_directory(screens_dir):
            logger.warning('Unable to create screenshots directory: "{path}"'.format(
                path=screens_dir))
        else:
            for service in services:
                if service.name == 'http' and service.screenshot is not None \
                        and service.screenshot.status == ScreenStatus.OK:

                    img_name = 'scren-{ip}-{port}-{id}'.format(
                        ip=str(service.host.ip),
                        port=service.port,
                        id=service.id)
                    path = screens_dir + '/' + img_name

                    ImageUtils.save_image(
                        service.screenshot.image, path + '.png')
                    ImageUtils.save_image(
                        service.screenshot.thumbnail, path + '.thumb.png')

        # Create index.html
        html = self.__generate_index()
        if FileUtils.write(self.output_path + '/index.html', html):
            logger.info('index.html file generated')
        else:
            logger.error('An error occured while generating index.html')
            return False

        # Create results-<service>.html (1 for each service)
        for service in services:
            # Useless to create page when no check has been run for the service
            if len(service.results) == 0:
                continue

            html = self.__generate_results_page(service)
            # Create a unique name for the service HTML file
            filename = 'results-{ip}-{port}-{service}-{id}.html'.format(
                ip=str(service.host.ip),
                port=service.port,
                service=service.name,
                id=service.id)
            if FileUtils.write(self.output_path + '/' + filename, html):
                logger.info('{filename} file generated'.format(
                    filename=filename))
            else:
                logger.error('An error occured while generating {filename}'.format(
                    filename=filename))
                return False

        logger.success('HTML Report written with success in: {path}'.format(
            path=self.output_path))
        logger.info('Important: If running from Docker container, make sure to run ' \
            '"xhost +" on the host before')
        if Output.prompt_confirm('Would you like to open the report now ?', 
                default=True):
            webbrowser.open(self.output_path + '/index.html')

        return True


    #------------------------------------------------------------------------------------
    # Index.html generation

    def __generate_index(self):
        """
        Generate HTML index code from template "index.tpl.html"
        """
        tpl = FileUtils.read(REPORT_TPL_DIR + '/index.tpl.html')

        tpl = tpl.replace('{{MISSION_NAME}}', self.mission)
        tpl = tpl.replace('{{TABLE_SERVICES_CONTENT}}', self.__generate_table_services())
        tpl = tpl.replace('{{TABLE_HOSTS_CONTENT}}', self.__generate_table_hosts())
        tpl = tpl.replace('{{TABLE_WEB_CONTENT}}', self.__generate_table_web())
        tpl = tpl.replace('{{TABLE_OPTIONS_CONTENT}}', self.__generate_table_options())
        tpl = tpl.replace('{{TABLE_PRODUCTS_CONTENT}}', self.__generate_table_products())
        tpl = tpl.replace('{{TABLE_CREDS_CONTENT}}', self.__generate_table_credentials())
        tpl = tpl.replace('{{TABLE_VULNS_CONTENT}}', self.__generate_table_vulns())

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
                <td colspan="11">No record found</td>
            </tr>
            """
        else:
            html = ''
            for service in services:

                hostname = service.host.hostname \
                    if service.host.ip != service.host.hostname else ''

                # Number of creds
                nb_userpass  = service.get_nb_credentials(single_username=False)
                nb_usernames = service.get_nb_credentials(single_username=True)
                nb_creds = '{}{}{}'.format(
                    '<span class="text-green">{}</span>'.format(str(nb_userpass)) \
                        if nb_userpass > 0 else '',
                    '/' if nb_userpass > 0 and nb_usernames > 0 else '',
                    '<span class="text-yellow">{}</span> user(s)'.format(
                        str(nb_usernames)) if nb_usernames > 0 else '')

                # Number of vulns
                if len(service.vulns) > 0:
                    nb_vulns = '<span class="text-green">{}</span>'.format(
                        len(service.vulns))
                else:
                    nb_vulns = '<span class="mdi mdi-window-close"></span>'


                technos = ''

                # For HTTP, respect a given order for technos for better readability
                if service.name == 'http':
                    product_types = (
                        'web-server',
                        'web-appserver',
                        'web-cms',
                        'web-language',
                        'web-framework',
                        'web-jslib'
                    )
                    for t in product_types:
                        product = service.get_product(t)
                        if product:
                            technos += '<span class="badge badge-{type} badge-light">' \
                                '{name}{version}</span>'.format(
                                    type=t,
                                    name=product.name,
                                    version=' '+str(product.version) \
                                        if product.version else '')
                else:
                    for p in service.products:
                        technos += '<span class="badge badge-generic badge-light">' \
                            '{name}{version}</span>'.format(
                                type=p.type,
                                name=p.name,
                                version=' '+str(p.version) if p.version else '')

                # Col "Comment/Title" (title is for HTML title for HTTP)
                if service.html_title:
                    comment = service.html_title
                else:
                    comment = service.comment

                # Results HTML page name
                results = 'results-{ip}-{port}-{service}-{id}.html'.format(
                    ip=str(service.host.ip),
                    port=service.port,
                    service=service.name,
                    id=service.id)

                html += """
                <tr{clickable}>
                    <td class="text-bold-green">{ip}</td>
                    <td>{hostname}</th>
                    <td>{port} /{proto}</td>
                    <td>{service}</td>
                    <td>{banner}</td>
                    <td>{technos}</td>
                    <td>{url}</td>
                    <td>{comment}</td>
                    <td>{checks}</td>
                    <td>{creds}</td>
                    <td>{vulns}</td>
                </tr>
                """.format(
                    clickable=' class="clickable-row" data-href="{results}"'.format(
                        results=results) if len(service.results) > 0 else '',
                    ip=service.host.ip,
                    hostname=hostname,
                    port=service.port,
                    proto={Protocol.TCP: 'tcp', Protocol.UDP: 'udp'}.get(
                        service.protocol),
                    service=service.name,
                    banner=service.banner,
                    technos=technos,
                    url='<a href="{}" title="{}">{}</a>'.format(
                        service.url, service.url, StringUtils.shorten(service.url, 50)) \
                        if service.url else '',
                    comment=StringUtils.shorten(comment, 40),
                    checks=len(service.results),
                    creds=nb_creds,
                    vulns=nb_vulns)
                
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


    def __generate_table_web(self):
        """
        Generate the table with HTTP services registered in the mission
        """

        req = ServicesRequester(self.sqlsession)
        req.select_mission(self.mission)
        filter_ = Filter(FilterOperator.AND)
        filter_.add_condition(Condition('http', FilterData.SERVICE_EXACT))
        req.add_filter(filter_)
        services = req.get_results()

        if len(services) == 0:
            html = """
            <tr class="notfound">
                <td colspan="5">No record found</td>
            </tr>
            """
        else:
            html = ''

            # Unavailable thumbnail
            with open(REPORT_TPL_DIR + '/../img/unavailable.png', 'rb') as f:
                unavailable_b64 = base64.b64encode(f.read()).decode('ascii')

            for service in services:

                # Results HTML page name
                results = 'results-{ip}-{port}-{service}-{id}.html'.format(
                    ip=str(service.host.ip),
                    port=service.port,
                    service=service.name,
                    id=service.id)

                # Web technos (in a specific order)
                
                # try:
                #     technos = ast.literal_eval(service.web_technos)
                # except Exception as e:
                #     logger.debug('Error when retrieving "web_technos" field ' \
                #         'from db: {exc} for {service}'.format(
                #             exc=e, service=service))
                #     technos = list()

                # tmp = list()
                # for t in technos:
                #     tmp.append('{}{}{}'.format(
                #         t['name'],
                #         ' ' if t['version'] else '',
                #         t['version'] if t['version'] else ''))
                # webtechnos = ' | '.join(tmp)

                webtechnos = ''
                product_types = (
                    'web-server',
                    'web-appserver',
                    'web-cms',
                    'web-language',
                    'web-framework',
                    'web-jslib'
                )
                for t in product_types:
                    product = service.get_product(t)
                    if product:
                        webtechnos += '<span class="badge badge-{type} badge-light">' \
                            '{name}{version}</span>'.format(
                                type=t,
                                name=product.name,
                                version=' '+str(product.version) \
                                    if product.version else '')

                # Screenshot
                img_name = 'scren-{ip}-{port}-{id}'.format(
                        ip=str(service.host.ip),
                        port=service.port,
                        id=service.id)
                path = self.output_path + '/screenshots'

                if service.screenshot is not None \
                        and service.screenshot.status == ScreenStatus.OK \
                        and FileUtils.exists(path + '/' + img_name + '.png') \
                        and FileUtils.exists(path + '/' + img_name + '.thumb.png'):

                    screenshot = """
                    <a href="{screenlarge}" title="{title}" class="image-link">
                        <img src="{screenthumb}" class="border rounded">
                    </a>
                    """.format(
                        screenlarge='screenshots/' + img_name + '.png',
                        title=service.html_title,
                        screenthumb='screenshots/' + img_name + '.thumb.png')

                else:
                    screenshot = """
                    <img src="data:image/png;base64,{unavailable}">
                    """.format(unavailable=unavailable_b64)

                # HTML for table row
                html += """
                <tr{clickable}>
                    <td>{url}</td>
                    <td>{title}</td>
                    <td>{webtechnos}</td>
                    <td>{screenshot}</td>
                    <td>{checks}</td>
                </tr>
                """.format(
                    clickable=' class="clickable-row" data-href="{results}"'.format(
                        results=results) if len(service.results) > 0 else '',
                    url='<a href="{}" title="{}">{}</a>'.format(
                        service.url, service.url, StringUtils.shorten(service.url, 50)) \
                        if service.url else '',
                    title=StringUtils.shorten(service.html_title, 40),
                    webtechnos=webtechnos,
                    screenshot=screenshot,
                    checks=len(service.results))

        return html


    def __generate_table_options(self):
        """
        Generate the table with all context-specific options registered in the mission 
        """
        
        req = OptionsRequester(self.sqlsession)
        req.select_mission(self.mission)
        options = req.get_results()

        if len(options) == 0:
            html = """
            <tr class="notfound">
                <td colspan="7">No record found</td>
            </tr>
            """
        else:
            html = ''
            for option in options:

                html += """
                <tr>
                    <td>{ip}</td>
                    <td>{hostname}</td>
                    <td>{service}</td>
                    <td>{port}</td>
                    <td>{proto}</td>
                    <td class="font-weight-bold">{optionname}</td>
                    <td class="font-weight-bold">{optionvalue}</td>
                </tr>
                """.format(
                    ip=option.service.host.ip,
                    hostname=option.service.host.hostname \
                        if option.service.host.hostname != str(option.service.host.ip) \
                        else '',
                    service=option.service.name,
                    port=option.service.port,
                    proto={Protocol.TCP: 'tcp', Protocol.UDP: 'udp'}.get(
                        option.service.protocol),
                    optionname=option.name,
                    optionvalue=option.value)

        return html


    def __generate_table_products(self):
        """
        Generate the table with all products registered in the mission 
        """
        
        req = ProductsRequester(self.sqlsession)
        req.select_mission(self.mission)
        products = req.get_results()

        if len(products) == 0:
            html = """
            <tr class="notfound">
                <td colspan="8">No record found</td>
            </tr>
            """
        else:
            html = ''
            for product in products:

                html += """
                <tr>
                    <td>{ip}</td>
                    <td>{hostname}</td>
                    <td>{service}</td>
                    <td>{port}</td>
                    <td>{proto}</td>
                    <td class="font-weight-bold">{producttype}</td>
                    <td class="font-weight-bold">{productname}</td>
                    <td class="font-weight-bold">{productversion}</td>
                </tr>
                """.format(
                    ip=product.service.host.ip,
                    hostname=product.service.host.hostname \
                        if product.service.host.hostname != str(product.service.host.ip)\
                        else '',
                    service=product.service.name,
                    port=product.service.port,
                    proto={Protocol.TCP: 'tcp', Protocol.UDP: 'udp'}.get(
                        product.service.protocol),
                    producttype=product.type,
                    productname=product.name,
                    productversion=product.version)

        return html


    def __generate_table_credentials(self):
        """
        Generate the table with all credentials registered in the mission 
        """
        
        req = CredentialsRequester(self.sqlsession)
        req.select_mission(self.mission)
        credentials = req.get_results()

        if len(credentials) == 0:
            html = """
            <tr class="notfound">
                <td colspan="10">No record found</td>
            </tr>
            """
        else:
            html = ''
            for cred in credentials:

                html += """
                <tr>
                    <td>{ip}</td>
                    <td>{hostname}</td>
                    <td>{service}</td>
                    <td>{port}</td>
                    <td>{proto}</td>
                    <td>{type}</td>
                    <td class="font-weight-bold">{username}</td>
                    <td class="font-weight-bold">{password}</td>
                    <td>{url}</td>
                    <td>{comment}</td>
                </tr>
                """.format(
                    ip=cred.service.host.ip,
                    hostname=cred.service.host.hostname \
                        if cred.service.host.hostname != str(cred.service.host.ip)\
                        else '',
                    service=cred.service.name,
                    port=cred.service.port,
                    proto={Protocol.TCP: 'tcp', Protocol.UDP: 'udp'}.get(
                        cred.service.protocol),
                    type=cred.type or '',
                    username='<empty>' if cred.username == '' else cred.username,
                    password={'': '<empty>', None: '<???>'}.get(
                        cred.password, cred.password),
                    url='<a href="{}" title="{}">{}</a>'.format(
                        cred.service.url, cred.service.url, 
                        StringUtils.shorten(cred.service.url, 50)) \
                            if cred.service.url else '',
                    comment=cred.comment)                    

        return html


    def __generate_table_vulns(self):
        """
        Generate the table with all vulnerabilities registered in the mission 
        """
        
        req = VulnsRequester(self.sqlsession)
        req.select_mission(self.mission)
        vulnerabilities = req.get_results()

        if len(vulnerabilities) == 0:
            html = """
            <tr class="notfound">
                <td colspan="5">No record found</td>
            </tr>
            """
        else:
            html = ''
            for vuln in vulnerabilities:

                html += """
                <tr>
                    <td>{ip}</td>
                    <td>{service}</td>
                    <td>{port}</td>
                    <td>{proto}</td>
                    <td>{vulnerability}</td>
                </tr>
                """.format(
                    ip=vuln.service.host.ip,
                    service=vuln.service.name,
                    port=vuln.service.port,
                    proto={Protocol.TCP: 'tcp', Protocol.UDP: 'udp'}.get(
                        vuln.service.protocol),
                    vulnerability=vuln.name)

        return html


    #------------------------------------------------------------------------------------
    # Results-<service>.html files generation

    def __generate_results_page(self, service):
        """
        Generate HTML code that contains command outputs of all the checks that have
        been run for the specified service.

        :param Service service: Service Model
        """
        tpl = FileUtils.read(REPORT_TPL_DIR + '/results.tpl.html')

        # service_string = 'host <span class="font-weight-bold">{ip}</span> | ' \
        #     'port <span class="font-weight-bold">{port}/{proto}</span> | ' \
        #     'service <span class="font-weight-bold">{service}</span>'.format(
        #         ip=str(service.host.ip),
        #         port=service.port,
        #         proto={Protocol.TCP: 'tcp', Protocol.UDP: 'udp'}.get(
        #             service.protocol),
        #         service=service.name) 

        tpl = tpl.replace('{{MISSION_NAME}}', self.mission)
        #tpl = tpl.replace('{{SERVICE}}', service_string)
        tpl = tpl.replace('{{SERVICE_IP}}', str(service.host.ip))
        tpl = tpl.replace('{{SERVICE_PORT}}', str(service.port))
        tpl = tpl.replace('{{SERVICE_PROTO}}', 
            {Protocol.TCP: 'tcp', Protocol.UDP: 'udp'}.get(service.protocol))
        tpl = tpl.replace('{{SERVICE_NAME}}', service.name)
        tpl = tpl.replace('{{SIDEBAR_CHECKS}}', self.__generate_sidebar_checks(service))
        tpl = tpl.replace('{{RESULTS}}', self.__generate_command_outputs(service))

        return tpl


    def __generate_sidebar_checks(self, service):
        """
        Generate the sidebar with the list of checks that have been run for the
        specified service.

        :param Service service: Service Model
        """
        req = ResultsRequester(self.sqlsession)
        req.select_mission(self.mission)

        # Filter on service id
        filter_ = Filter(FilterOperator.AND)
        filter_.add_condition(Condition(service.id, FilterData.SERVICE_ID))
        req.add_filter(filter_)
        results = req.get_results()

        html = ''
        i = 0
        for r in results:
            html += """
            <li{class_}>
                <a href="#{id}">{check}</a>
            </li>  
            """.format(
                class_=' class="active"' if i==0 else '',
                id=r.check,
                check=r.check)    
            i += 1

        return html


    def __generate_command_outputs(self, service):
        """
        Generate HTML code with all command outputs for the specified service.

        :param Service service: Service Model
        """
        req = ResultsRequester(self.sqlsession)
        req.select_mission(self.mission)

        # Filter on service id
        filter_ = Filter(FilterOperator.AND)
        filter_.add_condition(Condition(service.id, FilterData.SERVICE_ID))
        req.add_filter(filter_)
        results = req.get_results()

        html = ''
        i = 0
        for r in results:
            html += """
            <div class="tab-pane{active}" id="{id}">
                <div class="container-fluid">
                    <div class="row">
                        <div class="col-lg-12">
                            <h1 class="title-page">{category} > {check}</h1>
            """.format(
                active=' active' if i==0 else '',
                id=r.check,
                category=r.category,
                check=r.check)

            for o in r.command_outputs:
                # Convert command output (with ANSI codes) to HTML
                conv = ansi2html.Ansi2HTMLConverter(inline=True, scheme='solarized', linkify=True)
                output = conv.convert(o.output)
                # Warning: ansi2html generates HTML document with <html>, <style>...
                # tags. We only keep the content inside <pre> ... </pre>
                m = re.search('<pre class="ansi2html-content">(?P<output>.*)' \
                    '</pre>\n</body>', output, re.DOTALL)
                if m:
                    output = m.group('output')

                    html += """
                    <pre class="cmdline">{cmdline}</pre>
                    <pre>{output}</pre>
                    """.format(cmdline=o.cmdline, output=output)

            html += """
                        </div>
                    </div>
                </div>
            </div>
            """   
            i += 1       

        return html