# -*- coding: utf-8 -*-
###
### Requester > Condition
###
import ipaddress

from lib.core.Constants import *
from lib.core.Exceptions import FilterException
from lib.db.CommandOutput import CommandOutput
from lib.db.Credential import Credential
from lib.db.Host import Host
from lib.db.Mission import Mission
from lib.db.Result import Result
from lib.db.Service import Service, Protocol
from lib.db.Vuln import Vuln
from lib.utils.NetUtils import NetUtils



class Condition:

    def __init__(self, value, filtertype):
        """
        :param value: Condition value, either list or single element
        :param filtertype: Type of data to filter on (from enum FilterData)
        :raise FilterException:

        Example of values:
        Types   Values
        IP      [1.1.1.1,2.2.2.2]     -> means ip = 1.1.1.1 or 2.2.2.2
        Port    [8000-8100,9443]      -> means port = in [8000-8100] or 9443
        """
        self.value = value if type(value) == list else [value]
        #print(self.value)
        self.filtertype = filtertype
        self.mapping = {
            FilterData.IP              : self.__translate_ip,
            FilterData.HOST            : self.__translate_host,
            FilterData.PORT            : self.__translate_port,
            FilterData.PROTOCOL        : self.__translate_protocol,
            FilterData.UP              : self.__translate_up,
            FilterData.SERVICE         : self.__translate_service,
            FilterData.SERVICE_EXACT   : self.__translate_service_exact,
            FilterData.SERVICE_ID      : self.__translate_service_id,
            FilterData.OS              : self.__translate_os,
            FilterData.BANNER          : self.__translate_banner,
            FilterData.URL             : self.__translate_url,
            FilterData.URL_EXACT       : self.__translate_url_exact,
            FilterData.HTTP_HEADERS    : self.__translate_http_headers,
            FilterData.USERNAME        : self.__translate_username,
            FilterData.PASSWORD        : self.__translate_password,
            FilterData.AUTH_TYPE       : self.__translate_auth_type,
            FilterData.USER_AND_PASS   : self.__translate_user_and_pass,
            FilterData.ONLY_USER       : self.__translate_only_user,
            FilterData.COMMENT_SERVICE : self.__translate_comment_service,
            FilterData.COMMENT_HOST    : self.__translate_comment_host,
            FilterData.COMMENT_CRED    : self.__translate_comment_cred,
            FilterData.COMMENT_MISSION : self.__translate_comment_mission,
            FilterData.MISSION_EXACT   : self.__translate_mission_exact,
            FilterData.MISSION         : self.__translate_mission,
            FilterData.CHECK_ID        : self.__translate_check_id,
            FilterData.CHECK_NAME      : self.__translate_check_name,
            FilterData.COMMAND_OUTPUT  : self.__translate_command_output,
            FilterData.VULN            : self.__translate_vuln,
            FilterData.OPTION_NAME     : self.__translate_option_name,
            FilterData.OPTION_VALUE    : self.__translate_option_value,
            FilterData.PRODUCT_TYPE    : self.__translate_product_type,
            FilterData.PRODUCT_NAME    : self.__translate_product_name,
            FilterData.PRODUCT_VERSION : self.__translate_product_version,
        }

    def translate(self):
        """
        Translate the condition into sqlalchemy filter
        """
        method_translate = self.mapping.get(self.filtertype)
        if not method_translate:
            return None

        result = None
        for v in self.value:
            translated = method_translate(v)
            if translated is not None:
                if result is None:
                    result = (translated)
                else:
                    result = result | (translated)
        print(result)
        return result


    def __translate_ip(self, value):
        """
        value can be:
            - Single IP
            - IP range - format: 1.1.1.1/24
        """
        if NetUtils.is_valid_ip(value):
            return (Host.ip == value)
        elif NetUtils.is_valid_ip_range(value):
            return (Host.is_in_ip_range(value))
        else:
            raise FilterException('{value} invalid IP/range'.format(value=value))


    def __translate_host(self, value):
        """
        LIKE %value%
        """
        return (Host.hostname.ilike('%'+str(value)+'%'))


    def __translate_port(self, value):
        """
        value can be:
            - Single port number
            - Port range - format 8000-8100
        """
        if NetUtils.is_valid_port(value):
            return (Service.port == int(value))
        elif NetUtils.is_valid_port_range(value):
            minport, maxport = value.split('-')
            return (Service.port.between(int(minport), int(maxport)))
        else:
            raise FilterException('{value} invalid port/range'.format(value=value))


    def __translate_protocol(self, value):
        if value.lower() == 'tcp':
            return (Service.protocol == Protocol.TCP)
        elif value.lower() == 'udp':
            return (Service.protocol == Protocol.UDP)
        else:
            raise FilterException('{value} invalid protocol'.format(value=value))


    def __translate_up(self, value):
        val = (value.lower() == 'true')
        return (Service.up == val)

    def __translate_service(self, value):
        return (Service.name.ilike('%'+str(value)+'%'))

    def __translate_service_exact(self, value):
        return (Service.name == value)

    def __translate_service_id(self, value):
        return (Service.id == int(value))

    def __translate_os(self, value):
        return (Host.os.ilike('%'+str(value)+'%'))

    def __translate_banner(self, value):
        return (Service.banner.ilike('%'+str(value)+'%'))

    def __translate_url(self, value):
        return (Service.url.ilike('%'+str(value)+'%'))

    def __translate_url_exact(self, value):
        return (Service.url == str(value))

    def __translate_http_headers(self, value):
        return (Service.http_headers.ilike('%'+str(value)+'%'))

    def __translate_username(self, value):
        return (Credential.username.ilike('%'+str(value)+'%'))

    def __translate_password(self, value):
        return (Credential.password.ilike('%'+str(value)+'%'))

    def __translate_auth_type(self, value):
        return (Credential.type.ilike('%'+str(value)+'%'))

    def __translate_user_and_pass(self, boolean):
        if boolean:
            return (Credential.username.isnot(None) & Credential.password.isnot(None))
        else:
            return None

    def __translate_only_user(self, boolean):
        if boolean:
            return (Credential.username.isnot(None) & Credential.password.is_(None))
        else:
            return None

    def __translate_comment_service(self, value):
        return (Service.comment.ilike('%'+str(value)+'%'))

    def __translate_comment_host(self, value):
        return (Host.comment.ilike('%'+str(value)+'%'))

    def __translate_comment_cred(self, value):
        return (Credential.comment.ilike('%'+str(value)+'%'))

    def __translate_comment_mission(self, value):
        return (Mission.comment.ilike('%'+str(value)+'%'))

    def __translate_mission_exact(self, value):
        return (Mission.name == value)

    def __translate_mission(self, value):
        return (Mission.name.ilike('%'+str(value)+'%'))

    def __translate_check_id(self, value):
        return (Result.id == int(value))

    def __translate_check_name(self, value):
        return (Result.check.ilike('%'+str(value)+'%'))

    def __translate_command_output(self, value):
        return (CommandOutput.output.ilike('%'+str(value)+'%'))

    def __translate_vuln(self, value):
        return (Vuln.name.ilike('%'+str(value)+'%'))

    def __translate_option_name(self, value):
        return (Option.name.ilike('%'+str(value)+'%'))

    def __translate_option_value(self, value):
        return (Option.value.ilike('%'+str(value)+'%'))

    def __translate_product_type(self, value):
        return (Product.type.ilike('%'+str(value)+'%'))

    def __translate_product_name(self, value):
        return (Product.name.ilike('%'+str(value)+'%'))

    def __translate_product_version(self, value):
        return (Product.version.ilike('%'+str(value)+'%'))
