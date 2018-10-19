# -*- coding: utf-8 -*-
###
### SmartModules > SmartModule Result
###
from lib.db.Credential import Credential
from lib.db.Option import Option
from lib.core.Config import *
from lib.output.Logger import logger


class SmartModuleResult:

    def __init__(self):
        self.specific_options = list()
        self.usernames = list()
        self.credentials = list()


    def add_option(self, name, value):
        self.specific_options.append(Option(name=name, value=value))


    def add_username(self, username, auth_type=None):
        self.usernames.append(Credential(type=auth_type, username=username, password=None))


    def add_credentials(self, username, password, auth_type=None):
        self.credentials.append(Credential(type=auth_type, username=username, password=password))


    def update_service(self, service):
        self.__update_specific_options(service)
        self.__update_usernames(service)
        self.__update_credentials(service)


    def __update_specific_options(self, service):
        for option in self.specific_options:
            match_option = service.get_option(option.name)
            if match_option:
                if match_option.value == option.value:
                    logger.smartinfo('Detected option (no update): {name} = {old}'.format(
                        name=option.name, old=match_option.value))
                else:
                    logger.smartsuccess('Change option: {name} = {old} -> {new}'.format(
                        name=option.name, old=match_option.value, new=option.value))
                    match_option.value = option.value
            else:
                logger.smartsuccess('New detected option: {name} = {new}'.format(
                    name=option.name, new=option.value))
                service.options.append(option)


    def __update_usernames(self, service):
        for username in self.usernames:
            username_str = '{username} {auth_type}'.format(
                username=username.username or '<empty>',
                auth_type='('+username.type+')' if username.type else '')

            match_cred = service.get_credential(username.username, username.type)
            if match_cred:
                if match_cred.password is None:
                    logger.smartinfo('Detected username (already knwon): ' + username_str)
                else:
                    logger.smartinfo('Detected username (password already known): ' + username_str)
            else:
                logger.smartsuccess('New detected username: ' + username_str)
                service.credentials.append(username)


    def __update_credentials(self, service):
        for credential in self.credentials:
            credential_str = '{username}/{password} {auth_type}'.format(
                username=credential.username or '<empty>',
                password=credential.password or '<empty>',
                auth_type='('+credential.type+')' if credential.type else '')

            match_cred = service.get_credential(credential.username, credential.type)
            if match_cred:
                if match_cred.password is None:
                    logger.smartsuccess('Credentials found (username already known): ' + credential_str)
                    match_cred.password = credential.password
                elif match_cred.password != credential.password:
                    logger.smartsuccess('Credentials found (new password)' + credential_str)
                    match_cred.password = credential.password
                else:
                    logger.smartinfo('Credentials detected (no update): ' + credential_str)
            else:
                logger.smartsuccess('New Credentials found: ' + credential_str)
                service.credentials.append(credential)
                
