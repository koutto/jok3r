# -*- coding: utf-8 -*-
###
### Core > Constants
###
from enum import Enum 

CMD_RUN, CMD_INSTALL, CMD_UPDATE, CMD_CHECK = range(4) # Command types
MANDATORY, OPTIONAL = range(2)
NO_AUTH, USER_ONLY, POST_AUTH = range(3) # Authentication status for Context

class Mode(Enum):
    TOOLBOX = 1
    INFO = 2
    DB = 3
    ATTACK = 4

class TargetMode(Enum):
    URL = 1
    IP = 2

class OptionType(Enum):
    BOOLEAN = 1
    LIST = 2
    VAR = 3

class FilterData(Enum):
    IP = 1
    HOST = 2
    PORT = 3
    PROTOCOL = 4
    UP = 5
    SERVICE = 6
    SERVICE_EXACT = 7
    OS = 8
    BANNER = 9
    URL = 10
    URL_EXACT = 11
    HTTP_HEADERS = 12
    USERNAME = 13
    PASSWORD = 14
    AUTH_TYPE= 15
    USER_AND_PASS = 16
    ONLY_USER = 17
    COMMENT_SERVICE = 18
    COMMENT_HOST = 19
    COMMENT_CRED = 20
    COMMENT_MISSION = 21
    MISSION_EXACT = 22
    MISSION = 23

class FilterOperator(Enum):
    AND = 1
    OR = 2
