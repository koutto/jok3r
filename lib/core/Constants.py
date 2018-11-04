# -*- coding: utf-8 -*-
###
### Core > Constants
###
from enum import Enum, auto

CMD_RUN, CMD_INSTALL, CMD_UPDATE, CMD_CHECK = range(4) # Command types
MANDATORY, OPTIONAL = range(2)
NO_AUTH, USER_ONLY, POST_AUTH = range(3) # Authentication status for Context

class Mode(Enum):
    TOOLBOX = auto()
    INFO    = auto()
    DB      = auto()
    ATTACK  = auto()

class TargetMode(Enum):
    URL = auto()
    IP  = auto()

class OptionType(Enum):
    BOOLEAN = auto()
    LIST    = auto()
    VAR     = auto()
    PRODUCT = auto()

class FilterData(Enum):
    IP              = auto()
    HOST            = auto()
    PORT            = auto()
    PROTOCOL        = auto()
    UP              = auto()
    SERVICE         = auto()
    SERVICE_EXACT   = auto()
    OS              = auto()
    BANNER          = auto()
    URL             = auto()
    URL_EXACT       = auto()
    HTTP_HEADERS    = auto()
    USERNAME        = auto()
    PASSWORD        = auto()
    AUTH_TYPE       = auto()
    USER_AND_PASS   = auto()
    ONLY_USER       = auto()
    COMMENT_SERVICE = auto()
    COMMENT_HOST    = auto()
    COMMENT_CRED    = auto()
    COMMENT_MISSION = auto()
    MISSION_EXACT   = auto()
    MISSION         = auto()

class FilterOperator(Enum):
    AND = auto()
    OR  = auto()
