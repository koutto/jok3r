#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Core > Constants
###
from enum import Enum, auto

MANDATORY, OPTIONAL = range(2)
NO_AUTH, USER_ONLY, POST_AUTH = range(3) # Authentication status for ContextRequirements

class CmdType(Enum):
    RUN     = auto()
    INSTALL = auto()
    UPDATE  = auto()
    CHECK   = auto()

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

class FilterData(Enum):
    IP              = auto()
    HOST            = auto()
    PORT            = auto()
    PROTOCOL        = auto()
    UP              = auto()
    SERVICE         = auto()
    SERVICE_EXACT   = auto()
    SERVICE_ID      = auto()
    OS              = auto()
    OS_FAMILY       = auto()
    BANNER          = auto()
    URL             = auto()
    URL_EXACT       = auto()
    HTML_TITLE      = auto()
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
    CHECK_ID        = auto()
    CHECK_NAME      = auto()
    COMMAND_OUTPUT  = auto()
    VULN            = auto()
    OPTION_NAME     = auto()
    OPTION_VALUE    = auto()
    PRODUCT_TYPE    = auto()
    PRODUCT_NAME    = auto()
    PRODUCT_VERSION = auto()
    UNSCANNED       = auto()

class FilterOperator(Enum):
    AND = auto()
    OR  = auto()
