#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Core > Exceptions
###

class SettingsException(Exception):
    pass

class TargetException(Exception):
    pass

class ArgumentsException(Exception):
    pass

class AttackException(Exception):
    pass

class FilterException(Exception):
    pass


#----------------------------------------------------------------------------------------
# REST API Exceptions

class ApiException(Exception):
    pass

class ApiNoResultFound(Exception):
    pass
