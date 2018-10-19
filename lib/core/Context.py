# -*- coding: utf-8 -*-
###
### Core > Context
###
from lib.core.Config import *


class Context:
    """
    Each Command object has a Context object. It defines the required conditions
    to run the command. Those conditions can be on particular values of target's specific options
    and/or a particular authentication status.

    - Available specific options depends on the service, and are defined in settings.
    - Authentication status can be:
        - NO_AUTH   : No credentials are known
        - USER_ONLY : At least one username is known
        - POST_AUTH : Valid credentials (username+password) are known
        - None      : Any status

    Context object can be accessed/edited like a dictionnary. It contains the following keys:
    - auth_status : Authentication status
    - auth_type   : For HTTP service only, defines for which kind of authentication, the auth_status
                    value should be taken into account.
    - <options>   : All of the specific options that apply for the service.
    """
    def __init__(self, context_dict):
        """        
        :param context_dict: Dictionary of required conditions to run a command, 
        as defined in settings (specific options+auth status)
        """
        self.context  = context_dict if isinstance(context_dict, dict) else dict()


    def __getitem__(self, key):
        return self.context[key] if key in self.context else None

    def __setitem__(self, key, value):
        self.context[key] = value

    def __delitem__(self, key):
        del self.context[key]

    def __contains__(self, key):
        return key in self.context

    def __len__(self):
        return len(self.context)

    def __repr__(self):
        return repr(self.context)

    def keys(self):
        return self.context.keys()

    def values(self):
        return self.context.values()

    def __repr__(self):
        tmp = self.context
        if 'auth_status' in self.context:
            tmp['auth_status'] = {0: 'NO_AUTH', 1: 'USER_ONLY', 2: 'POST_AUTH'}.get(tmp['auth_status'])
        return str(tmp)
