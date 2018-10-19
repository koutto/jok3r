# -*- coding: utf-8 -*-
###
### Output > Logger
###
import logging
import colorlog

DEBUG   = '[.]'
INFO    = '[*]'
SUCCESS = '[+]'
PROMPT  = '[?]'
WARNING = '[X]'
ERROR   = '[!]'
SMARTINFO    = '[*] [SMART]'
SMARTSUCCESS = '[+] [SMART]'

# https://github.com/borntyping/python-colorlog
#LOG_FORMAT   = '[%(asctime)s] %(levelname)s %(message)s'
LOG_FORMAT   = '%(log_color)s%(levelname)s%(reset)s %(message_log_color)s%(message)s'
DATE_FORMAT  = '%H:%M:%S'

LOG_COLORS = {
    DEBUG    : 'cyan',
    INFO     : 'bold,blue',
    SUCCESS  : 'bold,green',
    PROMPT   : 'bold,cyan',
    WARNING  : 'bold,yellow',
    ERROR    : 'bold,red',
    SMARTINFO    : 'bold,blue', 
    SMARTSUCCESS : 'bold,green',
    #CRITICAL : 'bold,red',
}

SECONDARY_LOG_COLORS = {
        'message': {
            SUCCESS  : 'green',
            WARNING  : 'yellow',
            ERROR    : 'red',
            SMARTSUCCESS : 'green'
            #CRITICAL : 'bold,red',
        }
}

#logging.addLevelName(logging.CRITICAL, '[-]')

handler   = colorlog.StreamHandler()

formatter = colorlog.ColoredFormatter(LOG_FORMAT,
                                      datefmt=DATE_FORMAT,
                                      reset=True,
                                      log_colors=LOG_COLORS,
                                      secondary_log_colors=SECONDARY_LOG_COLORS,
                                      style='%')
handler.setFormatter(formatter)
logger = colorlog.getLogger()

# Add custom levels (not supported by default by logging)
# https://gist.github.com/hit9/5635505
logging.SUCCESS = 35
logging.PROMPT = 36
logging.SMARTINFO = 37
logging.SMARTSUCCESS = 38
logging.addLevelName(logging.DEBUG, DEBUG)
logging.addLevelName(logging.INFO, INFO)
logging.addLevelName(logging.SUCCESS, SUCCESS)
logging.addLevelName(logging.PROMPT, PROMPT)
logging.addLevelName(logging.WARNING, WARNING)
logging.addLevelName(logging.ERROR, ERROR)
logging.addLevelName(logging.SMARTINFO, SMARTINFO)
logging.addLevelName(logging.SMARTSUCCESS, SMARTSUCCESS)
setattr(logger, 'success', lambda message, *args: logger._log(logging.SUCCESS, message, args))
setattr(logger, 'prompt', lambda message, *args: logger._log(logging.PROMPT, message, args))
setattr(logger, 'smartinfo', lambda message, *args: logger._log(logging.SMARTINFO, message, args))
setattr(logger, 'smartsuccess', lambda message, *args: logger._log(logging.SMARTSUCCESS, message, args))

logger.setLevel('INFO')
logger.addHandler(handler)

logging.getLogger('urllib3').setLevel(logging.CRITICAL)
