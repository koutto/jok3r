#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Web-UI > WebSocketCallable (interface)
###
from flask_socketio import emit
from lib.output.Logger import logger


class WebsocketCallable:

    def __init__(self, 
                 called_from_websocket,
                 log_label):
        """
        WebSocketCallable Interface.
        Classes that define methods that are called from SocketIO routines should
        inherit this class.

        :param bool called_from_websocket:
        """
        self.called_from_websocket = called_from_websocket
        self.log_label = log_label


    def log(self, type, message):
        if self.called_from_websocket:
            emit(self.log_label, {
                'type': type,
                'message': message
            })

        if   type == 'info':    logger.info(message)
        elif type == 'error':   logger.error(message)
        elif type == 'success': logger.success(message)  
        elif type == 'warning': logger.warning(message)
        return 

