#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Web-UI > WebSocketCallable (interface)
###
from flask_socketio import SocketIO, emit
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
        self.socketio = SocketIO(message_queue='redis://')

    def log(self, type, message):
        """
        Log both in stdout and via websocket emit
        """
        self.logweb(type, message)

        if   type == 'info':    logger.info(message)
        elif type == 'error':   logger.error(message)
        elif type == 'success': logger.success(message)  
        elif type == 'warning': logger.warning(message)
        return 


    def logweb(self, type, message):
        """
        Log only via websocket emit
        """
        if self.called_from_websocket:
            self.socketio.emit(self.log_label, {
                'type': type,
                'message': message
            })
        return 