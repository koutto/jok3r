#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Web-UI > API > App main
###
import os
import uuid
import json
from flask import Flask, Blueprint
from flask_socketio import SocketIO, emit
from flask_cors import CORS

from lib.db.Session import Session
from lib.core.Exceptions import ApiException, ApiNoResultFound
from lib.webui.api.Api import api
from lib.webui.api.Config import *
from lib.webui.api.endpoints.HostsApi import ns as hosts_namespace
from lib.webui.api.endpoints.MissionsApi import ns as missions_namespace
from lib.webui.api.endpoints.ServicesApi import ns as services_namespace
from lib.webui.api.endpoints.VulnsApi import ns as vulns_namespace


app = Flask(__name__, static_url_path="")
app.url_map.strict_slashes = False
socketio = SocketIO(app, cors_allowed_origins='*')
CORS(app)

#----------------------------------------------------------------------------------------
# Exceptions handlers

@app.errorhandler(Exception)
def default_error_handler(error):
    """Default error handler"""
    return {'message': str(error)}, getattr(error, 'code', 500)

@app.errorhandler(ApiException)
def handle_api_exception(error):
    return {'message': str(error)}, 400

@app.errorhandler(ApiNoResultFound)
def handle_no_result_exception(error):
    return {'message': 'No result found in database' }, 404


#----------------------------------------------------------------------------------------

def configure_app(flask_app):
    flask_app.config['SERVER_NAME'] = FLASK_SERVER_NAME


def initialize_app(flask_app):
    configure_app(flask_app)

    blueprint = Blueprint('api', __name__, url_prefix='/api')
    api.init_app(blueprint)
    api.add_namespace(missions_namespace)
    api.add_namespace(hosts_namespace)
    api.add_namespace(services_namespace)
    api.add_namespace(vulns_namespace)
    flask_app.register_blueprint(blueprint)


def run_server():
    initialize_app(app)
    app.run(debug=FLASK_DEBUG)


@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, HEAD, DELETE')
    response.headers.add('Access-Control-Allow-Headers', 'content-type, x-requested-with')
    return response

@app.teardown_request
def remove_session(ex=None):
    Session.remove()





@socketio.on('connected')
def connected():
    print("%s connected" % (request.sid))


@socketio.on('disconnect')
def disconnect():
    print("%s disconnected" % (request.sid))



@socketio.on('start-transfer')
def start_transfer(filename, size):
    """Process an upload request from the client."""
    print(filename)
    _, ext = os.path.splitext(filename)
    print(filename)
    if ext not in ['.xml']:
        return False  # reject the upload
    id = uuid.uuid4().hex  # server-side filename
    with open('/tmp/' + id + '.json', 'wt') as f:
        json.dump({'filename': filename, 'size': size}, f)
    with open('/tmp/' + id + ext, 'wb') as f:
        pass
    print(id + ext)
    emit('log', {'message': 'Server receiving file {} ...'.format(filename)})
    return id + ext  # allow the upload


@socketio.on('write-chunk')
def write_chunk(filename, offset, data):
    """Write a chunk of data sent by the client."""
    if not os.path.exists('/tmp/' + filename):
        return False
    try:
        with open('/tmp/' + filename, 'r+b') as f:
            f.seek(offset)
            f.write(data)
            print(data)
            emit('log', {'message': 'File received by server'})
    except IOError:
        return False
    return True