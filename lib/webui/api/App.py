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
from lib.webui.api.Api import api, settings
from lib.webui.api.Config import *
from lib.webui.api.endpoints.HostsApi import ns as hosts_namespace
from lib.webui.api.endpoints.MissionsApi import ns as missions_namespace
from lib.webui.api.endpoints.ServicesApi import ns as services_namespace
from lib.webui.api.endpoints.VulnsApi import ns as vulns_namespace

from lib.core.Constants import FilterData
from lib.importer.ListImporter import ListImporter
from lib.importer.NmapResultsParser import NmapResultsParser
from lib.requester.Condition import Condition
from lib.requester.Filter import Filter
from lib.requester.MissionsRequester import MissionsRequester
from lib.requester.HostsRequester import HostsRequester


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
    response.headers.add(
        'Access-Control-Allow-Origin', '*')
    response.headers.add(
        'Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, HEAD, DELETE')
    response.headers.add(
        'Access-Control-Allow-Headers', 'content-type, x-requested-with')
    return response

@app.teardown_request
def remove_session(ex=None):
    Session.remove()

#----------------------------------------------------------------------------------------




@socketio.on('start-transfer')
def start_transfer(filename, size, type_transfert):
    """Process an upload request from the client."""
    print(filename)
    _, ext = os.path.splitext(filename)

    # Check type of transfert and extension, reject upload if not valid
    if type_transfert == 'nmap':
        if ext not in ['.xml']:
            # emit('log-import-nmap', {
            #     'type': 'error',
            #     'message': 'Invalid file extension, only Nmap XML results ' \
            #                'are authorized. Reject upload.'
            # })
            return False
    else:
        return False

    # Temporary server-side filename
    id = uuid.uuid4().hex
    with open('/tmp/' + id + '.json', 'wt') as f:
        json.dump({'filename': filename, 'size': size}, f)
    with open('/tmp/' + id + ext, 'wb') as f:
        pass
    print(id + ext)
    return id + ext  # allow the upload


@socketio.on('write-chunk')
def write_chunk(filename, offset, data):
    """Write a chunk of data sent by the client."""
    filepath = '/tmp/' + filename
    if not os.path.exists(filepath):
        return False

    try:
        with open(filepath, 'r+b') as f:
            f.seek(offset)
            f.write(data)
            print(data)
    except IOError:
        return False

    return True


@socketio.on('process-file')
def process_file(type_transfert, mission_id, filename, orig_filename):
    filepath = '/tmp/' + filename
    if not os.path.exists(filepath):
        return False

    if type_transfert == 'nmap':
        emit('log-import-nmap', {
            'type': 'success',
            'message': 'Server received file {}. ' \
                       'Start processing ...'.format(orig_filename)
        })

        try: 
            # Check mission is valid
            missions_req = MissionsRequester(Session)
            filter_ = Filter()
            filter_.add_condition(Condition(mission_id, FilterData.MISSION_ID))
            missions_req.add_filter(filter_)
            mission = missions_req.get_first_result()

            if not mission:
                emit('log-import-nmap', {
                    'type': 'error',
                    'message': '[{filename}] Invalid mission id selected, ' \
                               'cannot proceed !'.format(filename=orig_filename)
                })   
                return False

            # Parse Nmap file
            parser = NmapResultsParser(
                filepath, 
                settings.services,
                called_from_websocket=True,
                alt_filename=orig_filename)
            if not parser:
                emit('log-import-nmap', {
                    'type': 'error',
                    'message': '[{filename}] Unexpected error occured. '.format(
                        filename=orig_filename)
                })
                return False
          
            results = parser.parse(
                http_recheck=False,
                html_title_grabbing=True,
                nmap_banner_grabbing=False,
                web_technos_detection=True
            )
            os.remove(filepath)

            if results is not None:
                if len(results) == 0:
                    emit('log-import-nmap', {
                        'type': 'warning',
                        'message': '[{filename}] No new service has been added into ' \
                                   'current mission.'.format(filename=orig_filename)
                    })
                else:
                    emit('log-import-nmap', {
                        'type': 'info',
                        'message': '[{filename}] Update the database... ' .format(
                            filename=orig_filename)
                    })

                    req = HostsRequester(Session)
                    req.select_mission(mission.name)
                    for host in results:
                        req.add_or_merge_host(host)
                    emit('log-import-nmap', {
                        'type': 'success',
                        'message': '[{filename}] Nmap results imported with success ' \
                                   'into current mission.'.format(filename=orig_filename)
                    })
                return True
            else:
                emit('log-import-nmap', {
                    'type': 'error',
                    'message': '[{filename}] Unable to parse file. Probably not a ' \
                               'valid Nmap XML file.'.format(filename=orig_filename)
                })
                return False

        except Exception as e:
            emit('log-import-nmap', {
                'type': 'error',
                'message': '[{filename}] Error occured: {exception} '.format(
                    filename=orig_filename,
                    exception=e)
            })
            return False


@socketio.on('import-list')
def import_list(mission_id, list_targets):
    try: 
        # Check mission is valid
        missions_req = MissionsRequester(Session)
        filter_ = Filter()
        filter_.add_condition(Condition(mission_id, FilterData.MISSION_ID))
        missions_req.add_filter(filter_)
        mission = missions_req.get_first_result()

        if not mission:
            emit('log-import-list', {
                'type': 'error',
                'message': 'Invalid mission id selected, cannot proceed !'
            })   
            return False

        # Parse list of target services
        importer = ListImporter(
            list_targets,
            settings.services,
            Session,
            mission.name,
            called_from_websocket=True
        )
        importer.run(
            reverse_dns_lookup=True,
            html_title_grabbing=True,
            nmap_banner_grabbing=True,
            web_technos_detection=True            
        )
        emit('import-list-finished')

    except Exception as e:
        emit('log-import-list', {
            'type': 'error',
            'message': 'Error occured: {exception} '.format(exception=e)
        })
        emit('import-list-finished')
        return False
