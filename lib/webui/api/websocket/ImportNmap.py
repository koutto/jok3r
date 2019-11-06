#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Web-UI > WebSocket > Import Nmap Results
###
import os
import uuid
import json
from flask_socketio import SocketIO, emit
from lib.webui.api.App import socketio
from lib.webui.api.Api import settings

from lib.db.Session import Session
from lib.core.Constants import FilterData
from lib.importer.NmapResultsParser import NmapResultsParser
from lib.requester.Condition import Condition
from lib.requester.Filter import Filter
from lib.requester.MissionsRequester import MissionsRequester
from lib.requester.HostsRequester import HostsRequester




@socketio.on('start-transfer')
def start_transfer(filename, size, type_transfert):
    """Process an upload request from the client."""
    #print(filename)
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
    #print(id + ext)
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
                    nb_imported_services = 0
                    for host in results:
                        req.add_or_merge_host(host)
                        for service in host.services:
                            nb_imported_services += 1

                    emit('log-import-nmap', {
                        'type': 'success',
                        'message': '[{filename}] Nmap results imported with success ' \
                                   'into current mission.'.format(filename=orig_filename)
                    })
                    emit('import-nmap-finished', {
                        'file': orig_filename,
                        'success': True, 
                        'nbServices': nb_imported_services
                    })
                return True
            else:
                emit('log-import-nmap', {
                    'type': 'error',
                    'message': '[{filename}] Unable to parse file. Probably not a ' \
                               'valid Nmap XML file.'.format(filename=orig_filename)
                })
                emit('import-nmap-finished', {
                    'file': orig_filename,
                    'success': False, 
                    'nbServices': 0
                })
                return False

        except Exception as e:
            emit('log-import-nmap', {
                'type': 'error',
                'message': '[{filename}] Nmap import stopped due to unexpected ' \
                'error: {exception} '.format(
                    filename=orig_filename,
                    exception=e)
            })
            emit('import-nmap-finished', {
                'file': orig_filename,
                'success': False, 
                'nbServices': 0
            })
            return False

