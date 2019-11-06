#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Web-UI > WebSocket > Import List of Targets
###
from flask_socketio import SocketIO, emit
from lib.webui.api.App import socketio
from lib.webui.api.Api import settings

from lib.db.Session import Session
from lib.core.Constants import FilterData
from lib.importer.ListImporter import ListImporter
from lib.requester.Condition import Condition
from lib.requester.Filter import Filter
from lib.requester.MissionsRequester import MissionsRequester


@socketio.on('import-list')
def import_list(mission_id, list_targets, options):
    """
    :param int mission_id: Mission id in which the import must occur
    :param str list_targets: List of targets, one per line with syntax defined in
        ListImporter
    :param dict options: Additional import options
        Default:
        {
            'reverseDnsLookup': True, 
            'nmapBannerGrabbing': True, 
            'webTechnoDetection': True
        }
    """
    nb_new_services = 0
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

        if 'reverseDnsLookup' not in options:
            options['reverseDnsLookup'] = True
        if 'nmapBannerGrabbing' not in options:
            options['nmapBannerGrabbing'] = True
        if 'webTechnoDetection' not in options:
            options['webTechnoDetection'] = True

        # Parse list of target services
        importer = ListImporter(
            list_targets,
            settings.services,
            Session,
            mission.name,
            called_from_websocket=True
        )
        nb_new_services = importer.run(
            reverse_dns_lookup=options['reverseDnsLookup'],
            html_title_grabbing=True,
            nmap_banner_grabbing=options['nmapBannerGrabbing'],
            web_technos_detection=options['webTechnoDetection']            
        )
        emit('import-list-finished', {
            'success': True, 
            'nbServices': nb_new_services
        })

    except Exception as e:
        emit('log-import-list', {
            'type': 'error',
            'message': 'List import stopped due to unexpected error: {exception} '.format(
                exception=e)
        })
        emit('import-list-finished', {
            'success': False, 
            'nbServices': nb_new_services
        })
        return False
