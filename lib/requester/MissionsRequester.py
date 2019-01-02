#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Requester > Missions
###
from lib.requester.Requester import Requester
from lib.db.Mission import Mission
from lib.utils.StringUtils import StringUtils
from lib.output.Logger import logger
from lib.output.Output import Output


class MissionsRequester(Requester):

    def __init__(self, sqlsession):
        query = sqlsession.query(Mission)
        super().__init__(sqlsession, query)


    #------------------------------------------------------------------------------------

    def get_list_mission_names(self):
        """Get list of missions in the database"""
        results = self.get_results()
        return [ r.name for r in results ]


    #------------------------------------------------------------------------------------

    def show(self, highlight=None):
        """
        Display selected missions.
        :param str highlight: Name of the mission to highlight
        """
        results = self.get_results()
        if not results:
            logger.warning('No matching mission')
        else:
            data = list()
            columns = [
                'Mission',
                'Creation date',
                'Comment',
                '# Hosts',
                '# Services',
            ]
            for mission in results:
                color = 'light_green' if mission.name == highlight else None
                data.append([
                    Output.colored(mission.name, color=color),
                    Output.colored(str(mission.creation_date), color=color),
                    Output.colored(StringUtils.wrap(mission.comment, 50), color=color),
                    Output.colored(len(mission.hosts), color=color),
                    Output.colored(mission.get_nb_services(), color=color),                
                ])
            Output.table(columns, data, hrules=False)


    #------------------------------------------------------------------------------------

    def add(self, name):
        """
        Add new mission.
        :param str name: Name of the mission to add
        """
        mission = self.sqlsess.query(Mission).filter(Mission.name == name).first()
        if mission:
            logger.warning('A mission named "{name}" already exists'.format(
                name=mission.name))
            return False
        else:
            self.sqlsess.add(Mission(name=name))
            self.sqlsess.commit()
            logger.success('Mission "{name}" successfully added'.format(name=name))
            return True


    #------------------------------------------------------------------------------------

    def delete(self):
        """Delete selected missions in database"""
        results = self.get_results()
        if not results:
            logger.error('No mission with this name')
        else:
            for r in results:
                self.sqlsess.delete(r)
            self.sqlsess.commit()
            logger.success('Mission deleted')


    def reset(self):
        """Delete all missions in database (re-create a fresh "default" mission)"""
        self.sqlsess.query(Mission).delete()
        self.sqlsess.commit()
        self.sqlsess.add(Mission(name='default', comment='Default scope'))
        self.sqlsess.commit()
        logger.success('All missions deleted & fresh "default" mission created')


    def rename(self, old, new):
        """
        Rename selected missions.
        :param str old: Name of the mission to rename
        :param str new: New mission name
        """
        if old == 'default':
            logger.warning('Default mission cannot be renamed')
        else:
            mission = self.sqlsess.query(Mission).filter(Mission.name == old).first()
            mission.name = new
            self.sqlsess.commit()
            logger.success('Mission renamed: {old} -> {new}'.format())


    def edit_comment(self, comment):
        """
        Edit comment of selected missions.
        :param str comment: New comment
        """
        results = self.get_results()
        if not results:
            logger.error('No mission with this name')
        else:
            for r in results:
                r.comment = comment
            self.sqlsess.commit()
            logger.success('Comment edited')