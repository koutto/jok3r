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


    def get_list_mission_names(self):
        results = self.get_results()
        return [ r.name for r in results ]


    def show(self, highlight=None):
        results = self.get_results()
        if not results:
            logger.warning('No matching mission')
        else:
            data = list()
            columns = [
                'Mission',
                'Creation date',
                'Comment',
                '# hosts',
                '# services',
            ]
            for r in results:
                color = 'light_green' if r.name == highlight else None
                data.append([
                    Output.colored(r.name, color=color),
                    Output.colored(str(r.creation_date), color=color),
                    Output.colored(StringUtils.wrap(r.comment, 50), color=color),
                    Output.colored('TODO', color=color),
                    Output.colored('TODO', color=color),                
                ])
            Output.table(columns, data, hrules=False)


    def add(self, name):
        mission = self.sqlsess.query(Mission).filter(Mission.name == name).first()
        if mission:
            logger.warning('A mission named "{name}" already exists'.format(name=mission.name))
            return False
        else:
            self.sqlsess.add(Mission(name=name))
            self.sqlsess.commit()
            logger.success('Mission "{name}" successfully added'.format(name=name))
            return True


    def delete(self):
        results = self.get_results()
        if not results:
            logger.error('No mission with this name')
        else:
            for r in results:
                self.sqlsess.delete(r)
            self.sqlsess.commit()
            logger.success('Mission deleted')


    def reset(self):
        self.sqlsess.query(Mission).delete()
        self.sqlsess.commit()
        self.sqlsess.add(Mission(name='default', comment='Default scope'))
        self.sqlsess.commit()
        logger.success('All missions deleted & fresh "default" mission created')


    def rename(self, old, new):
        if old == 'default':
            logger.warning('Default mission cannot be renamed')
        else:
            mission = self.sqlsess.query(Mission).filter(Mission.name == old).first()
            mission.name = new
            self.sqlsess.commit()
            logger.success('Mission renamed: {old} -> {new}'.format())


    def edit_comment(self, comment):
        results = self.get_results()
        if not results:
            logger.error('No mission with this name')
        else:
            for r in results:
                r.comment = comment
            self.sqlsess.commit()
            logger.success('Comment edited')