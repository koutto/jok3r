# -*- coding: utf-8 -*-
###
### Requester > Requester
###
from lib.db.Mission import Mission

class Requester:

    def __init__(self, sqlsession, query):
        """
        :param sqlsession: Sqlalchemy session
        :param query: Base query used to access all data (no filter applied)
        """
        self.sqlsess = sqlsession
        self.query = query
        self.results = None
        self.filter_applied = False
        self.current_mission = 'default'

    def select_mission(self, mission):
        self.current_mission = mission
        self.query = self.query.filter(Mission.name == mission)


    def add_filter(self, filter_):
        """
        :param filter_: Filter object
        """
        filt = filter_.translate()
        if filt is not None:
            self.filter_applied = True
            self.query = self.query.filter(filt)


    def order_by(self, column):
        self.query = self.query.order_by(column)


    def get_results(self):
        return self.query.all()

    def get_first_result(self):
        return self.query.first()