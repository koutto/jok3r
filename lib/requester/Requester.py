#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Requester > Requester
###
from lib.db.Mission import Mission


class Requester:

    def __init__(self, sqlsession, query):
        """
        Interface for Requesters.

        :param Session sqlsession: Sqlalchemy Session
        :param query query: Base query used to access all data (no filter applied)
        """
        self.sqlsess = sqlsession
        self.query = query
        self.results = None
        self.filter_applied = False
        self.current_mission = 'default'


    #------------------------------------------------------------------------------------

    def select_mission(self, mission):
        """
        Select a mission.
        :param str mission: Mission name
        """
        self.current_mission = mission
        self.query = self.query.filter(Mission.name == mission)


    #------------------------------------------------------------------------------------

    def add_filter(self, filter_):
        """
        Add a Filter to the query.
        :param Filter filter_: Filter to apply
        """
        filt = filter_.translate()
        if filt is not None:
            self.filter_applied = True
            self.query = self.query.filter(filt)


    #------------------------------------------------------------------------------------

    def order_by(self, column):
        """
        Add ORDER BY statement
        :param str column: Column name to order by
        """
        self.query = self.query.order_by(column)


    #------------------------------------------------------------------------------------

    def get_results(self):
        """Retrieve all results"""
        return self.query.all()


    def get_first_result(self):
        """Retrieve one result"""
        return self.query.first()