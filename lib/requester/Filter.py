#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Requester > Filter
###
from lib.core.Constants import *


class Filter:

    def __init__(self, operator=FilterOperator.AND):
        """
        Create a Filter object.

        A Filter is a combination of conditions.
        Several Filters can also be encapsulated.

        :param FilterOperator operator: Combination between conditions is 
            performed using AND/OR operator        
        """
        self.conditions = list()
        self.operator = operator


    #------------------------------------------------------------------------------------

    def add_condition(self, condition):
        """
        Add a condition to the filter.
        :param Condition condition: Condition to add
        """
        self.conditions.append(condition)


    #------------------------------------------------------------------------------------
    
    def translate(self):
        """Combine all conditions together to create Sqlalchemy filter"""
        result = None
        for c in self.conditions:
            translated = c.translate()
            if translated is not None:
                if result is None:
                    result = (translated)
                else:
                    if self.operator == FilterOperator.AND:
                        result = result & (translated)
                    else:
                        result = result | (translated)
        return result
