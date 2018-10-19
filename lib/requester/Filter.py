# -*- coding: utf-8 -*-
###
### Requester > Filter
###
from lib.core.Constants import *


class Filter:

    def __init__(self, operator=FilterOperator.AND):
        """
        Filters can be encapsulated
        """
        self.conditions = list()
        self.operator = operator

    def add_condition(self, condition):
        """
        :param condition: Condition object
        """
        self.conditions.append(condition)

    def translate(self):
        """
        Translate the filter into sqlalchemy filter
        """
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
