#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Utils > OrderedDefaultDict
###
import collections


# From https://gist.github.com/stevekm/b722712e40df6cf5886af4e6aa7265db

# class OrderedDefaultDict(collections.OrderedDict, collections.defaultdict):
#     def __init__(self, default_factory=None, *args, **kwargs):
#         #in python3 you can omit the args to super
#         super().__init__(*args, **kwargs)
#         self.default_factory = default_factory

# From https://stackoverflow.com/questions/18809482/python-nesting-dictionary-ordereddict-from-collections
# and https://stackoverflow.com/questions/36727877/inheriting-from-defaultddict-and-ordereddict
class OrderedDefaultDict(collections.OrderedDict):
	
    def __init__(self, default_factory=None, *args, **kwargs):
        super(OrderedDefaultDict, self).__init__(*args, **kwargs)
        self.default_factory = default_factory


    def __missing__(self, key):
        if self.default_factory is None:
            raise KeyError(key)
        val = self[key] = self.default_factory()
        return val