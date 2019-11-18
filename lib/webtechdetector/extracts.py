#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
import os,sys,inspect, time
currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
libdir = os.path.dirname(os.path.dirname(currentdir))
sys.path.insert(0,libdir) 

from lib.smartmodules.matchstrings.products.HttpWebAppserverProducts import *
from lib.smartmodules.matchstrings.products.HttpWebApplicationFirewallProducts import *
from lib.smartmodules.matchstrings.products.HttpWebCmsProducts import *
from lib.smartmodules.matchstrings.products.HttpWebFrameworkProducts import *
from lib.smartmodules.matchstrings.products.HttpWebJslibProducts import *
from lib.smartmodules.matchstrings.products.HttpWebLanguageProducts import *
from lib.smartmodules.matchstrings.products.HttpWebServerProducts import *

def is_in_matchstings(name, type):
    for p in products_match['http'][type]:
        if 'wappalyzer' in products_match['http'][type][p]:
            if name == products_match['http'][type][p]['wappalyzer']:
                return True
    return False

def check_cvedetails(name):
    l = name.split(' ')
    for i in range(len(l)):
        test = ' '.join(l[i:])
        print(test)

        os.system("""
            cd /root/jok3r/toolbox/multi/cvedetails-lookup; 
            python3 cvedetails-lookup.py --product '{product}' --version 0.1;
            """.format(product=test))
        time.sleep(1)

# l = list(products_match['http']['web-cms'].keys())
# l.sort()

# for e in l:
#     print(e+',')


db = json.load(open('./apps.json', encoding='utf-8'))
apps = db['apps']



# # web-server / web-appserver
# for app in apps:
#     # if 'icon' in apps[app]:
#     #     print('"{app}": "{icon}",'.format(app=app, icon=apps[app]['icon']))
#     if 'cats' in apps[app]:
#         if 22 in apps[app]['cats'] and 18 not in apps[app]['cats']:
#             if not is_in_matchstings(app, 'web-appserver') and \
#                not is_in_matchstings(app, 'web-server'):

#         if 21 in apps[app]['cats'] or 1 in apps[app]['cats']:
#             if not is_in_matchstings(app, 'web-cms'):


#                 #print(app)
#                 print(

# """'{product}': {{
#     'wappalyzer': '{product}',
# }},""".format(product=app)
#                 )
#                 # print()
#                 # check_cvedetails(app)
#                 # print()
#                 # print()
#                 pass



# # web-cms
# for app in apps:
#     if 'cats' in apps[app]:

#         if 21 in apps[app]['cats'] or 1 in apps[app]['cats']:
#             if not is_in_matchstings(app, 'web-cms'):


#                 #print(app)
#                 print(

# """'{product}': {{
#     'wappalyzer': '{product}',
# }},""".format(product=app)
#                 )
#                 # print()
#                 # check_cvedetails(app)
#                 # print()
#                 # print()
#                 pass


# web-framework
for app in apps:
    if 'cats' in apps[app]:

        if 18 in apps[app]['cats'] and 25 not in apps[app]['cats'] \
            and 59 not in apps[app]['cats'] and 12 not in apps[app]['cats']\
            and '.js' not in app.lower() and 'css' not in app.lower():
            if not is_in_matchstings(app, 'web-framework') and \
                not is_in_matchstings(app, 'web-language') and \
                not is_in_matchstings(app, 'web-server') and \
                not is_in_matchstings(app, 'web-appserver'):


                #print(app)
                print(

    """'{product}': {{
    'wappalyzer': '{product}',
    }},""".format(product=app)
                )
                # print()
                # check_cvedetails(app)
                # print()
                # print()
                pass