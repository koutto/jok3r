#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
import os,sys,inspect
currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
libdir = os.path.dirname(os.path.dirname(currentdir))
sys.path.insert(0,libdir) 

from lib.smartmodules.matchstrings.MatchStrings import products_match

# CPE file: https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.zip
# CPE format example:
# cpe:2.3:a:.bbsoftware:bb_flashback:*:*:*:*:*:*:*:*
# Other format (v2.2): cpe:/a:cmsimple:cmsimple:4.0 
#
#https://vulners.com/api/v3/burp/software?software=cpe:/a:apache:tomcat&version=7.0.79&type=cpe

def extract_main_cpes():
    j = None
    with open('nvdcpematch-1.0.json', 'r') as f:
        j = json.loads(f.read())

    with open('cpe_extracted.txt', 'w+') as f:
        for c in j['matches']:
            f.write('{}\n'.format(c['cpe23Uri']))


def load_main_cpes():
    cpes = None
    with open('cpe_extracted.txt', 'r') as f:
        cpes = f.read().splitlines()
    return cpes


def load_products():
    products = []
    for svc in products_match.keys():
        for type in products_match[svc].keys():
            for name in products_match[svc][type].keys():
                products.append(name)

    return products


def clean_name(name):
    name = name.lower()
    name = name.replace(' ', '_')
    name = name.replace('!', '\!')
    return name


def eq(name1, name2):

    return(
        name1 == name2 or
        name1.replace('_', '') == name2.replace('_', '') or 
        name1.replace('_', '') == name2 or 
        name1 == name2.replace('_', '') or 
        name1.replace('_', '-') == name2.replace('_', '-') or
        name1.replace('_', '-') == name2 or
        name1 == name2.replace('_', '-')
    )


def are_names_equivalent(name1, name2):
    if eq(name1, name2):
        return True

    if name2.endswith('_cms'):
        name2_alt = name2[:name2.index('_cms')]
        if eq(name1, name2_alt):
            return True

    elif name2.endswith('cms'):
        name2_alt = name2[:name2.index('cms')]
        if eq(name1, name2_alt):
            return True
    return False


def searchfor_corresponding_cpe(product, cpe_list):
    product = clean_name(product)
    if '/' in product:
        vendor, name = product.split('/', maxsplit=1)
    else:
        vendor, name = None, product

    if vendor:
        for cpe in cpe_list:
            c = cpe.split(':')
            vendor_cpe, name_cpe = c[3], c[4]

            
            if are_names_equivalent(vendor_cpe, vendor) and \
                (are_names_equivalent(name_cpe, name) or name_cpe.startswith(name)):
                return cpe

    for cpe in cpe_list:
        c = cpe.split(':')
        vendor_cpe, name_cpe = c[3], c[4]

        if are_names_equivalent(name_cpe, name) and are_names_equivalent(vendor_cpe, name):
            return cpe

    for cpe in cpe_list:
        c = cpe.split(':')
        vendor_cpe, name_cpe = c[3], c[4]
        
        if are_names_equivalent(name_cpe, name):
            return cpe
            
    return None


def convert_cpe23_to_cpe22(cpe23):
    c = cpe23.split(':')
    type, vendor, name = c[2], c[3], c[4]
    return 'cpe:/{type}:{vendor}:{name}'.format(
        type=type,
        vendor=vendor,
        name=name,
    )



list_cpe = load_main_cpes()
products = load_products()

for p in products:
    cpe = searchfor_corresponding_cpe(p, list_cpe)
    print("'{product}': {cpe},".format(
        #status='[+] ' if cpe else '[!]',
        product=p,
        cpe="'{}'".format(convert_cpe23_to_cpe22(cpe)) if cpe else 'None',
    ))