#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Utils > WebUtils
###
import bs4
import re
import urllib3
import requests
from six.moves.urllib.parse import urlparse
from lib.utils.StringUtils import StringUtils

urllib3.disable_warnings()


HTTP_KEYWORDS = 'html|http|head|body|404|403|401|500'
USER_AGENT = 'Mozilla/5.0 (X11; Linux x86_64; rv:62.0) Gecko/20100101 Firefox/62.0'

class WebUtils:

    @staticmethod
    def add_prefix_http(url):
        """If protocol not present, add http:// prefix"""
        if not url:
            return False
        if not url.startswith('http://') and not url.startswith('https://'):
            return 'http://{0}'.format(url)
        return url


    @staticmethod
    def switch_http_https(url):
        """
        Switch between HTTP and HTTPS in the url
        http://  -> https://
        https:// -> http:// 
        """
        newurl = ''
        if url.startswith('http://'):
            newurl = 'https://' + url[7:]
        elif url.startswith('https://'):
            newurl = 'http://' + url[8:]
        return newurl

    @staticmethod
    def is_valid_url(url):
        """Check if given URL is valid"""
        regex = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+'
            r'(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # ...or ipv4
            r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # ...or ipv6
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        return True if regex.match(url) else False


    @staticmethod
    def is_url_reachable(url):
        """Check if an URL is reachable"""
        try:
            http = urllib3.PoolManager(cert_reqs='CERT_NONE')
            r = http.request('GET', url, headers={'User-Agent': USER_AGENT})
            return (True, r.status, r.getheaders())
        except Exception as e:
            print(e)
            return (False, None, None)


    @staticmethod
    def is_returning_http_data(ip, port):
        """
        Check if the given ip:port actually returns HTTP data
        :return: URL if ok, else ''
        """
        timeout = urllib3.util.timeout.Timeout(0.4)
        http_url  = 'http://{0}:{1}'.format(ip, port)
        https_url = 'https://{0}:{1}'.format(ip, port)
        regex = re.compile(HTTP_KEYWORDS, re.IGNORECASE)
        http = urllib3.PoolManager(cert_reqs='CERT_NONE')
        try:
            r1 = http.request(
                'GET', https_url, 
                headers={'User-Agent': USER_AGENT}, timeout=timeout)
            r2 = http.request(
                'GET', '{0}/aaa'.format(https_url), 
                headers={'User-Agent': USER_AGENT}, timeout=timeout)
            if r1.data or r2.data:
                if regex.search(str(r1.data)) or regex.search(str(r2.data)):
                    return https_url
        except Exception as e:
            pass
        try:
            r1 = http.request('GET', http_url, timeout=timeout)
            r2 = http.request(
                'GET', '{0}/aaa'.format(http_url), 
                headers={'User-Agent': USER_AGENT}, timeout=timeout)
            
            if r1.data or r2.data:
                if regex.search(str(r1.data)) or regex.search(str(r2.data)):
                    return http_url
            return ''
        except Exception as e:
            #print e
            return ''


    @staticmethod
    def get_port_from_url(url):
        """Return port from URL"""
        parsed = urlparse(url)
        if parsed.port:
            return int(parsed.port)
        else:
            return 443 if parsed.scheme == 'https' else 80

    @staticmethod
    def grab_html_title(url):
        """Return HTML title from an URL"""
        try:
            r = requests.get(url, verify=False)
            html = bs4.BeautifulSoup(r.text, 'html.parser')

            # Remove non-ASCII characters and duplicate spaces
            title = StringUtils.remove_non_printable_chars(html.title.text.strip())
            title = " ".join(title.split())
            return title
        except:
            return ''



