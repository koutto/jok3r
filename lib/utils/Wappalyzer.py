#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Utils > Wappalyzer
###
#
# Code taken from https://github.com/LyleMi/python3-Wappalyzer
#
# >>> from Wappalyzer import WebPage
# >>> WebPage("https://github.com").info()
# {'apps': 'Twitter Bootstrap', 'title': "The world's leading software development platform · GitHub"}
# >>> WebPage("https://fr.wordpress.com/").info()
# {'apps': 'Nginx;WordPress;PHP;Google Font API', 'title': 'WordPress.com : Créez un site ou un blog gratuit'}
#

import re
import json
import requests
from bs4 import BeautifulSoup


class WebPage(object):
    """
    Simple representation of a web page, decoupled
    from any particular HTTP library's API.
    """

    def __init__(self, url, verify=False):
        """
        Initialize a new WebPage object.

        Parameters
        ----------

        url : str
            The web page URL.
        html : str
            The web page content (HTML)
        headers : dict
            The HTTP response headers
        """
        response = requests.get(url, verify=verify, timeout=30)
        self.url = url
        # if use response.text, could have some error
        self.html = response.content.decode('utf8')
        self.headers = response.headers

        # Parse the HTML with BeautifulSoup to find <script> and <meta> tags.
        self.parsed_html = soup = BeautifulSoup(self.html, "html.parser")
        self.scripts = [script['src'] for script in
                        soup.findAll('script', src=True)]
        self.meta = {
            meta['name'].lower():
                meta['content'] for meta in soup.findAll(
                    'meta', attrs=dict(name=True, content=True))
        }

        self.title = soup.title.string if soup.title else 'None'

        wappalyzer = Wappalyzer()
        self.apps = wappalyzer.analyze(self)

    def info(self):
        return {
            "apps": ';'.join(self.apps),
            "title": self.title,
        }


class Wappalyzer(object):
    """
    Python Wappalyzer driver.
    """

    def __init__(self, apps_file=None):
        """
        Initialize a new Wappalyzer instance.

        Parameters
        ----------

        categories : dict
            Map of category ids to names, as in apps.json.
        apps : dict
            Map of app names to app dicts, as in apps.json.
        """
        if apps_file:
            with open(apps_file, 'r') as fd:
                obj = json.load(fd)
        else:
            with open("lib/utils/wappalyzer-apps.json", 'r') as fd:
                obj = json.load(fd)

        self.categories = obj['categories']
        self.apps = obj['apps']

        for name, app in self.apps.items():
            self._prepare_app(app)

    def _prepare_app(self, app):
        """
        Normalize app data, preparing it for the detection phase.
        """

        # Ensure these keys' values are lists
        for key in ['url', 'html', 'script', 'implies']:
            value = app.get(key)
            if value is None:
                app[key] = []
            else:
                if not isinstance(value, list):
                    app[key] = [value]

        # Ensure these keys exist
        for key in ['headers', 'meta']:
            value = app.get(key)
            if value is None:
                app[key] = {}

        # Ensure the 'meta' key is a dict
        obj = app['meta']
        if not isinstance(obj, dict):
            app['meta'] = {'generator': obj}

        # Ensure keys are lowercase
        for key in ['headers', 'meta']:
            obj = app[key]
            app[key] = {k.lower(): v for k, v in obj.items()}

        # Prepare regular expression patterns
        for key in ['url', 'html', 'script']:
            app[key] = [self._prepare_pattern(pattern) for pattern in app[key]]

        for key in ['headers', 'meta']:
            obj = app[key]
            for name, pattern in obj.items():
                obj[name] = self._prepare_pattern(obj[name])

    def _prepare_pattern(self, pattern):
        """
        Strip out key:value pairs from the pattern and compile the regular
        expression.
        """
        regex, _, rest = pattern.partition('\\;')
        try:
            return re.compile(regex, re.I)
        except re.error as e:
            # regex that never matches:
            # http://stackoverflow.com/a/1845097/413622
            return re.compile(r'(?!x)x')

    def _has_app(self, app, webpage):
        """
        Determine whether the web page matches the app signature.
        """
        # Search the easiest things first and save the full-text search of the
        # HTML for last

        for regex in app['url']:
            if regex.search(webpage.url):
                return True

        for name, regex in app['headers'].items():
            if name in webpage.headers:
                content = webpage.headers[name]
                if regex.search(content):
                    return True

        for regex in app['script']:
            for script in webpage.scripts:
                if regex.search(script):
                    return True

        for name, regex in app['meta'].items():
            if name in webpage.meta:
                content = webpage.meta[name]
                if regex.search(content):
                    return True

        for regex in app['html']:
            if regex.search(webpage.html):
                return True

    def _get_implied_apps(self, detected_apps):
        """
        Get the set of apps implied by `detected_apps`.
        """
        def __get_implied_apps(apps):
            _implied_apps = set()
            # edited here to correct a bug from original script
            apps = set(map(lambda x: x.split('\\')[0], apps))
            try:
                for app in apps:
                    if 'implies' in self.apps[app]:
                        implies = set(map(lambda x: x.split('\\')[0], set(self.apps[app]['implies'])))
                        _implied_apps.update(implies)
            except:
                pass
            return _implied_apps

        #print(detected_apps)
        implied_apps = __get_implied_apps(detected_apps)
        all_implied_apps = set()

        # Descend recursively until we've found all implied apps
        while not all_implied_apps.issuperset(implied_apps):
            all_implied_apps.update(implied_apps)
            implied_apps = __get_implied_apps(all_implied_apps)

        print(all_implied_apps)
        return all_implied_apps

    def get_categories(self, app_name):
        """
        Returns a list of the categories for an app name.
        """
        cat_nums = self.apps.get(app_name, {}).get("cats", [])
        cat_names = [self.categories.get("%s" % cat_num, "")
                     for cat_num in cat_nums]

        return cat_names

    def analyze(self, webpage):
        """
        Return a list of applications that can be detected on the web page.
        """
        detected_apps = set()

        for app_name, app in self.apps.items():
            if self._has_app(app, webpage):
                detected_apps.add(app_name)

        detected_apps |= self._get_implied_apps(detected_apps)

        return detected_apps

    def analyze_with_categories(self, webpage):
        detected_apps = self.analyze(webpage)
        categorised_apps = {}

        for app_name in detected_apps:
            cat_names = self.get_categories(app_name)
            categorised_apps[app_name] = {"categories": cat_names}

        return categorised_apps
