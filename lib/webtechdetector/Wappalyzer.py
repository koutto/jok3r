#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Smartmodules > Web Technologies > Wappalyzer
###
# Code fully adapted from https://github.com/kanishk619/wappalyzer-python
import json
import os
import re
import urllib3
import requests
from bs4 import BeautifulSoup

urllib3.disable_warnings()


class Props(object):

    def __init__(self, *args, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


    def __getattr__(self, item):
        if item not in self.__dict__:
            return None
        return self.__dict__[item]


class Application(object):

    def __init__(self, name, props, detected=False):
        self.confidence = {}
        self.confidenceTotal = 0
        self.detected = bool(detected)
        self.excludes = []
        self.name = name
        self.props = Props(**props)
        self.version = ''


    def __str__(self):
        return self.name


    def getConfidence(self):
        total = 0
        for id in self.confidence:
            total += int(self.confidence[id])
        self.confidenceTotal = min(total, 100)
        return self.confidenceTotal


class Wappalyzer(requests.Session):

    def __init__(self, url, filename='apps.json'):
        super().__init__()
        self.verify = False

        file = os.path.join(os.getcwd(), os.path.dirname(__file__), filename)
        if not os.path.exists(file):
            self.log('Downloading latest wappalyzer database file', 'init', 'error')
            self.downloadWappalyzerDB(file)

        self.headers['User-Agent'] = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko) ' \
            'Chrome/65.0.3325.181'
        self.db = json.load(open(file, encoding='utf-8'))
        self.apps = self.db['apps']
        self.jsPatterns = self.parseJsPatterns()
        self.url = url
        self.data = self.get(url)
        js = {}
        for i in self.jsPatterns:
            for j in self.jsPatterns[i]:
                js.update({i: {j: {}}})
        self.data.js = js
        self.data.scripts = [script['src'] for script in
                             BeautifulSoup(self.data.text, 'html.parser').find_all(
                                'script', {'src': True})]

        self.data.headers = {i.lower(): j for i, j in self.data.headers.items()}


    def downloadWappalyzerDB(self, file):
        db_url = 'https://raw.githubusercontent.com/AliasIO/Wappalyzer/master/src/apps.json'
        resp = self.get(db_url, stream=True)
        with open(file, 'wb') as f:
            for chunk in resp.iter_content(chunk_size=1024):
                if chunk:
                    f.write(chunk)


    def asArray(self, value):
        return value if isinstance(value, list) else [value]


    def analyze(self):
        apps = {}
        matches = re.search('<html[^>]*[: ]lang="([a-z]{2}((-|_)[A-Z]{2})?)"', 
            self.data.text, re.IGNORECASE)
        language = None
        if matches:
            language = matches.groups()[0]
            matches = matches.group()

        for appName in self.apps:
            apps[appName] = Application(appName, self.apps[appName])
            app = apps[appName]
            if self.data.text:
                self.analyzeHtml(app, self.data.text)
                self.analyzeMeta(app, self.data.text)

            if self.data.scripts:
                self.analyzeScripts(app, self.data.scripts)

            if self.data.headers:
                self.analyzeHeaders(app, self.data.headers)

            if hasattr(self.data, 'env'):
                self.analyzeEnv(app, self.data.env)

        if self.data.js:
            for appName in self.data.js:
                self.analyzeJs(apps[appName], self.data.js[appName])

        for appName, app in apps.copy().items():
            if not app.detected or not app.getConfidence():
                apps.pop(appName)

        self.resolveExcludes(apps)
        self.resolveImplies(apps)
        return apps


    def parseJsPatterns(self):
        patterns = {}
        for appName in self.apps:
            if 'js' in self.apps[appName]:
                patterns.update({appName: self.parsePatterns(self.apps[appName]['js'])})
        return patterns


    def resolveExcludes(self, apps):
        excludes = []
        for appName, app in apps.items():
            if app.props.excludes:
                for excluded in self.asArray(app.props.excludes):
                    excludes.append(excluded)
        for appName in apps.copy():
            if appName in excludes:
                apps.pop(appName)


    def parsePatterns(self, patterns):
        if not patterns:
            return []

        parsed = {}
        if isinstance(patterns, str) or isinstance(patterns, list):
            patterns = {
                'main': self.asArray(patterns)
            }

        for key in patterns:
            parsed[key] = []

            for pattern in self.asArray(patterns[key]):
                attrs = {}

                pattern_version = pattern.split('\\;')

                for i in range(len(pattern_version)):
                    attr = pattern_version[i]
                    if i:
                        attr = attr.split(':')
                        if len(attr) > 1:
                            attrs[attr[0]] = attr[1]
                    else:
                        attrs['string'] = attr
                        attrs['regex'] = attr.replace('/', '\/')
                    parsed[key].append(attrs)

        if 'main' in parsed:
            parsed = parsed['main']
        return parsed


    def resolveImplies(self, apps):
        checkImplies = True
        while checkImplies:
            checkImplies = False
            for appName in apps.copy():
                app = apps[appName]
                if app and app.props.implies:
                    for implied in self.asArray(app.props.implies):
                        implied = self.parsePatterns(implied)[0]

                        if not self.apps[implied['string']]:
                            self.log('Implied application ' + implied.string + \
                                ' does not exist', 'core', 'warn')
                            return

                        if not implied['string'] in apps:
                            apps[implied['string']] = Application(
                                implied['string'], self.apps[implied['string']], True)
                            checkImplies = True

                        for id in app.confidence:
                            ind = id+' implied by '+appName
                            apps[implied['string']].confidence[ind] = \
                                    app.confidence[id] * int(
                                        int(implied['confidence']) / 100 \
                                            if 'confidence' in implied else 1)


    def analyzeUrl(self, app: Application, url):
        patterns = self.parsePatterns(app.props['url'])
        if patterns:
            for pattern in patterns:
                if re.search(pattern['regex'], url):
                    self.addDetected(app, pattern, 'url', url)


    def analyzeHtml(self, app, html):
        patterns = self.parsePatterns(app.props.html)
        if patterns:
            try:
                for pattern in patterns:
                    #print(pattern)
                    if 'regex' in pattern and re.search(pattern['regex'], html):
                        self.addDetected(app, pattern, 'html', html)
            except:
                pass


    def analyzeScripts(self, app: Application, scripts):
        patterns = self.parsePatterns(app.props.script)
        for pattern in patterns:
            for uri in scripts:
                if re.search(pattern['regex'], uri):
                    self.addDetected(app, pattern, 'script', uri)


    def analyzeMeta(self, app, html):
        regex = re.compile('<meta[^>]+>', re.IGNORECASE)
        patterns = self.parsePatterns(app.props.meta)
        matches = re.findall(regex, html)
        for match in matches:
            for meta in patterns:
                r = re.search('(?:name|property)=["\']' + meta + '["\']', 
                              match, re.IGNORECASE)
                if r:
                    content = re.findall('content=["|\']([^"\']+)["|\']', 
                                         match, re.IGNORECASE)
                    for pattern in patterns[meta]:
                        if content and re.search(pattern['regex'], 
                                                 content[0], re.IGNORECASE):
                            self.addDetected(app, pattern, 'meta', content[0], meta)


    def analyzeHeaders(self, app: Application, headers: dict):
        patterns = self.parsePatterns(app.props.headers)
        if headers:
            for headerName in patterns:
                for pattern in patterns[headerName]:
                    headerName = headerName.lower()
                    if headerName in headers:
                        headerValue = headers[headerName]
                        if re.search(pattern['regex'], headerValue):
                            self.addDetected(
                                app, pattern, 'headers', headerValue, headerName)


    def analyzeJs(self, app: Application, results):
        for string in results:
            for index in results[string]:
                pattern = self.jsPatterns[app.name][string][index]
                value = results[string][index]

                if pattern and re.search(pattern['regex'], value):
                    self.addDetected(app, pattern, 'js', value)


    def addDetected(self, app: Application, pattern, type, value, key=''):
        app.detected = True
        app.confidence[type + ' ' + (key + ' ' if key else '') + pattern['regex']] = \
            pattern['confidence'] if 'confidence' in pattern else 100

        if 'version' in pattern:
            versions = []
            version = pattern['version']
            matches = re.findall(pattern['regex'], value, re.IGNORECASE)
            if matches:
                for i in range(len(matches)):
                    match = matches[i]
                    ternary = re.findall('\\\\' + str(i) + '\\?([^:]+):(.*)$', version)

                    if isinstance(match, tuple):  
                        # findall returns tuple groups sometimes if groups used in regex
                        match = match[1]

                    if ternary and len(ternary) >= 3:
                        version = version.replace(ternary[0], ternary[1] \
                            if match else ternary[2])

                    version = version.replace(version, match or '')

                    if version and version not in versions:
                        versions.append(version.strip())

                    if len(versions):
                        app.version = max(versions)


    def analyzeEnv(self, app, envs):
        patterns = self.parsePatterns(app.props.env)
        for pattern in patterns:
            for env in envs:
                if re.search(pattern['regex'], env):
                    self.addDetected(app, pattern, 'env', env)


    def log(self, message, source, _type):
        print('[wappalyzer {}] [{}] {}'.format(_type, source, message))


    def __del__(self):
        del self.db
        del self.apps
        del self.jsPatterns
        del self.data


#----------------------------------------------------------------------------------------

def getSimple(url):
    """
    Output example:
    {
        'cdn': ['CloudFlare'], 
        'cms': ['SPIP'], 
        'javascript-libraries': ['XRegExp', 'jQuery'], 
        'programming-languages': ['PHP']
    }
    """
    wappalyzer = Wappalyzer(url)
    apps = wappalyzer.analyze()
    simple_result = {}

    for appName, app in apps.items():
        categories = app.props.cats
        for category_id in categories:
            category_name = wappalyzer.db['categories'][str(category_id)]['name'].lower().replace(' ', '-')
            if category_name not in simple_result:
                simple_result.update({category_name: []})
            simple_result[category_name].append(appName)
    del wappalyzer
    return simple_result


def getDetail(url):  # wappalyzer styled output
    """
    Output example:
    {
        'applications': [
            {'confidence': '100', 'name': 'CloudFlare', 'version': ''},
            {'confidence': '100', 'name': 'SPIP', 'version': '2.1.10'},
            {'confidence': '100', 'name': 'XRegExp', 'version': ''},
            {'confidence': '100', 'name': 'jQuery', 'version': ''},
            {'confidence': '0', 'name': 'PHP', 'version': ''}],
        'url': 'https://www.site.com/'
    }
    """
    wappalyzer = Wappalyzer(url)
    apps = wappalyzer.analyze()
    detail_result = {"url": url, "applications": []}

    for appName, app in apps.items():
        f = {
            'name': app.name,
            'confidence': str(app.confidenceTotal),
            'version': app.version,
            #'icon': app.props.icon,
            #'website': app.props.website,
            #'categories': [{str(c): wappalyzer.db['categories'][str(c)]['name']} \
            #   for c in app.props.cats]
        }
        detail_result['applications'].append(f)
    del wappalyzer
    return detail_result


# import pprint
# pprint.pprint(getDetail("https://www.site.com/"))
