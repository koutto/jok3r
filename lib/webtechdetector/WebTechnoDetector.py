#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Smartmodules > Web Technologies > Web Techno Detector
###
from lib.webtechdetector.Wappalyzer import Wappalyzer
from lib.output.Output import Output


class WebTechnoDetector:

    def __init__(self, url):
        self.url = url
        self.technos = list()


    def detect(self):
        """
        Detect web technologies.

        :return: List of detected web technologies
        :rtype: list(dict('name', 'version'))
        """
        self.technos = self.__run_wappalyzer()

        # TODO: Add other detection methods
        
        return self.technos


    def print_technos(self):
        """
        Display web technologies detected in a table.
        """
        data = list()
        columns = ['Name', 'Version']
        for t in self.technos:
            data.append([t['name'], t['version']])
        Output.table(columns, data, hrules=False)


    def __run_wappalyzer(self):
        """Detect web technologies using Wappalyzer"""
        technos = list()
        wappalyzer = Wappalyzer(self.url)
        apps = wappalyzer.analyze()

        for appName, app in apps.items():
            f = {
                'name': app.name,
                'version': app.version,
            }
            technos.append(f)
        del wappalyzer
        return technos