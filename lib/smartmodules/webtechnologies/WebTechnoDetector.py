#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Smartmodules > Web Technologies > Web Techno Detector
###
from lib.smartmodules.webtechnologies.Wappalyzer import Wappalyzer


class WebTechnoDetector:

    def __init__(self, url):
        self.url = url


    def detect(self):
        """
        Detect web technologies.

        :return: List of detected web technologies
        :rtype: list(dict('name', 'version'))
        """
        technos = self.__run_wappalyzer()

        # TODO: Add other detection methods
        
        return technos


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