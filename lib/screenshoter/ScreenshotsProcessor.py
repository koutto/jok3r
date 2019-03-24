#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Screenshoter > Screenshots Processor
###
from lib.db.Screenshot import ScreenStatus
from lib.output.Logger import logger
from lib.requester.Filter import Filter
from lib.requester.Condition import Condition
from lib.requester.ServicesRequester import ServicesRequester
from lib.screenshoter.WebScreenshoter import WebScreenshoter
from lib.utils.ImageUtils import ImageUtils


class ScreenshotsProcessor:

    def __init__(self, mission_name, sqlsession):
        """
        :param str mission_name: Name of the mission to process
        :param Session sqlsession: SQLAlchemy session
        """
        self.mission_name = mission_name
        self.sqlsession = sqlsession


    def run(self):

        # Extract HTTP services from the mission in database
        req = ServicesRequester(self.sqlsession)
        req.select_mission(self.mission_name)
        filter_ = Filter(FilterOperator.AND)
        filter_.add_condition(Condition('http', FilterData.SERVICE_EXACT))
        req.add_filter(filter_)
        services = req.get_results()

        if len(services) == 0:
            return

        logger.info('Taking web page screenshots for HTTP services (total: ' \
            '{nb})...'.format(nb=len(services)))

        screenshoter = WebScreenshoter()
        if not screenshoter.create_driver():
            logger.error('No screenshot will be added to the report')
            return

        i = 1
        for s in services:
            if s.screenshot is not None and s.screenshot.status == ScreenStatus.OK:
                logger.info('[{i}/{nb}] Screenshot already in database for {url}'.format(
                    i=i, nb=len(services), url=s.url))
            else:
                logger.info('[{i}/{nb}] Taking screenshot for {url}...'.format(
                    i=i, nb=len(services), url=s.url))
                status, screen = screenshoter.take_screenshot(s.url)

                # Create Screenshot entry in database if necessary
                if s.screenshot is None:
                    screenshot = Screenshot(status=status)
                    self.sqlsession.add(screenshot)
                    s.screenshot = screenshot
                    self.sqlsession.commit()

                # Create thumbnail if status is OK
                if status == ScreenStatus.OK:
                    thumb = ImageUtils.create_thumbnail(screen, 300, 300)
                    s.screenshot.status = status
                    s.screenshot.image = screen
                    s.screenshot.thumbnail = thumb
                else:
                    s.screenshot.status = status
                self.sqlsession.commit()

            i += 1


