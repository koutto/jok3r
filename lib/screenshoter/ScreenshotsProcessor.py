#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Screenshoter > Screenshots Processor
###
from lib.core.Constants import *
from lib.db.Screenshot import Screenshot, ScreenStatus
from lib.output.Logger import logger
from lib.requester.Filter import Filter
from lib.requester.Condition import Condition
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
        self.screenshoter = WebScreenshoter()
        if not self.screenshoter.create_driver():
            logger.error("Unable to create screenshoter driver !")
            return None

    def run(self):

        # Extract HTTP services from the mission in database
        from lib.requester.ServicesRequester import ServicesRequester

        req = ServicesRequester(self.sqlsession)
        req.select_mission(self.mission_name)
        filter_ = Filter(FilterOperator.AND)
        filter_.add_condition(Condition("http", FilterData.SERVICE_EXACT))
        req.add_filter(filter_)
        services = req.get_results()

        if len(services) == 0:
            return

        logger.info(
            "Taking web page screenshots for HTTP services (total: "
            "{nb})...".format(nb=len(services))
        )

        i = 1
        for s in services:
            self.take_screenshot(s, i, len(services))
            i += 1

    def take_screenshot(self, service, current_nb=None, total_nb=None):
        """
        Take screenshot of web page of target HTTP service.

        :param Service service: Service model object
        :param int current_nb: Current number of screenshot to take (None for single
            screenshot)
        :param int total_nb: Total number of screenshots to take (None for single
            screenshot)
        :return: Status
        :rtype: ScreenStatus
        """
        if current_nb is not None and total_nb is not None:
            prefix = "[{i}/{nb}] ".format(i=current_nb, nb=total_nb)
        else:
            prefix = ""

        if (
            service.screenshot is not None
            and service.screenshot.status == ScreenStatus.OK
            and service.screenshot.image is not None
            and service.screenshot.thumbnail is not None
        ):
            logger.info(
                "{prefix}Screenshot already in database for {url}".format(
                    prefix=prefix, url=service.url
                )
            )
            return ScreenStatus.OK

        else:
            logger.info(
                "{prefix}Taking screenshot for {url}...".format(
                    prefix=prefix, url=service.url)
            )
            status, screen = self.screenshoter.take_screenshot(service.url)

            # Create Screenshot entry in database if necessary
            if service.screenshot is None:
                screenshot = Screenshot(status=status)
                self.sqlsession.add(screenshot)
                service.screenshot = screenshot
                self.sqlsession.commit()

            # Create thumbnail if status is OK
            if status == ScreenStatus.OK:
                thumb = ImageUtils.create_thumbnail(screen, 300, 300)
                if not thumb:
                    status = ScreenStatus.ERROR
                service.screenshot.status = status
                service.screenshot.image = screen
                service.screenshot.thumbnail = thumb
            else:
                service.screenshot.status = status
            self.sqlsession.commit()

            return status
