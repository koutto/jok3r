#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
### Screenshoter > Web Screenshoter
###
import os
import sys
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.common.exceptions import NoAlertPresentException
from selenium.common.exceptions import TimeoutException
from selenium.common.exceptions import UnexpectedAlertPresentException
from selenium.common.exceptions import WebDriverException
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities

from lib.db.Screenshot import ScreenStatus
from lib.output.Logger import logger


class WebScreenshoter:
    """
    This class is used to generate a web page screenshot.

    Credit:
    It is directly adapted from the great project "EyeWitness" available on github:
    https://github.com/FortyNorthSecurity/EyeWitness/blob/master/modules/selenium_module.py
    It also make use of custom firefox addon to handle basic auth:
    https://github.com/FortyNorthSecurity/EyeWitness/raw/master/bin/dismissauth.xpi
    """

    def __init__(self, timeout=7, max_attempts=2, user_agent=None):
        """
        :param int timeout: Page load timeout (optional)
        :param int max_attempts: Maximum number of attempts to take a screenshot
            (used when timeout is reached)
        :param str user_agent: User-agent string (optional)
        """
        self.timeout = timeout
        self.max_attempts = max_attempts
        self.user_agent = user_agent

        # Selenium Firefox Driver (selenium.webdriver.Firefox)
        self.driver = None 


    def create_driver(self):
        """
        Creates a selenium FirefoxDriver.

        :return: Creation status
        :rtype: bool
        """
        profile = webdriver.FirefoxProfile()

        # Load custom firefox addon to handle basic auth.
        extension_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),'dismissauth.xpi')
        profile.add_extension(extension_path)

        # Set user agent if necessary
        if self.user_agent is not None:
            profile.set_preference('general.useragent.override', self.user_agent)

        # Set up our proxy information directly in the firefox profile
        # if cli_parsed.proxy_ip is not None and cli_parsed.proxy_port is not None:
        # profile.set_preference('network.proxy.type', 1)
        #     if "socks" in cli_parsed.proxy_type:
        #     profile.set_preference('network.proxy.socks', cli_parsed.proxy_ip)
        #     profile.set_preference('network.proxy.socks_port', cli_parsed.proxy_port)
        #     profile.set_preference('network.proxy.socks_remote_dns', True)
        # else:
        #     profile.set_preference('network.proxy.http', cli_parsed.proxy_ip)
        #     profile.set_preference(
        #     'network.proxy.http_port', cli_parsed.proxy_port)
        #     profile.set_preference('network.proxy.ssl', cli_parsed.proxy_ip)
        #     profile.set_preference('network.proxy.ssl_port', cli_parsed.proxy_port)

        profile.set_preference('app.update.enabled', False)
        profile.set_preference('browser.search.update', False)
        profile.set_preference('extensions.update.enabled', False)
        profile.set_preference('capability.policy.default.Window.alert', 'noAccess')
        profile.set_preference('capability.policy.default.Window.confirm', 'noAccess')
        profile.set_preference('capability.policy.default.Window.prompt', 'noAccess')

        try:
            capabilities = DesiredCapabilities.FIREFOX.copy()
            capabilities.update({'acceptInsecureCerts': True})
            options = Options()
            options.add_argument("--headless")
            driver = webdriver.Firefox(
                profile, capabilities=capabilities, options=options)
            driver.set_page_load_timeout(self.timeout)
            self.driver = driver
            return True
        except Exception as e:
            if 'Failed to find firefox binary' in str(e):
                logger.error('Firefox not found! You can fix this by installing Firefox')
            else:
                logger.error(e)
            return False


    def take_screenshot(self, url):
        """
        Take screenshot of a web page and return it as binary data.

        :param str url: URL of the web page to take screenshot of
        :return: Status and screenshot as binary data if no error occured
        :rtype: ScreenStatus, bytearray()
        """

        # Attempt to access the URL with webdriver
        for i in range(1, self.max_attempts+1):

            try:
                self.driver.get(url)
                status = ScreenStatus.OK
                break

            except KeyboardInterrupt:
                logger.warning('Web Screenshot: Skipping {url}'.format(url=url))
                status = ScreenStatus.SKIPPED

            except TimeoutException:
                if i < self.max_attempts:
                    logger.info('Web Screenshot: Hit timeout limit when connecting ' \
                        'to {url}, retrying...'.format(url=url))
                    if not self.__recreate_driver():
                        status = ScreenStatus.ERROR
                        break
                else:
                    logger.warning('Web Screenshot: Hit timeout limit when connecting ' \
                        'to {url}, retrying...'.format(url=url))
                    status = ScreenStatus.TIMEOUT
                    break

            except httplib.BadStatusLine:
                logger.warning('Web Screenshot: Bad status line when connecting to ' \
                    '{url}'.format(url=url))
                status = ScreenStatus.BADSTATUS
                break

            except WebDriverException:
                if i < self.max_attempts:
                    logger.info('Web Screenshot: WebDriverError when connecting to ' \
                        '{url}, retrying...'.format(url=url))
                    if not self.__recreate_driver():
                        status = ScreenStatus.ERROR
                        break
                else:
                    logger.warning('Web Screenshot: WebDriverError when connecting to ' \
                        'to {url}...'.format(url=url))
                    status = ScreenStatus.BADSTATUS
                    break

            # Dismiss any alerts present on the page
            # Will not work for basic auth dialogs!
            try:
                alert = self.driver.switch_to.alert
                alert.dismiss()
            except Exception as e:
                pass

        # Take the screenshot if everything is ok so far
        if status == ScreenStatus.OK:
            for i in range(1, self.max_attempts+1):
                try:
                    #driver.save_screenshot('screen.png')
                    screenshot = self.driver.get_screenshot_as_png()
                    break
                except WebDriverException as e:
                    if i < self.max_attempts:
                        logger.info('Web Screenshot: WebDriverError when taking web page ' \
                            'screenshot for {url}, retrying...'.format(url=url))
                        
                        # Re-create driver
                        if not self.__recreate_driver():
                            status = ScreenStatus.ERROR
                            screenshot = None
                            break
                    else:
                        logger.warning('Web Screenshot: WebDriverError when taking web page ' \
                            'screenshot for {url}'.format(url=url))
                        status = ScreenStatus.BADSTATUS
                        screenshot = None
        else:
            screenshot = None

        return status, screenshot


    def __recreate_driver(self):
        """
        Attempt to re-create selenium FirefoxDriver.
        Called when an error has occured and before making a retry.

        :return: Boolean indicating status
        :rtype: bool
        """
        self.driver.quit()
        self.create_driver()
        if not self.driver:
            logger.warning('Web Screenshot: An error occured when reinitializing ' \
                'WebDriver')
            return False
        else:
            return True




# driver = create_driver()
# if not driver :
# screenshot = capture_host('https://github.com/', driver)

# import io
# from PIL import Image

# size = 300,300

# image = Image.open(io.BytesIO(screenshot))
# image.thumbnail(size, Image.ANTIALIAS)
# image.save('screen.thumb.png')

# region = image.crop(size)
#     region.save('sample_screenshot_3.jpg', 'JPEG', optimize=True, quality=95)