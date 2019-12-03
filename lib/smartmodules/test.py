#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import inspect

from lib.smartmodules.SmartPostcheck import SmartPostcheck
from lib.utils.StringUtils import StringUtils
from lib.output.Logger import logger





logger.setLevel('DEBUG')


output = """
[*] Looking for "Joomla 3.7.0" in cvedetails.com database...
[!] No exact match for this product/version. Checking for CVE in newer versions...
[*] Checking with version = 3.7.0%
[*] Checking with version = 3.7.%
[*] Checking with version = 3.7%
[*] Checking with version = 3.%
[*] Checking with version = 3%
[*] Checking with version = %
[+] Closest superior version found in database is: 2007-01-18
[*] IDs summary: Vendor=Joomla [3496] | Product=Joomla [6129] | Version=2007-01-18 [40634]
[*] Fetch results for version id 40634 ...
[+] Total number of CVEs fetched: 1
[*] Results ordered by published date (desc):
+---------------+------+------------+----------------------------------------------------------------------------------+----------------------------------------------+----------+
| ID            | CVSS | Date       | Description                                                                      | URL                                          | Exploit? |
+---------------+------+------------+----------------------------------------------------------------------------------+----------------------------------------------+----------+
| CVE-2007-0387 | 7.5  | 2007-01-19 | SQL injection vulnerability in models/category.php in the Weblinks component for | http://www.cvedetails.com/cve/CVE-2007-0387/ | None     |
|               |      |            | Joomla! SVN 20070118 (com_weblinks) allows remote attackers to execute arbitrary |                                              |          |
|               |      |            | SQL commands via the catid parameter.                                            |                                              |          |
+---------------+------+------------+----------------------------------------------------------------------------------+----------------------------------------------+----------+

[*] CSV output:
ID;CVSS;Date;Description;URL;Exploit?
CVE-2007-0387;7.5;2007-01-19;SQL injection vulnerability in models/category.php in the Weblinks component for Joomla! SVN 20070118 (com_weblinks) allows remote attackers to execute arbitrary SQL commands via the catid parameter.;http://ww
w.cvedetails.com/cve/CVE-2007-0387/;None


"""

service = 'http'
tool_name = 'cvedetails-lookup'
output = StringUtils.interpret_ansi_escape_clear_lines(output)
outputraw = StringUtils.remove_ansi_escape(output)

postcheck = SmartPostcheck(
    service,
    tool_name,
    None,
    '{0}\n{1}'.format(cmdline, outputraw))

postcheck.run()