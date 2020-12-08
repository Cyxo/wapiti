#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (http://wapiti.sourceforge.io)
# Copyright (C) 2008-2020 Nicolas Surribas
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
import os
import sys
from os.path import splitext, join as path_join
from urllib.parse import quote
from collections import defaultdict
from enum import Enum
from math import ceil
import random
from types import GeneratorType, FunctionType
from binascii import hexlify

from requests.exceptions import RequestException, ReadTimeout

from wapitiCore.net.web import Request


modules = [
    "mod_test",
    "mod_osint"
]

COMMON_ANNOYING_PARAMETERS = (
    "__VIEWSTATE",
    "__VIEWSTATEENCRYPTED",
    "__VIEWSTATEGENERATOR",
    "__EVENTARGUMENT",
    "__EVENTTARGET",
    "__EVENTVALIDATION",
    "ASPSESSIONID",
    "ASP.NET_SESSIONID",
    "JSESSIONID",
    "CFID",
    "CFTOKEN"
)


# class Flags:
#     def __init__(self, type=PayloadType.pattern, section="", method=PayloadType.get, platform="all", dbms="all"):
#         self.type = type
#         self.section = section
#         self.method = method
#         self.platform = platform
#         self.dbms = dbms
#
#     def with_method(self, method):
#         return Flags(type=self.type, section=self.section, method=method, platform=self.platform, dbms=self.dbms)
#
#     def with_section(self, section):
#         return Flags(type=self.type, section=section, method=self.method, platform=self.platform, dbms=self.dbms)
#
#     def __str__(self):
#         return "Flags(type={}, section='{}', method={}, platform='{}', dbms='{}')".format(
#             self.type,
#             self.section,
#             self.method,
#             self.platform,
#             self.dbms
#         )
#
#     def __eq__(self, other):
#         if not isinstance(other, Flags):
#             raise ValueError("Can't compare a Flags object to another kind of object")
#
#         return (
#             self.type == other.type and
#             self.section == other.section and
#             self.method == other.method and
#             self.platform == other.platform and
#             self.dbms == other.dbms
#         )


class Result:
    """This class is what every passive module should return for its output
       to be correctly used by Wapiti"""

    def __init__(self, content, category, page, level = 1, type = "text"):
        self.type = type
        self.content = content
        self.category = category
        self.level = level
        self.page = page


class Analysis:
    """This class represents an analysis, it must be extended for any class
    which implements a new type of passive analysis"""

    name = "analysis"

    do_get = True
    do_post = True

    # List of modules (strings) that must be launched before the current module
    # Must be defined in the code of the module
    require = []

    BASE_DIR = os.path.dirname(sys.modules["wapitiCore"].__file__)
    CONFIG_DIR = os.path.join(BASE_DIR, "config", "attacks")
    PAYLOADS_FILE = None

    # Color codes
    STD = "\033[0;0m"
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    ORANGE = "\033[0;33m"
    YELLOW = "\033[1;33m"
    BLUE = "\033[1;34m"
    MAGENTA = "\033[0;35m"
    CYAN = "\033[0;36m"
    GB = "\033[0;30m\033[47m"

    allowed = [
        'php', 'html', 'htm', 'xml', 'xhtml', 'xht', 'xhtm',
        'asp', 'aspx', 'php3', 'php4', 'php5', 'txt', 'shtm',
        'shtml', 'phtm', 'phtml', 'jhtml', 'pl', 'jsp', 'cfm',
        'cfml', 'py'
    ]

    # The priority of the module, from 0 (first) to 10 (last). Default is 5
    PRIORITY = 5

    def __init__(self, persister, logger):
        super().__init__()
        self._session_id = "".join([random.choice("0123456789abcdefghjijklmnopqrstuvwxyz") for __ in range(0, 6)])
        self.persister = persister
        self.add_vuln = persister.add_vulnerability
        self.add_anom = persister.add_anomaly
        self.add_addition = persister.add_additional

        # List of attack urls already launched in the current module
        self.pages = []

        self.verbose = 0
        self.color = 0

        # List of modules (objects) that must be launched before the current module
        # Must be left empty in the code
        self.deps = []

        self._logger = logger
        self.log = self._logger.log
        self.log_blue = self._logger.log_blue
        self.log_cyan = self._logger.log_cyan
        self.log_green = self._logger.log_green
        self.log_magenta = self._logger.log_magenta
        self.log_orange = self._logger.log_orange
        self.log_red = self._logger.log_red
        self.log_white = self._logger.log_white
        self.log_yellow = self._logger.log_yellow

    def set_verbose(self, verbose):
        self.verbose = verbose

    def set_color(self):
        self.color = 1

    def load_require(self, dependencies: list = None):
        self.deps = dependencies

    @property
    def internal_endpoint(self):
        return self.options.get("internal_endpoint", "https://wapiti3.ovh/")

    @property
    def external_endpoint(self):
        return self.options.get("external_endpoint", "http://wapiti3.ovh")

    def analyse(self, page):
        raise NotImplementedError("Override me bro")

    def does_timeout(self, request):
        try:
            self.crawler.send(request)
        except ReadTimeout:
            return True
        except RequestException:
            pass
        return False

# if __name__ == "__main__":
#
#     mutator = Mutator(payloads=[("INJECT", Flags()), ("ATTACK", Flags())], qs_inject=True, max_queries_per_pattern=16)
#     res1 = Request(
#         "http://httpbin.org/post?var1=a&var2=b",
#         post_params=[['post1', 'c'], ['post2', 'd']]
#     )
#
#     res2 = Request(
#         "http://httpbin.org/post?var1=a&var2=z",
#         post_params=[['post1', 'c'], ['post2', 'd']]
#     )
#
#     res3 = Request(
#         "http://httpbin.org/get?login=admin&password=letmein",
#     )
#
#     assert res1.hash_params == res2.hash_params
#
#     for evil_request, param_name, payload, flags in mutator.mutate(res1):
#         print(evil_request)
#         print(flags)
#
#     print('')
#     print("#"*50)
#     print('')
#
#     for evil_request, param_name, payload, flags in mutator.mutate(res2):
#         print(evil_request)
#
#     print('')
#     print("#"*50)
#     print('')
#
#     def iterator():
#         yield "abc", Flags()
#         yield "def", Flags()
#
#     mutator = Mutator(payloads=iterator, qs_inject=True, max_queries_per_pattern=16)
#     for evil_request, param_name, payload, flags in mutator.mutate(res3):
#         print(evil_request)
#
#     print('')
#     print("#"*50)
#     print('')
#
#     def random_string():
#         """Create a random unique ID that will be used to test injection."""
#         # doesn't uppercase letters as BeautifulSoup make some data lowercase
#         return "w" + "".join([random.choice("0123456789abcdefghjijklmnopqrstuvwxyz") for __ in range(0, 9)]), Flags()
#
#     mutator = Mutator(payloads=random_string, qs_inject=True, max_queries_per_pattern=16)
#     for evil_request, param_name, payload, flags in mutator.mutate(res3):
#         print(evil_request)
#         print("Payload is", payload)
#
#     mutator = Mutator(
#         methods="G",
#         payloads=[("INJECT", Flags()), ("ATTACK", Flags())],
#         qs_inject=True,
#         parameters=["var1"]
#     )
#
#     assert len(list(mutator.mutate(res1))) == 2
#
#     f1 = Flags()
#     f2 = Flags()
#     assert f1 == f2
#     assert f1.with_section("abcd") == f2.with_section("abcd")
#     assert f1 != f1.with_section("abcd")
