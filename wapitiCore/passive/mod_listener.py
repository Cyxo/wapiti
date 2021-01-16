from wapitiCore.passive.passive import Analysis, Result
from wapitiCore.language.vulnerability import _, Additional
from webdrivermanager import ChromeDriverManager
from selenium import webdriver
from wapitiCore.main import wapiti
import os
import re

class mod_osint(Analysis):
    """This class implements a module to retrive and execute event listeners"""

    name = "listener"

    def __init__(self, persister, logger):
        Analysis.__init__(self, persister, logger)
        HOME_DIR = os.getenv("HOME") or os.getenv("USERPROFILE")
        WEBDRIVER = os.path.join(HOME_DIR, ".wapiti", "generated_report")
        if not os.path.isdir(WEBDRIVER):
            os.makedirs(WEBDRIVER)
        chr = ChromeDriverManager(download_root=WEBDRIVER, link_path=WEBDRIVER)
        self.driver_path = chr.download_and_install(show_progress_bar=False)[1]

    def analyse(self, page):
        options = webdriver.chrome.options.Options()
        options.add_argument("--headless")
        capabilities = webdriver.common.desired_capabilities.DesiredCapabilities.CHROME
        capabilities["goog:loggingPrefs"] = {"performance": "ALL"}
        driver = webdriver.Chrome(executable_path=self.driver_path, \
                                  options=options, \
                                  desired_capabilities=capabilities)
        # Récuperer les logs d'initialisation pour les effacer :
        driver.get_log("performance")
        driver.get(page.base_url)
        node_ID = driver.execute_cdp_cmd("DOM.getDocument", {})["root"]["nodeId"]
        object_ID = driver.execute_cdp_cmd("DOM.resolveNode", {"nodeId": node_ID, "objectGroup":"provided"})['object']['objectId']
        listeners = driver.execute_cdp_cmd("DOMDebugger.getEventListeners", {"objectId": object_ID, "depth":-1})['listeners']