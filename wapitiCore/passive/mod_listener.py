from wapitiCore.passive.passive import Analysis, Result
from wapitiCore.language.vulnerability import _, Additional
from wapitiCore.net.crawler import Page, MIME_TEXT_TYPES
from requests.models import Response
from webdrivermanager import ChromeDriverManager
from selenium import webdriver
import os
import time
import json

class mod_listener(Analysis):
    """This class implements a module to retrive and execute event listeners"""

    name = "listener"

    def __init__(self, persister, logger):
        Analysis.__init__(self, persister, logger)
        HOME_DIR = os.getenv("HOME") or os.getenv("USERPROFILE")
        WEBDRIVER = os.path.join(HOME_DIR, ".wapiti", "webdriver")
        if not os.path.isdir(WEBDRIVER):
            os.makedirs(WEBDRIVER)
        chr = ChromeDriverManager(download_root=WEBDRIVER, link_path=WEBDRIVER)
        self.driver_path = chr.download_and_install(show_progress_bar=False)[1]
        
        options = webdriver.chrome.options.Options()
        options.add_argument("--headless")
        capabilities = webdriver.common.desired_capabilities.DesiredCapabilities.CHROME
        capabilities["goog:loggingPrefs"] = {"performance": "ALL"}
        self.driver = webdriver.Chrome(executable_path=self.driver_path, \
                                  options=options, \
                                  desired_capabilities=capabilities)
        # Récuperer les logs d'initialisation pour les effacer :
        self.driver.get_log("performance")

        self.pages = []
        self.urls = []

    def analyse(self, page):
        if not page.content in self.pages:
            self.pages.append(page.content)

            self.driver.get(page.url)

            log = self.driver.get_log("performance")
            messages = [l["message"] for l in log]

            print("Analysing JS on page", page.url)

            for m in messages:
                if '"Network.responseReceived"' in m:
                    m = json.loads(m)
                    r = m["message"]["params"]["response"]
                    url = r["url"]
                    mime = r["mimeType"]

                    if not url in self.urls and not 'image' in mime:# and mime.startswith(MIME_TEXT_TYPES):
                        self.urls.append(url)
                        yield Result(None, None, url, type="url")

            initial_page = self.driver.page_source
            initial_url = self.driver.current_url

            node_ID = self.driver.execute_cdp_cmd("DOM.getDocument", {})["root"]["nodeId"]
            object_ID = self.driver.execute_cdp_cmd("DOM.resolveNode", {"nodeId": node_ID, "objectGroup":"provided"})['object']['objectId']
            listeners = self.driver.execute_cdp_cmd("DOMDebugger.getEventListeners", {"objectId": object_ID, "depth":-1})['listeners']
            
            for listener in listeners:
                evt_type = listener["type"]
                try:
                    evt_node = self.driver.execute_cdp_cmd("DOM.resolveNode", {"backendNodeId": listener["backendNodeId"]})['object']['objectId']
                except:
                    # C'est crade, faudrait recharger initial_url, récup les nouveaux listeners, et itérer sur des ids de listeners genre (scriptId, line, column)
                    continue

                js_func = "function(){ this.dispatchEvent(new Event('" + evt_type + "')); }" 
                aaa = self.driver.execute_cdp_cmd("Runtime.callFunctionOn", {"functionDeclaration": js_func, "objectId": evt_node, "userGesture": True})
                
                if self.driver.page_source != initial_page or self.driver.current_url != initial_url:
                    res = Response()
                    res.status_code = 200
                    res._content = self.driver.page_source.encode()
                    res.url = self.driver.current_url

                    if not self.driver.page_source in self.pages:
                        self.pages.append(self.driver.page_source)
                        # Pour que ça marche, faudrait que res.raw soit définit -> ça doit être un file-like genre un BytesIO. A voir si il tient aux headers ou pas...
                        # yield Result(Page(res), None, page.url, type="url")

                
                log = self.driver.get_log("performance")
                messages = [l["message"] for l in log]
                for m in messages:
                    if '"Network.responseReceived"' in m:
                        m = json.loads(m)
                        r = m["message"]["params"]["response"]
                        url = r["url"]
                        mime = r["mimeType"]

                        if not url in self.urls and not 'image' in mime:# and mime.startswith(MIME_TEXT_TYPES):
                            self.urls.append(url)
                            yield Result(None, None, url, type="url")
