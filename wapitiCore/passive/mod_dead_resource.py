from wapitiCore.passive.passive import Analysis, Result
from wapitiCore.language.vulnerability import _, Additional
import requests
import re
import sys

class mod_dead_resource(Analysis):
    """This class detect dead resources in a web page"""

    name = "dead_resource"

    def __init__(self, persister, logger):
        Analysis.__init__(self, persister, logger)

    def analyse(self, page):
        if page.base_url not in self.pages:
            self.pages.append(page.base_url)

            links=[]
#
#           for link in page.soup.find_all("a", attrs={'href': re.compile("^http://|^https://")}) : #src=True?
#               links.append(link['href'])
#
#	
#           for link in page.soup.find_all("a", attrs={'href': re.compile("^//")}) : #src=True?
#               links.append(page

            links.extend(page.links)
            links.extend(list(page.extra_urls))


            for link in links :
                try : 
                    r = requests.get(link)
                    if (r.status_code<200 or r.status_code >=300):
                        #print("Le lien {0} renvoie une erreur {1}".format(link, r.status_code))"
                        yield Result(Additional.INFO_DEAD_RESOURCE_HTTP_RESPONSE.format(link,r.status_code), Additional.MSG_DEAD_RESOURCE, page.base_url, type="additional")
                except :
                    yield Result(Additional.INFO_DEAD_RESOURCE_REQUESTS_EXCEPT.format(link, sys.exc_info()[0]), Additional.MSG_DEAD_RESOURCE, page.base_url, type="additional")
