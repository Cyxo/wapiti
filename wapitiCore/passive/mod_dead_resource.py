from wapitiCore.passive.passive import Analysis, Result
from wapitiCore.language.vulnerability import _, Additional
from urllib.parse import urlparse
import requests
import socket
import dns, dns.resolver
import sys

class mod_dead_resource(Analysis) :
    """This class detect dead resources in a web page"""

    name = "dead_resource"

    def __init__(self, persister, logger):
        Analysis.__init__(self, persister, logger)
    
    def test_connectivity(self, host='8.8.8.8', port=53, timeout=3) :
        try :
            socket.setdefaulttimeout(timeout)
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
            return True
        except socket.error :
            return False
    
    def test_dns_resolution(self, url):
        """This function return 0 for DNS error such as no valid record or DNS failure, 1 if it determines the DNS query name does not exist, 2 for valid IP resolution"""
        name = urlparse(url).netloc
        try :
            dns.resolver.resolve(name, 'A')
        except dns.resolver.NXDOMAIN :
            return 1
# In case there is no IPv4 DNS answer, try IPv6 
        except dns.resolver.NoAnswer :
            try :
                dns.resolver.resolve(name, 'AAAA')
            except :
                return 0
        except :
            return 0
        return 2

    def analyse(self, page) :
        if page.base_url not in self.pages :
            self.pages.append(page.base_url)

# Create the list of the links and fetched resources in the page
            links=[]
            links.extend(page.links)
            links.extend(list(page.extra_urls))

# Introduce error variables to avoid displaying the same warning twice
            connectivity_failure_flag = None
            resolver_failure_flag = None
            network_unknown_failure_flag = None
            
            for link in links :

# Only test URLs external to the tested domain, for which the resource could be replaced by an attacker
                if page.is_external_to_domain(link):
                    try : 
                        r = requests.get(link)

# In case of abnormal HTTP response code, add this to the report
                        if (r.status_code>=400):
                            yield Result(Additional.INFO_DEAD_RESOURCE_HTTP_RESPONSE.format(link,r.status_code), Additional.MSG_DEAD_RESOURCE, page.base_url, type="additional")

# Handle requests exceptions 
# In case of ConnnectionError we need to verify if the domain name exists. If not, the link could be abused and we need to add this to report
# Other cases of ConnectionError and ConnectTimeout are usually not relevant for the report but we would like to diagnose the cause and alert the user
                    except (requests.ConnectionError, requests.exceptions.ConnectTimeout) :

# Test only once for Internet connectivity
                        if connectivity_failure_flag is None :
                            if self.test_connectivity() == False :        
                                print("Warning : Broken link analysis - Some results have been skipped in report due to Internet connectivity failure")
                                connectivity_failure_flag = True
                            else :
                                connectivity_failure_flag = False

# If Internet connectivity is working, test for correct DNS resolution
                        if not connectivity_failure_flag :
                            resolution = self.test_dns_resolution(link)

# If DNS resolution is impossible and warning has never been displayed before, alert the user about DNS issue
                            if (resolution == 0) and (resolver_failure_flag is None):
                                print("Warning : Broken link analysis - Some results have been skipped in report due to DNS resolution failure")
                                resolver_failure_flag = True

# If domain name does not exist, it is a dead resource, add this to report
                            elif resolution == 1 :
                                yield Result(Additional.INFO_DEAD_RESOURCE_DOMAIN_NAME.format(link), Additional.MSG_DEAD_RESOURCE, page.base_url, type="additional")

# If both Internet connectivity and DNS resolution are working, alert the user about network unknown issue 
                        if (not connectivity_failure_flag) and (resolution == 2) and (network_unknown_failure_flag is None) :
                                print("Warning : Broken link analysis - Some results have been skipped in report due to connection failure")
                                network_unknown_failure_flag = True

# Handle other less common requests Exceptions : HTTPError, SSLError, TooManyRedirects, ContentDecodingError, ReadTimeout -> Those may be of interest and will figure in report
# Exceptions like URLRequired, MissingSchema, InvalidSchema, InvalidURL, InvalidHeader should not happen due to preformatting pattern
                    except :
                        yield Result(Additional.INFO_DEAD_RESOURCE_REQUESTS_EXCEPT.format(link, sys.exc_info()[0]), Additional.MSG_DEAD_RESOURCE, page.base_url, type="additional")
