from wapitiCore.passive.passive import Analysis, Result

class mod_test(Analysis):
    """This class implements a test of a passive module"""

    name = "test"

    def __init__(self, persister, logger):
        Analysis.__init__(self, persister, logger)

    def analyse(self, page):
        if page.base_url not in self.pages:
            self.pages.append(page.base_url)
            yield Result("Testing passive module on page {}".format(page.url), "Test", page.base_url)