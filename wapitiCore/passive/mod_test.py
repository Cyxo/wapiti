from wapitiCore.passive.passive import Analysis

class mod_test(Analysis):
    """This class implements a test of a passive module"""

    name = "test"

    def __init__(self, page, persister, logger):
        Analysis.__init__(self, page, persister, logger)

    def analyse(self):
        yield "Testing passive module"
