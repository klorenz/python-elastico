class DataProcessor(object):
    expand_config_items = []
    config_item = None

    def __init__(self, config, es_client=None):
        self.config    = config
        self.es_client = es_client
        self.status = {}

    def process(self, rule, action=None):
        pass

    def process_rules(self, action=None):
        for rule in self.config.get("%s.rules" % self.config_item, []):
            self.process(rule, action=action)



