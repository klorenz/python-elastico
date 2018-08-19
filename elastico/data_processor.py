class DataProcessor(object):
    expand_config_items = []
    config_item = None

    def __init__(self, config, es_client=None):
        self.config    = config
        self.es = es_client
        self.status = {}

    def __getattr__(self, name):
        if name == 'bulk_docs':
            self.bulk_docs = []
            return self.bulk_docs
        return DataProcessor.__getattr__(self, name)

    def bulk_append(self, doc, docs=None):
        '''append a document to bulk buffer

        Flushing happens automatically, when there are `bulk.size` elements in
        bulk buffer.
        '''
        if docs is None:
            docs = self.bulk_docs

        assert '_id' in doc, "you have to set _id field"
        assert '_index' in doc, "you have to set _index field"

        docs.append(doc)
        size = self.config.get("bulk.size", 1000)
        if len(docs) > size:
            return self.bulk_flush(docs)

        return (0, [])

    def bulk_flush(self, docs=None):
        '''flush bulk buffer to elasticsearch
        '''
        if docs is None:
            docs = self.bulk_docs

        from elasticsearch.helpers import bulk
        result = bulk(self.es, docs)
        self.es.indices.refresh('_all')
        docs[:] = []
        return result

    def process(self, rule, action=None):
        pass

    def get_required(self, item, name, message=None):
        value = item.get(name)
        if message is None:
            message = "{name} required in {item}"
        assert value is not None, message.format(item=item['name'], name=name)
        return value

    def process_rules(self, action=None):
        rules = self.config.get("%s.rules" % self.config_item, [])
        for i,rule in enumerate(rules, start=1):
            rule.update_from_includes()
            rule_name = rule.get('name')
            assert rule_name, "you must provide a name for rule #%s from file %s" % (i, self.config.get_filename(rule))
            self.process(rule, action=action)

