"""digest data for having a history

Having e.g. metricbeat data from every 15 seconds or every minute results in
a lot of detailed data.  Looking back in history it is not so important for
having all of the data, but rather having averages, minima, maxima, etc.

This module shall provide tools for easy aggregating data (maybe even
automatic) and put them into buckets and write them to some history index.

"""

from .util import get_config_value, string

import logging
log = logging.getLogger('elastico.digest')

from .data_processor import DataProcessor

class Digester(DataProcessor):
    config_item = 'digest'

    def __init__(self, es_client, config={}):
        self.es = es_client
        self.config = config

    def get_aggregate_items(self, agg_type, field_specs):
        aggs = []

        # type 1: dictionary
        if isinstance(field_specs, dict):

            # item type 1b: implicit name -> field mapping
            for name, field in field_specs.items():
                aggs.append({name: {agg_type: {"field": field}}})
        else:
            # type 2: list
            for field_spec in field_specs:
                # item type 1: dict
                if isinstance(field_spec, dict):
                    # item type 1a: explicit definition
                    if 'field' in field_spec:
                        name  = field_spec['name']
                        field = field_spec['field']
                        _field_spec = {"field": field}
                        for k,v in field_spec:
                            if k in ('name', 'field'): continue
                            _field_spec[k] = v
                        aggs.append((name, {agg_type: _field_spec}))
                    else:
                        # item type 1b: implicit name -> field mapping
                        for k,v in field_spec.items():
                            aggs.append((k, {agg_type: {"field": v}}))
                # item type 2: string:   string -> string mapping
                else:
                    aggs.append({field_spec: {agg_type: {"field": field_spec}}})
        return aggs

    def make_query(self, rule, digest):
        import pprint
        # dictionary of final aggregations
        aggs = {}
        for agg_type, field_specs in digest.get('aggregates', {}).items():
            agg_items = self.get_aggregate_items(agg_type, field_specs)
            for agg_item in agg_items:
                aggs.update(agg_item)

        log.debug("aggs: %s", aggs)

        # setup the buckets
        for bucket_type, field_specs in digest.get('buckets', {}).items():
            agg_items = self.get_aggregate_items(bucket_type, field_specs)
            log.debug("bucket - agg_items: %s", agg_items)
            for spec in agg_items:
                value = spec.values()[0]
                value['aggs'] = aggs
                aggs = spec

        log.debug("aggs: %s", aggs)

        # setup query
        query = digest.get('query')

        if isinstance(query, list):
            query = {'bool': {'must': query}}
        elif isinstance(query, string): # string
            query = {'query_string': {'query': query}}

        # setup final wrapping timestamp aggregation
        timestamp_field = digest.get('timestamp_field', '@timestamp')

        agg_type = "date_histogram"
        timestamp_spec = self.get_aggregate_items(agg_type, [timestamp_field])
        timestamp_agg = timestamp_spec[0]

        # set interval (unless set)
        timestamp_interval = digest.get('timestamp_interval', '1h')
        key = timestamp_agg.keys()[0]

        log.debug("key=%s, agg_type=%s, timestamp_agg=%s", key, agg_type, timestamp_agg)
        if 'interval' not in timestamp_agg[key][agg_type]:
            timestamp_agg[key][agg_type]['interval'] = timestamp_interval

        timestamp_agg.values()[0]['aggs'] = aggs

        result = {
            'query': query,
            'aggs': timestamp_agg,
            'size': 0
        }

        log.debug("result: %s", result)
        return result

    def process(rule, action=None):
        digests = get_config_value(rule, 'digests', [])

#        if digest_config_path is not None:


    @classmethod
    def run_query(cls, config):
        config = ConfigFactory(config['config']).create(config)
        digester = Digester(config)

        digester.query()



#        for digest in
#        self.make_query()


#    def process_rules(self):





