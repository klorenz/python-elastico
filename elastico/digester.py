"""digest data for having a history

Having e.g. metricbeat data from every 15 seconds or every minute results in
a lot of detailed data.  Looking back in history it is not so important for
having all of the data, but rather having averages, minima, maxima, etc.

This module shall provide tools for easy aggregating data (maybe even
automatic) and put them into buckets and write them to some history index.

"""

from .util import string, to_dt, start_of_day, end_of_day, first_value

import logging
log = logging.getLogger('elastico.digest')

from .data_processor import DataProcessor
from datetime import datetime, timedelta

class Digester(DataProcessor):
    config_item = 'digest'


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


    def make_range_query(self, min_date=None, max_date=None):
        range = None
        if min_date or max_date:
            range = {"range": {timestamp_field: {}}}

        if min_date:
            range['range'][timestamp_field]['gte'] = dt_isoformat(min_date)

        if max_date:
            range['range'][timestamp_filed]['lte'] = dt_isoformat(max_date)

        return range


    def make_query(self, rule, digest, min_date=None, max_date=None):
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
                value = first_value(spec)
                value['aggs'] = aggs
                aggs = spec

        log.debug("aggs: %s", aggs)

        # setup query
        query = digest.get('query')

        # setup condition
        if isinstance(query, list):
            query = {'bool': {'must': query}}
        elif isinstance(query, string): # string
            query = {'bool': {'must': [{'query_string': {'query': query}}]}}

        range = self.make_range_query(min_date, max_date)
        if range:
            query['bool']['must'].append(range)

        # setup final wrapping timestamp aggregation
        timestamp_field = rule.get('timestamp_field', '@timestamp')
        timestamp_field = digest.get('timestamp_field', timestamp_field)

        agg_type = "date_histogram"
        timestamp_spec = self.get_aggregate_items(agg_type, [timestamp_field])
        timestamp_agg = timestamp_spec[0]

        # set interval (unless set)
        timestamp_interval = digest.get('timestamp_interval', '1h')
        key = list(timestamp_agg.keys())[0]

        log.debug("key=%s, agg_type=%s, timestamp_agg=%s", key, agg_type, timestamp_agg)
        if 'interval' not in timestamp_agg[key][agg_type]:
            timestamp_agg[key][agg_type]['interval'] = timestamp_interval

        first_value(timestamp_agg)['aggs'] = aggs

        result = {
            'query': query,
            'aggs': timestamp_agg,
            'size': 0
        }

        log.debug("result: %s", result)
        return result


    def get_aggregated_doc(self, bucket, doc=None):
        if doc is None:
            doc = {}

        for key, value in bucket.items():
            if not isinstance(value, dict): continue

            if 'value' in value:
                doc[key] = value['value']
            elif 'buckets' in value:
                for b in value['buckets']:
                    if 'key_as_string' in b:
                        doc[key] = b['key_as_string']
                    else:
                        doc[key] = b['key']

                    if '_id' not in doc:
                        doc['_id'] = b['key']

                    self.get_aggregated_doc(b, doc)
            else:
                doc[key] = value

        return doc


    def get_run_at(self):
        run_at = self.config.get('arguments.run_at')

        if not run_at:
            run_at = datetime.datetime.now()
        else:
            run_at = to_dt(run_at)

        return run_at

        return datetime.combine(run_at.date(), datetime.min.time())


    def get_relevant_indexes(self, rule, min_date, max_date):
        # get index exclude pattern
        index_exclude = rule.get('index.exclude', [])
        if isinstance(index_exclude, string):
            index_exclude = [index_exclude]

        index_exclude = [ re.compile(n.replace('*', '.*')) for n in index_exclude ]

        # predicate to check if indexname shall be excluded
        def is_excluded(index_name):
            for x in index_exclude:
                if x.match(index_name):
                    return True
            return False

        # setup final wrapping timestamp aggregation
        timestamp_field = rule.get('timestamp_field', '@timestamp')

        # get index pattern
        index_pattern = self.get_required(rule, 'index.source')

        # iterate over indexes and create a list of indexes to process
        index_names = {}
        for index_name in self.es.indices.get(index_pattern):
            if is_excluded(index_name): continue

            first_entry = self.es.search(index=index_pattern, query={
                "query": { "match_all": {} },
                "sort": [ { timestamp_field: { "order": "asc" } } ],
                "size": 1,
            })

            if not first_entry['total']: # nothing to do
                # index can be dropped
                continue

            first_entry = first_entry['hits']['hits'][0]['_source']
            startdate = first_entry[timestamp_field]

            if max_date:
                if startdate > max_date:
                    # this index must be skipped
                    continue

            latest_entry = self.es.search(index=index_name, query={
                 "query": { "match_all": {} },
                 "sort": [ { timestamp_field: { "order": "desc" } } ],
                 "size": 1,
            })

            last_entry = last_entry['hits']['hits'][0]['_source']
            enddate = to_dt(last_entry[timestamp_field])

            if enddate < min_date:
                # this index must be skipped
                continue

            index_names[index_name] = (startdate, enddate)

        return index_names



    def process(rule, action=None):
        # get minimum age of documents, default 14 days
        min_age = timedelta(*rule.get('age.min', {'days': 7}))
        max_date = end_of_day(self.get_run_day() - min_age)

        # maximum age of documents
        max_age = rule.get('age.max')
        if max_age:
            max_age = timedelta(*max_age)
            min_date = start_of_day(self.get_run_day() - max_age)

        # field specifying timestamp
        timestamp_field = rule.get('timestamp_field', '@timestamp')

        index_names = self.get_relevant_indexes(rule, min_date, max_date)

        # iterate from starttime to endtime in steps of timeframe
        timeframe = timedelta(self.config.get('digest.timeframe', {'days': 1}))

        _starttime = starttime
        while _starttime < endtime:
            # setup _endtime of current timeframe
            _endtime = _starttime + timeframe

            if _endtime > endtime:
                _endtime = endtime

            # collection to store failed index requests of aggregated docs
            failed = []

            # create list of indexes having documents within current timeframe
            indexes=[]
            for idx,idx_range in index_names.items():
                if idx_range[1] < _starttime or idx_range[0] > _endtime:
                    continue
                indexes.append(idx)

            # collection to store digestion_queries, important for later
            # handling of successful digestions
            digestion_queries = []

            # digest all documents
            for digest in rule.get('digests', []):
                query = self.make_query(rule, digest, starttime, _endtime)
                result = self.es.search(index=",".join(indexes), query=query)

                for agg in result['aggregations'][timestamp_field]['buckets']:
                    doc = self.get_aggregated_doc(agg['aggregations'])
                    target_index = timestamp.strftime(to_dt(doc[timestamp_field]))
                    doc['_index'] = target_index
                    bulk_success, bulk_failed = self.bulk_append(doc)
                    failed += bulk_failed

                digestion_queries.append(query['query'])

                if digest.get('on_success'):
                    bulk_success, bulk_failed = self.bulk_flush()
                    failed += bulk_failed

                    self.on_success(failed, digest, indexes, query['query'])

            bulk_success, bulk_failed = self.bulk_flush()
            failed += bulk_failed

            success_query = { 'bool': { 'should': digestion_queries } }
            self.on_success(failed, rule, indexes, success_query)

            delete_empty_indices = self.config.get('delete_empty_indices')
            if rule.get('delete_empty_indices', delete_empty_indices):
                self.delete_empty_indices(indexes)

            _starttime = _endtime


    def delete_documents(self, indexes, query):
        result = self.es.delete_by_query(
            index=",".join(indexes),
            body={'query': query}
        )
        log.info("deleted %s documents out of %s matching", result['deleted'], result['total'])


    def on_success(self, failed, rule, indexes, query):
        if len(failed):
            log.warning("there were erros doing bulk indexing: %s", failed)
            return

        for action in rule.get('on_success', []):
            if action in ('delete_digested', 'delete'):
                self.delete_documents(indexes, query)
            #body={'query': {'bool': {
            #    'should': digestion_queries
            #}}}

            elif isinstance(action, dict):
                assert 'delete' in action, "you must specify 'delete' item"

                range = self.make_range_query(_starttime, _endtime)
                if action['delete'] in ('all', '_all', '*'):
                    self.delete_documents(indexes, range)

                elif isinstance(action['delete'], (list,dict)):
                    _delete = action['delete']
                    if isinstance(_delete, dict):
                        _delete = [_delete]

                    self.delete_documents(indexes,
                        {'bool': {'must': _delete + [range]}})

                else:
                    raise NotImplemented(
                        "You cannot specify a deletion with %s" %
                        action['delete'])


    def delete_empty_indices(self, indexes):
        for idx in indexes:
            result = self.es.search(index=idx, query={
                 "query": { "match_all": {} },
                 "size": 0,
            })
            if result['hits']['total'] > 0:
                continue

            log.info("delete empty index %s", idx)

            self.indices.delete(idx)


    @classmethod
    def run_query(cls, config):
        config = ConfigFactory(config['config']).create(config)
        digester = Digester(config)

        digester.query()



#        for digest in
#        self.make_query()


#    def process_rules(self):





