"""sweep data

"""

from .cli import command, opt, arg
from ..connection import elasticsearch
from ..util import to_dt, PY3, dt_isoformat, start_of_day
import pyaml
import logging
import sys
import time
from elasticsearch.helpers import scan

from datetime import datetime, timedelta

log = logging.getLogger('elastico.cli.sweep')

if PY3:
    unicode = str
    string = str
else:
    string = basestring
    Exception = StandardError


#def make_query(rule, name='match', default_timestamp_field='@timestamp', older_than=):

def make_query(query, older_than, at, timestamp_field='@timestamp', before=None):
    # body = None
    # query = rule.getval(name)

    # list of filters
    if isinstance(query, list):
        filters = query

    # lucene query string
    if isinstance(query, string):
        filters = [{'query_string': {'query': query.strip()}}]

    # complete search body (including timerange, if any)
    if isinstance(query, dict):
        return query

    # timestamp_field = rule.getval('timestamp_field', )
    # timeframe = rule.getval('timeframe', {'minutes': 15})

    endtime = to_dt(at) - timedelta(**older_than)

#    if before is not None:
#        dt_before = start_of_day(before)
#        if endtime > dt_before:
#            endtime = dt_before

#    starttime = dt_isoformat(starttime, 'T', 'seconds')#+"Z"
    endtime   = dt_isoformat(endtime, 'T', 'seconds')#+"Z"

    return {
        'query': {'bool': {'must': [
                {'range': {timestamp_field: {'lte': endtime}}}
            ] + filters
            }},
        'sort': [{timestamp_field: 'desc'}],
        'size': 1
    }


@command('sweep', opt('--confirm', '-y'), opt("--details"), opt("--max-process"), arg("--filter", default=None))
def sweep(config):
    """
    Sweep rule configuration example:

        # mandatory: name of the rule
        name: Unneeded process data

        # optional: enabled or not, default is false
        enabled: false

        # optional: specify a date which will be a hard limit for the selected
        # data.  will override older_than.
        before: 2018-09-09

        # optional: older_than specify a relative date.  keys can be whatever
        # can be passed to to python's timedelta class.
        older_than:
            days: 14

        # mandatory: a query
        match: >
            metricset.name: process
            AND system.process.cmdline: /syslog/

    """
    default_older_than = config.get('sweep.older_than', {'days': 14})
    default_timestamp_field = config.get('sweep.default_timestamp_field', '@timestamp')
    now = to_dt(config.get('at', datetime.utcnow()))

    # do a validation
    for rule in config.get('sweep.rules'):
        assert rule.get("name"), "name required in rule"
        assert rule.get("index"), "index is required in %(name)s" % rule
        assert rule.get("match"), "match is required in %(name)s" % rule

    es = elasticsearch(config)

    for rule in config.get('sweep.rules'):

        older_than      = rule.get('older_than', default_older_than)
        timestamp_field = rule.get('timestamp_field', default_timestamp_field)
        index_pattern   = rule.get("index")

        keys = es.indices.get(index_pattern).keys()

        for idx in sorted(keys):
            query = rule.get("match")
            assert query

            if config.get('sweep.filter'):
                filter = config.get('sweep.filter', '')
                if filter not in idx:
                    log.info("skip=%s", idx)
                    continue

            log.debug("action=sweep index=%s query=%r", idx, query)
            query_body = make_query(query, older_than, at=now, timestamp_field=timestamp_field, before=rule.get('before'))

            enabled = rule.get('enabled', False)

            if config.get('sweep.confirm'):
                count  = es.count(index=idx)['count']

                start = time.time()

                if enabled:

                    #log.info("DELETE")
                    del query_body['size']
                    del query_body['sort']
                    results = es.delete_by_query(index=idx, body=query_body, refresh=True, request_timeout=3600)
                    merge_results = es.indices.forcemerge(index=idx, only_expunge_deletes=True, request_timeout=3600)
                    #results = {"DELETE": "DELETE"}

                end = time.time()

                if not config.get("sweep.details"):
                    delete = results['deleted']
                    if count > 0:
                        rate = delete*100.0/count
                    else:
                        rate = 0.0

                    print("rule={!r} index={} enabled={} deleted={} total={} rate={:.2f}% took={:.3f}s".format(rule['name'], idx, enabled, delete, count, rate, end-start))
                else:
                    pyaml.p({'delete_by_query': results, 'forcemerge': merge_results})

                # if enabled and results['deleted'] > 0:
                #     sys.exit(1)
            else:
                results = es.search(index=idx, body=query_body)

                if 1:
#                if not config.get("sweep.details"):
#                    list_spec = config.get('sweep.list')
                    count  = es.count(index=idx)['count']
                    delete = results['hits']['total']
                    if count > 0:
                        rate = delete*100.0/count
                    else:
                        rate = 0.0

                    out_string = "rule={!r} index={} enabled={} delete={} total={} rate={:.2f}%".format(rule['name'], idx, enabled, delete, count, rate)
                    print(out_string)

                if config.get("sweep.details"):
                    list_spec = rule.get('list_format')

                    if list_spec:
                        string = list_spec

                        for hit in scan(es, query={'query': query_body['query']}, index=idx):
                            try:
                                print("  "+string.format(**hit['_source']))
                            except Exception as e:
                                hit['_error'] = "error formatting record: %r" % e
                                hit['_formatstring'] = string
                                pyaml.p(hit)
                                raise

                    else:
                        print("  details_error='no list_format defined'")

            # if config.get('sweep.details'):
            #     results = es.search(index=idx, body=query_body)
            #     if not config.get("sweep.details"):
            #     pyaml.p()

