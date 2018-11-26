"""sweep data

"""

from .cli import command, opt, arg
from ..connection import elasticsearch
from ..util import to_dt, PY3, dt_isoformat
import pyaml
import logging
import sys

from datetime import datetime, timedelta

log = logging.getLogger('elastico.cli.sweep')

if PY3:
    unicode = str
    string = str
else:
    string = basestring
    Exception = StandardError


#def make_query(rule, name='match', default_timestamp_field='@timestamp', older_than=):

def make_query(query, older_than, at, timestamp_field='@timestamp'):
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


@command('sweep', opt('--confirm', '-y'), opt("--details"))
def sweep(config):
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

        older_than = rule.get('older_than', default_older_than)
        timestamp_field = rule.get('timestamp_field', default_timestamp_field)
        index_pattern = rule.get("index")

        assert index_pattern, "index is required "

        keys = es.indices.get(index_pattern).keys()

        for idx in sorted(keys):
            query = rule.get("match")
            assert query

            log.debug("action=sweep index=%s query=%r", idx, query)
            query_body = make_query(query, older_than, at=now, timestamp_field=timestamp_field)

            enabled = rule.get('enabled', True)

            if config.get('sweep.confirm'):
                if enabled:
                    #log.info("DELETE")
                    del query_body['size']
                    del query_body['sort']
                    results = es.delete_by_query(index=idx, body=query_body, refresh=True, request_timeout=3600)
                    merge_results = es.indices.forcemerge(index=idx, only_expunge_deletes=True)
                    #results = {"DELETE": "DELETE"}

                if not config.get("sweep.details"):
                    print("index={} enabled={} deleted={}".format(idx, enabled, results['deleted']))
                else:
                    pyaml.p({'delete_by_query': results, 'forcemerge': merge_results})

                # if enabled and results['deleted'] > 0:
                #     sys.exit(1)
            else:
                results = es.search(index=idx, body=query_body)
                if not config.get("sweep.details"):
                    list_spec = config.get('sweep.list')

                    out_string = "index={} enabled={} total={}".format(idx, enabled, results['hits']['total'])
                    # total = result['hits']['total']
                    # if list_spec:


                    print(out_string)

            if config.get('sweep.details'):
                pyaml.p()


