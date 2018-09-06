from .util import to_dt, dt_isoformat
from .util import string
from datetime import datetime, timedelta

def search(es, query=None, index=None):
    return es.search(index=index or '*', body=build_query_body(query))

def build_query_body(query):
    return {'query': {'query_string': {'query': query}}}

def build_search_body(config, name):
    '''build a search body from given key `name` in config.

    '''
    body = None
    # list of filters
    if isinstance(config[name], list):
        filters = config[name]

    # lucene query string
    if isinstance(config[name], string):
        filters = [{'query': {'query_string': {'query': config[name]}}}]

    # complete search body (including timerange, if any)
    if isinstance(config[name], dict):
        return config[name]

    timestamp_field = config.get('timestamp_field', '@timestamp')
    timeframe = config.get('timeframe_minutes', 60)

    if 'endtime' in config:
        endtime = to_dt(config['endtime'])
    else:
        endtime = datetime.utcnow() #.isoformat('T', 'seconds')+"Z"

    if 'starttime' in config:
        starttime = to_dt(config['starttime'])
    else:
        starttime = endtime - timedelta(minutes=timeframe)

    starttime = dt_isoformat(starttime)
    endtime   = dt_isoformat(endtime)

    return {
        'query': {'bool': {'must': [
                {'range': {timestamp_field: {'gte': starttime, 'lte': endtime}}}
            ] + filters,
        'sort': {timestamp_field: 'desc'}
    }}}
