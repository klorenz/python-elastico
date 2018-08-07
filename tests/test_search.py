from dateutil.parser import parse as parse_dt

from elastico.search import search

def test_search():
    from datetime import datetime

    actions = [
        {
        "_index": "foo",
        "_type": "doc",
        "_id": i,

        "any": "data-%s" % i,
        "@timestamp": parse_dt('2017-01-01')
        }
        for i in range(10)
    ]

    from elasticsearch.helpers import bulk
    from elastico.search import search
    from elastico.connection import elasticsearch
    es = elasticsearch()

    try:
        actions
        bulk(es, actions)
        es.indices.refresh('foo')
        r = search(es, 'any: "data-2"')
        assert r['hits']['total'] == 1
        assert r['hits']['hits'][0]['_source']['@timestamp'] == '2017-01-01T00:00:00'
    finally:
        es.indices.delete('foo')



