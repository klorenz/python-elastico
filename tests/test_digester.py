"""
Here a concrete query, which provides bucket data (to be used in Kibana's Dev
Tools)

```
POST metricbeat-6.3.2-2018.08.06/_search?size=0
{
    "query": {
      "term": { "metricset.name": "filesystem" }
    },
    "aggs" : {
        "period" : {
            "date_histogram" : {
                "field" : "@timestamp",
                "interval" : "1h"
            },
            "aggs": {
              "host.name" : {
                "terms" : { "field" : "host.name" },
                "aggs" : {
                  "system.filesystem.mount_point" : {
                    "terms": { "field" : "system.filesystem.mount_point" },
                    "aggs" : {
                      "available": {
                        "stats": { "field": "system.filesystem.available" }
                      },
                      "free": {
                        "stats": { "field": "system.filesystem.free" }
                      },
                      "files": {
                        "stats": { "field": "system.filesystem.files" }
                      },
                      "total": {
                        "stats": { "field": "system.filesystem.total" }
                      },
                      "used_bytes": {
                        "stats": { "field": "system.filesystem.used.bytes" }
                      },
                      "used_pct": {
                        "stats": { "field": "system.filesystem.used.pct" }
                      },
                      "tags": {
                        "terms": { "field": "tags" }
                      }
                    }
                }
              }
            }
          }
        }
    }
}
```
"""
import io
import yaml
from textwrap import dedent
from elastico.util import PY3
from elastico.digest import Digester
from elastico.config_factory import ConfigFactory

from pprint import pprint

if PY3:
    unicode = str


def test_make_query():
    config = yaml.load(io.StringIO(dedent(unicode("""
      digest:
        age:
            min:
                days: 14
            max:
                days: 30

        timeframe:
          days: 1

        rules:
        - name: metricbeat

          index:
            source: metricbeat-*
            target: metricbeat-history-%Y-%m
            exclude: metricbeat-history-*

          on_success:
            - delete

          delete_empty_indices: true
            #- indices.delete

          digests:
          - name: metricset-filesystem
            query:
                term:
                    metricset.name: filesystem
            fields:
                metricset.module: system
                metricset.name: filesystem
            buckets:
                terms:
                  - host.name
                  - system.filesystem.mount_point
            aggregates:
                terms:
                  - tags
                stats:
                  - system.filesystem.available
                  - system.filesystem.free
                  - system.filesystem.files
                  - system.filesystem.total
                  - system.filesystem.available
                  - system.filesystem.used.pct
                  - system.filesystem.used.bytes
    """))))

    config = ConfigFactory(config).create()

    digester = Digester(config)

    rule = config['digest']['rules'][0]
    digest = rule['digests'][0]
    query = digester.make_query(rule, digest)

    expected = {
        'size': 0,
        'query': {
          'term': { "metricset.name": "filesystem" }
        },
        'aggs' : {
            "@timestamp" : {
                "date_histogram" : {
                    "field" : "@timestamp",
                    "interval" : "1h"
                },
                "aggs": {
                    "system.filesystem.mount_point" : {
                        "terms" : { "field" : "system.filesystem.mount_point" },
                        "aggs" : {
                            "host.name" : {
                                "terms": { "field" : "host.name" },
                                "aggs" : {
                                    "system.filesystem.available": {
                                        "stats": { "field": "system.filesystem.available" }
                                    },
                                    "system.filesystem.free": {
                                        "stats": { "field": "system.filesystem.free" }
                                    },
                                    "system.filesystem.files": {
                                        "stats": { "field": "system.filesystem.files" }
                                    },
                                    "system.filesystem.total": {
                                        "stats": { "field": "system.filesystem.total" }
                                    },
                                    "system.filesystem.used.bytes": {
                                        "stats": { "field": "system.filesystem.used.bytes" }
                                    },
                                    "system.filesystem.used.pct": {
                                        "stats": { "field": "system.filesystem.used.pct" }
                                    },
                                    "tags": {
                                        "terms": { "field": "tags" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    assert query == expected

def test_get_aggregated_doc():
    search_result = {
        "took": 2340,
        "timed_out": False,
        "_shards": {
          "total": 1,
          "successful": 1,
          "skipped": 0,
          "failed": 0
        },
        "hits": {
          "total": 122451,
          "max_score": 2.6272042,
          "hits": []
        },
        "aggregations": {
          "@timestamp": {
            "buckets": [
              {
                "key_as_string": "2018-08-05T22:00:00.000Z",
                "key": 1533506400000,
                "doc_count": 5100,
                "host.name": {
                  "doc_count_error_upper_bound": 0,
                  "sum_other_doc_count": 0,
                  "buckets": [
                    {
                      "key": "holo1",
                      "doc_count": 1560,
                      "system.filesystem.mount_point": {
                        "doc_count_error_upper_bound": 0,
                        "sum_other_doc_count": 960,
                        "buckets": [
                          {
                            "key": "/",
                            "doc_count": 60,
                            "tags": {
                              "doc_count_error_upper_bound": 0,
                              "sum_other_doc_count": 0,
                              "buckets": [
                                {
                                  "key": "vm-host",
                                  "doc_count": 60,
                                  "used_bytes": {
                                    "count": 60,
                                    "min": 19692740608,
                                    "max": 19692740608,
                                    "avg": 19692740608,
                                    "sum": 1181564436480
                                  },
                                  "available": {
                                    "value": 26867056640
                                  },
                                  "free": {
                                    "count": 60,
                                    "min": 29383639040,
                                    "max": 29383639040,
                                    "avg": 29383639040,
                                    "sum": 1763018342400
                                  }
                                }
                              ]
                            }
                          },
                          {
                            "key": "/boot",
                            "doc_count": 60,
                            "tags": {
                              "doc_count_error_upper_bound": 0,
                              "sum_other_doc_count": 0,
                              "buckets": [
                                {
                                  "key": "vm-host",
                                  "doc_count": 60,
                                  "total": {
                                    "count": 60,
                                    "min": 238787584,
                                    "max": 238787584,
                                    "avg": 238787584,
                                    "sum": 14327255040
                                  },
                                  "used_bytes": {
                                    "count": 60,
                                    "min": 51494912,
                                    "max": 51494912,
                                    "avg": 51494912,
                                    "sum": 3089694720
                                  },
                                  "available": {
                                    "value": 174553088
                                  },
                                  "free": {
                                    "count": 60,
                                    "min": 187292672,
                                    "max": 187292672,
                                    "avg": 187292672,
                                    "sum": 11237560320
                                  }
                                }
                              ]
                            }
                          }
                        ]
                      }
                    },
                    {
                      "key": "holo2",
                      "doc_count": 1320,
                      "system.filesystem.mount_point": {
                        "doc_count_error_upper_bound": 0,
                        "sum_other_doc_count": 720,
                        "buckets": [
                          {
                            "key": "/",
                            "doc_count": 60,
                            "tags": {
                              "doc_count_error_upper_bound": 0,
                              "sum_other_doc_count": 0,
                              "buckets": [
                                {
                                  "key": "vm-host",
                                  "doc_count": 60,
                                  "total": {
                                    "count": 60,
                                    "min": 10434699264,
                                    "max": 10434699264,
                                    "avg": 10434699264,
                                    "sum": 626081955840
                                  },
                                  "used_bytes": {
                                    "count": 60,
                                    "min": 2461360128,
                                    "max": 2461360128,
                                    "avg": 2461360128,
                                    "sum": 147681607680
                                  },
                                  "available": {
                                    "value": 7419691008
                                  },
                                  "free": {
                                    "count": 60,
                                    "min": 7973339136,
                                    "max": 7973339136,
                                    "avg": 7973339136,
                                    "sum": 478400348160
                                  }
                                }
                              ]
                            }
                          },
                          {
                            "key": "/boot",
                            "doc_count": 60,
                            "tags": {
                              "doc_count_error_upper_bound": 0,
                              "sum_other_doc_count": 0,
                              "buckets": [
                                {
                                  "key": "vm-host",
                                  "doc_count": 60,
                                  "total": {
                                    "count": 60,
                                    "min": 10426310656,
                                    "max": 10426310656,
                                    "avg": 10426310656,
                                    "sum": 625578639360
                                  },
                                  "used_bytes": {
                                    "count": 60,
                                    "min": 85614592,
                                    "max": 85614592,
                                    "avg": 85614592,
                                    "sum": 5136875520
                                  },
                                  "available": {
                                    "value": 9787469824
                                  },
                                  "free": {
                                    "count": 60,
                                    "min": 10340696064,
                                    "max": 10340696064,
                                    "avg": 10340696064,
                                    "sum": 620441763840
                                  }
                                }
                              ]
                            }
                          }
                        ]
                      }
                    }
                 ]
              }
            }
          ]
        }
      }
    }

    config = ConfigFactory({}).create()
    digester = Digester(None)
    doc = digester.get_aggregated_doc(search_result['aggregations'])
    pprint(doc)
    assert doc == {
        '_id': 1533506400000,
        '@timestamp': "2018-08-05T22:00:00.000Z",
        'available': 9787469824,
        'free': {'avg': 10340696064,
                  'count': 60,
                  'max': 10340696064,
                  'min': 10340696064,
                  'sum': 620441763840},
         'host.name': 'holo2',
         'system.filesystem.mount_point': '/boot',
         'tags': 'vm-host',
         'total': {'avg': 10426310656,
                   'count': 60,
                   'max': 10426310656,
                   'min': 10426310656,
                   'sum': 625578639360},
         'used_bytes': {'avg': 85614592,
                        'count': 60,
                        'max': 85614592,
                        'min': 85614592,
                        'sum': 5136875520}
    }



