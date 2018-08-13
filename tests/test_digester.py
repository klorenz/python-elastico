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


if PY3:
    unicode = str


def test_make_query():
    config = yaml.load(io.StringIO(dedent(unicode("""
      digest:
        rules:
        - name: metricbeat
          index-pattern: metricbeat-*
          target: metricbeat-history-%Y-%m
          digest_type: index
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
    import pprint
    query = digester.make_query(rule, digest)
    print("query")
    pprint.pprint(query)

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

    print("expected")
    pprint.pprint(expected)

    assert query == expected
