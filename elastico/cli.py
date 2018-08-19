from argdeco import command, main, arg
from os.path import exists, join
import requests
import os
import json
from zipfile import ZipFile, ZipInfo

from .connection import elasticsearch
from .search import build_search_body
from .config_factory import ConfigFactory

import logging
logger = logging.getLogger('elastico.cli')

# we need also executable flags
class MyZipFile(ZipFile):
    def _extract_member(self, member, targetpath, pwd):
        if not isinstance(member, ZipInfo):
            member = self.getinfo(member)

        if targetpath is None:
            targetpath = os.getcwd()

        ret_val = ZipFile._extract_member(self, member, targetpath, pwd)
        attr = member.external_attr >> 16
        os.chmod(ret_val, attr)
        return ret_val



@command('install')
def install(config):
    '''install elasticsearch from zip right here, mostly used for testing'''

    package = "elasticsearch"
    version = "6.3.2"
    filename = "{}-{}.zip".format(package, version)

    if not exists(filename):
        url = "https://artifacts.elastic.co/downloads/elasticsearch/"+filename

        logger.info("Downloading %s", url)

        r = requests.get(url)
        with open(filename, 'wb') as output:
            for chunk in r.iter_content(chunk_size=512*1024):
                output.write(chunk)

    logger.info("Extracting %s", filename)
    import zipfile
    zip_ref = MyZipFile(filename, 'r')
    zip_ref.extractall(".")
    zip_ref.close()

# @command('testdata',
#     arg('--index-pattern', '-i', help="pattern for the index name, will be interpreted by strftime with timestamp"),
#
#     arg('--starttime', '-s', help="pattern for the index name, will be interpreted by strftime with timestamp"),
#     arg('--endtime', '-e', help="pattern for the index name, will be interpreted by strftime with timestamp"),
#     arg('--steptime', '-S', help="frequency of time"),
#
#     arg('--count', '-c', help="count"),
#
#     arg('fields', nargs='+', help="fields according to field spec"))
# def testdata():
#     '''Generate test data suitable for bulk import.
#
#     # Field Spec
#
#     name=type:generator:arg1:arg2...
#
#     There are following types:
#
#     - *int* -- integer
#     - *datetime* -- datetime
#     - *float* -- float
#     - *string* -- string
#     - *
#
#
#     '''
#
#     import requests
#
#     # get the adventures of sherlock holmes
#     r = requests.get('http://www.gutenberg.org/cache/epub/1661/pg1661.txt')
#

# @command('import',
#     arg_config
# )
# def cmd_import(config, data):
#


@command('search',
    arg('--host', '-H', help="url to elasticsearch host, default http://localhost:9200", default=None),
    arg('--format', '-F', help="format string, which is applied to each match", default=None),
    arg('query', help="may be a query, a filename or '-' to read from stdin"),
)
def search(config): #host, format, query):
    host = config.get('host')
    format = config.get('format')
    query = config.get('query')
    content = None
    if query == '-':
        content = sys.stdin.read()
    elif exists(query):
        with open(query, 'r') as f:
            content = f.read()
    else:
        config = {}
        config['query'] = query
        config['format'] = format

    if host:
        if 'elasticsearch' not in config:
            config['elasticsearch'] = {}
        config['elasticsearch']['hosts'] = [ host ]

    if content is not None:
        if content.startswith("---"):
            import frontmatter
            config, content = frontmatter.loads(content)
            config['template'] = content
        else:
            config = yaml.loads(io.StringIO(content))

    body = build_search_body(config, 'search')
    es = elasticsearch(config)
    results = es.search(index=config.get('index', '*'), body=body)

    if config['format']:
        for hit in results['hits']['hits']:
            print(config['format'].format(hit))

    elif config['template']:
        import chevron
        args = {}
        for k in ('template', 'partials_path', 'partials_ext',
           'partials_dict', 'padding', 'def_ldel', 'def_rdel'):
            if k in config:
                args[k] = config[k]

        data = config.get('data', {}).copy()
        data.update(results)
        args['data'] = data
        print(chevron.render(**args))

    else:
        import pyaml
        pyaml.p(results)


# alert commands

from .alert import Alerter

alert_command = command.add_subcommands('alert',)
arg_config = arg('config', help="configuration file or '-' to read from stdin", default=None)

def read_config(config):
    if not config:
        return {}

    if config == '-':
        config = yaml.load(sys.stdin)
    elif exists(config):
        with open(config, 'r') as f:
            config = yaml.load(f)

    path = config.get('rules_path')
    if 'rules' not in config:
        config['rules'] = []

    if path:
        path = path.format(**config)
        read_config_dir(path.format(**config), config, 'rules')

    config['arguments'] = {}
    return config


alert_command("expand_rules",
    arg_config,
    description = Alerter.expand_rules.__doc__
    )
def cmd_alert_expand_rules(config):
    config_factory = ConfigFactory(config)

#    config = read_config(config)

    for r in Alerter.expand_rules(config_factory):
        print("---")
        pyaml.p(r)


alert_command("run",
    arg('--dry-run', help="do a dry run without writing to index"),
    arg_config,
    description = Alerter.run.__doc__
    )
def cmd_alert_run(config):
    cfg = read_config(config['config'])
    cfg['arguments'] = config
    Alerter.run(cfg)

digest_command = command.add_subcommands('digest',)

'''idea of digest commands is to analyse and do digestions.

Here an example for aggregating filesystem metricset of metric beat:

Configuration:
```yaml
# for each index matching index pattern
retentions:
- index-pattern: metricbeat-*

  target: history-metricbeat-%Y-%m

  digest:
  - name: metricset-filesystem

    fields:
        metricset.module: "system"
        metricset.name: "filesystem"

    buckets:
        terms:
            tags:        tags
            host_name:   host.name
            mount_point: system.filesystem.mount_point

    aggregate:
        terms:
            metricset.name:   metricset.name
            metricset.module: metricset.module
        stats:
            available:  system.filesystem.available
            free:       system.filesystem.free
            total:      system.filesystem.total
            available:  system.filesystem.available
            used_pct:   system.filesystem.used.pct
            used_bytes: system.filesystem.used.bytes

  - name: metricset-network

      fields:
        metricset.module: "system"
        metricset.name: "filesystem"

      buckets:
        terms:
          - host.name
          - system.network.name

      aggregate:
        terms:
            - tags
        stats:
            - system.network.in.bytes
            - system.network.in.dropped
            - system.network.in.errors
            - system.network.in.packats

            - system.network.out.bytes
            - system.network.out.dropped
            - system.network.out.errors
            - system.network.out.packats
```

```json
```

'''
arg_config = arg('--config', '-c', help="configuration file or '-' to read from stdin", default=None)

digest_command('query',
    arg_config,
    arg('--run-at', help="simulate running this program at given time"),
    arg('--starttime', help="start date"),
    arg('--endtime', help="end date"),
    arg('name', help="name of the digestion to run the query for"),
)
def cmd_query(config):
    from digest import Digester
    Digester.run_query(config)


digest_command('collect', arg_config,
    arg('--starttime', help="start date"),
    arg('--endtime', help="end date"),
    arg('--period', help="length of period (possible: 10s, 10m, 10h)"),
)
def cmd_collect(config): #, starttime, endtime, period):
    config = read_config(config)
    config['arguments'] = {}
    if starttime:
        config['arguments']['starttime'] = starttime

    if endtime:
        config['arguments']['endtime'] = endtime


import pyaml
@command('indices', arg_config)
def cmd_indices(config):
    from .connection import elasticsearch
    es = elasticsearch(config)
    pyaml.p([idx for idx in es.indices.get('_all').keys()])


#@command('index')

@command('export', arg_config, arg('index_name'))
def cmd_export(config):
    from .connection import elasticsearch
    es = elasticsearch(config)
    from elasticsearch.helpers import scan

    # pyaml.p([idx for idx in es.indices.get('_all').keys()])
    index_name = config.get('index_name')

    result = es.indices.get(index_name)
    #result = {'mappings': result[index_name]['mappings']}
    os.makedirs(index_name)
    with open(join(index_name, 'mappings.json'), 'w') as f:
        json.dump(result[index_name]['mappings'], f)

    with open(join(index_name, 'data.json'), 'w') as f:
        for data in scan(es, query={'query': {'match_all': {}}}, index=index_name):
            json.dump(data, f)
            f.write("\n")

@command('import', arg_config, arg('index_name'))
def cmd_import(config):
    index_name = config.get('index_name')

    with open(join(index_name, 'mappings.json'), 'r') as f:
        mappings = json.load(f)

    es.indices.create(index_name, body={'mappings': mappings})
    with open(join(index_name, 'data.json'), 'r') as f:
        bulk(es, [ json.loads(line) for line in f ], refresh=True)
