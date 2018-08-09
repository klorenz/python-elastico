from argdeco import command, main, arg
from os.path import exists
import requests
import os
from zipfile import ZipFile, ZipInfo

from .connection import elasticsearch
from .search import build_search_body

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
def install():
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
def search(host, format, query):
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
arg_config = arg('config', help="configuration file or '-' to read from stdin")

def read_config(config):
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

        if exists(path):
            for root, dirs, files in os.walk(path):
                for name in files:
                    with open(join(root, name), 'r') as f:
                        for _rule in yaml.load_all(f):
                            config['rules'].append(_rule)

    config['arguments'] = {}
    return config


alert_command("expand_rules",
    arg_config,
    description = Alerter.expand_rules.__doc__
    )
def cmd_alert_expand_rules(config):
    config = read_config(config)

    for r in Alerter.expand_rules(config):
        print("---")
        pyaml.p(r)


alert_command("run",
    arg('--dry-run', help="do a dry run without writing to index"),
    arg_config,
    description = Alerter.run.__doc__
    )
def cmd_alert_run(dry_run, config):
    config = read_config(config)

    if dry_run:
        config['arguments']['dry_run'] = True
    Alerter.run(config)


