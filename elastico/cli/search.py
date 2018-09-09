from .cli import command, arg
from os.path import exists
from ..search import build_search_body
from ..connection import elasticsearch

import logging
log = logging.getLogger('elastico.cli.search')

@command('search',
    arg('--format', '-F',
        help="format string, which is applied to each match",
        default=None),
    arg('query', help="may be a query, a filename or '-' to read from stdin"),
    arg('index', help="index to query", nargs="?", default='*')
)
def search(config): #host, format, query):
    format = config.get('search.format')
    query  = config.get('search.query')

    log.debug("format=%r query=%r", format, query)
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

    if content is not None:
        if content.startswith("---"):
            import frontmatter
            config, content = frontmatter.loads(content)
            config['search.template'] = content
        else:
            config = yaml.loads(io.StringIO(content))

    body = build_search_body(config, 'query')
    log.error("body=%r", body)
    es = elasticsearch(config)
    results = es.search(index=config.get('search.index', '*'), body=body)

    if config.get('search.format'):
        for hit in results['hits']['hits']:
            print(config['search.format'].format(hit))

    elif config.get('search.template'):
        import chevron
        args = {}
        for k in ('template', 'partials_path', 'partials_ext',
           'partials_dict', 'padding', 'def_ldel', 'def_rdel'):
            if k in config['search']:
                args[k] = config['search'][k]

        data = config.get('data', {}).copy()
        data.update(results)
        args['data'] = data
        print(chevron.render(**args))

    else:
        import pyaml
        pyaml.p(results)

