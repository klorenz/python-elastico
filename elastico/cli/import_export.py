from .cli import command, arg

@command('export',
    arg('--format', choices=('zip', 'dir'), default="dir"),
    arg('index_name', help="name of index to export"),
    )
def cmd_export(config):
    """Export indices into your working directory
    """
    from .connection import elasticsearch
    es = elasticsearch(config)
    from elasticsearch.helpers import scan

    index_name = config.get('export.index_name')
    result = es.indices.get(index_name)

    for idx_name, idx_data in result.items():

        if config.get('export.format') == 'dir':
            os.makedirs(idx_name)
            with open(join(idx_name, 'mappings.json'), 'w') as f:
                json.dump(result[idx_name]['mappings'], f)

            log.info("exporting %s to %s/", idx_name, idx_name)

            with open(join(idx_name, 'data.json'), 'w') as f:
                for data in scan(es, query={'query': {'match_all': {}}}, index=index_name):
                    json.dump(data, f)
                    f.write("\n")

        elif config.get('export.format') == 'zip':
            pass


@command('import', arg('index_name'))
def cmd_import(config):
    index_name = config.get('index_name')

    with open(join(index_name, 'mappings.json'), 'r') as f:
        mappings = json.load(f)

    es.indices.create(index_name, body={'mappings': mappings})
    with open(join(index_name, 'data.json'), 'r') as f:
        bulk(es, [ json.loads(line) for line in f ], refresh=True)
