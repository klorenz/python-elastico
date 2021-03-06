from .cli import command, arg, opt

index_command = command.add_subcommands('index',help="work with indices")

@index_command('ls', arg('index', help="index name(s)", nargs="*"), opt('--count'))
def cmd_indices(config):
    '''list indices'''
    from ..connection import elasticsearch
    es = elasticsearch(config)
    indexes = config.get('index.ls.index')
    if not indexes:
        indexes = ['_all']

    for indexpattern in indexes:
        for idx in sorted(es.indices.get(indexpattern).keys()):
            details = config.get('index.ls.count')
            if details:
                print("index={} count={}".format(idx, es.count(index=idx)['count']))
            else:
                print(idx)



@index_command('rm', arg('index', help="index name(s)", nargs="+"))
def cmd_indices(config):
    '''list indices'''
    from ..connection import elasticsearch
    es = elasticsearch(config)
    for idx in config.get('index.rm.index'):
        es.indices.delete(idx)

@index_command('refresh', arg('index', help="index name(s)", nargs="+"))
def cmd_indices(config):
    '''list indices'''
    from ..connection import elasticsearch
    es = elasticsearch(config)
    for idx in config.get('index.refresh.index'):
        print(es.indices.refresh(idx))

    # for idx in es.indices.get('_all').keys():
    # for idx in es.indices.get('_all').keys():
    #     print(idx)
