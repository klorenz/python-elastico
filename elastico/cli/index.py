from .cli import command

index_command = command.add_subcommands('index',help="work with indices")

@index_command('ls')
def cmd_indices(config):
    '''list indices'''
    from .connection import elasticsearch
    es = elasticsearch(config)
    for idx in es.indices.get('_all').keys():
        print(idx)
