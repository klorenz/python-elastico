from .cli import command, arg, opt
from ..util import F
from os.path import abspath, join, dirname, exists
import os, tempfile, shutil, json
from posixpath import join as pjoin
import logging
log = logging.getLogger('elastico.cli.import_export')
from zipfile import ZipFile

@command('export',
    #arg('--format', choices=('zip', 'dir'), default="dir"),
    arg('--output', '-o', help="name of the output zip or dir", default=None),
    arg('index_name', help="name of index to export", nargs="+"),
    )
def cmd_export(config):
    """Export indices into your working directory

    If you do not pass an output name, for each index there will be created
    a single zip-file.

    If you pass an output-name, and it ends with ".zip" a single zip file will
    be created and all given indexes are stored in this zip.

    If you pass an output-name without ".zip" suffix a directory named like this
    will be created and all indexes are stored within. Directory must not exist.
    """
    log = logging.getLogger('elastico.cli.export')
    from ..connection import elasticsearch
    es = elasticsearch(config)
    from elasticsearch.helpers import scan

    index_name = config.get('export.index_name')
    result = {}
    for idx_name in index_name:
        result.update(es.indices.get(idx_name))

    tmpdir = None
    is_zip = False
    zip_output = None

    output_name = config.get('export.output')
    if output_name is None:
        is_zip = True
        zipbase = os.getcwd()
        dirbase = tmpdir = tempfile.mkdtemp()

    elif output_name.endswith('.zip'):
        is_zip = True
        zip_output = ZipFile(output_name, 'w')
        dirbase = tmpdir = tempfile.mkdtemp()

    else:
        dirbase = abspath(output_name)
        assert not exists(dirbase), "Output directory exists."
        os.makedirs(dirbase)

    try:
        for idx_name, idx_data in result.items():
            os.makedirs(join(dirbase, idx_name))

            with open(join(dirbase, idx_name, 'mappings.json'), 'w') as f:
                json.dump(idx_data['mappings'], f)

            with open(join(dirbase, idx_name, 'settings.json'), 'w') as f:
                json.dump(idx_data['settings'], f)

            log.info("exporting %s to %s/", idx_name, idx_name)

            with open(join(dirbase, idx_name, 'data.json'), 'w') as f:
                for data in scan(es, query={'query': {'match_all': {}}}, index=index_name):
                    json.dump(data, f)
                    f.write("\n")

            if is_zip:
                zf = zip_output
                if not zf:
                    zf = ZipFile(F('{zipbase}/{idx_name}.zip'), 'w')

                for fn in ('mappings.json', 'settings.json', 'data.json'):
                    zf.write(join(dirbase, idx_name, fn), pjoin(idx_name, fn))

                if not zip_output:
                    zf.close()

                shutil.rmtree(join(dirbase, idx_name))

    finally:
        if zip_output:
            zip_output.close()

        shutil.rmtree(tmpdir)


@command('import',
    arg("input", help="file or directory to import"),
    # mutually_exclusive(
    # )
    arg("--index", help="prefix index names to import with this name"),
    arg("--force", help="force import into existing index"),
    arg("--prefix", help="prefix index names to import with this name"),
    arg("--suffix", help="suffix index names to import with this name"),
    opt("--delete", help="delete the index before importing"),
    opt("--edit", "-e", help="substitution pattern in name s/foo/bar/", action="append")
    )
def cmd_import(config):
    '''Import index exports to elasticsearch.

    You can import from:

    * a directory containing an export (i.e. mappings.json, settings.json and
      data.json) files.  Index-name is assumed to be the name of the directory.

    * a directory containing directories (index-names) containing the set
      of import files.

    * a zip file containing one or more directories (index-names) with files from
      previous export.

    You can tweak the index-name in the following ways:

    * you can specify the target index.  In this case all of your indexes
      specified in import, will be imported into same index.  Be aware, that
      they have to be compatible in terms of field types and ID fields.
    * you can specify a prefix.  This will be prepended to each index_name
      in input.
    * you can specify a suffix.  This will be prepended to each index_name
      in input.
    * you can edit the index-name by specifying substituion expressions, which
      will be applied to each index-name


    '''
    input = config.get('import.input')
    if isdir(input):
        if exists(F("{input}/data.json")):
            input_list = [input]
        else:
            input_list = os.listdir(input)
    else:
        pass
        # zipfile

    target_index = None
    if config.get('import.index'):
        target_index = config.get('import.index')

    # if zipfile, extract first, then determine target_index
    # else de

    # I need a function, which takes a root dir and a list of subdirs or iterate
    # over it and for each index do an import

    for input in input_list:
        # handle zipfile
        pass

    #def load_file(name)

    mappings_file = join(index_name, 'mappings.json')
    if exists(mappings_file):
        with open(mappings_file, 'r') as f:
            mappings = json.load(f)

    mappings = None
    mappings_file = join(index_name, 'mappings.json')
    if exists(mappings_file):
        with open(mappings_file, 'r') as f:
            mappings = json.load(f)

    es.indices.create(index_name, body={'mappings': mappings})
    with open(join(index_name, 'data.json'), 'r') as f:
        bulk(es, [ json.loads(line) for line in f ], refresh=True)
