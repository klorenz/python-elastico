from argdeco import command, main, arg, opt, config_factory
from os.path import exists, join
from zipfile import ZipFile, ZipInfo

from ..util import to_dt, dt_isoformat
from ..config import Config

import os
import logging
from datetime import datetime

# initialize logger
logger = logging.getLogger('elastico.cli')

# use our compiler factory for generating config object
main.configure(compiler_factory=config_factory(Config,
    prefix = 'arguments',
    config_file=arg( '--config-file', '-C',
        help="File to read configuration from"),
    ),
    prog="elastico"
    )

@arg('--run-at',
    help="simulate running this program at given time",
    config="run_at",
    default=to_dt(dt_isoformat(datetime.utcnow(), 'T', 'seconds'))
    )
def arg_run_at(value):
    return to_dt(value)

# add global arguments
main.add_arguments(
    arg('--host', '-H', help="Elasticsearch host. (CFG: elasticsearch.hosts)", config="elasticsearch.hosts"),
    arg('--netrc', help="get netrc entry <machine>. (CFG: netrc.machine)", config="netrc.machine"),
    arg('--netrc-file', help="set netrc file to read. (CFG: netrc.file)", config="netrc.file"),
    arg_run_at,
)

class MyZipFile(ZipFile):
    '''This class overrides :py:meth:~zipfile.ZipFile:'s ``_extract_member``
    method to set executable flags, if set in ZIP file'''

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

@command('run')
def install(config):
    """run elastic search in current directory"""

    package = "elasticsearch"
    version = "6.3.2"

    executable = "{}-{}/bin/elasticsearch".format(package, version)

    #if not exists(executable)

    os.execl(executable, executable)

@command('check-args')
def check_args(config):
    """check config"""
    import pyaml
    pyaml.p(config)

