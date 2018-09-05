import logging, requests

from argdeco import command, main, arg, opt, config_factory
from os.path import exists, join, expanduser
from zipfile import ZipFile, ZipInfo

from ..util import to_dt, dt_isoformat, write_output
from ..config import Config

import os
import logging
from datetime import datetime

# initialize logger
logger = logging.getLogger('elastico.cli')
import os

# find config_file default
# ------------------------
if 'USERPROFILE' in os.environ and 'HOME' not in os.environ:
    os.environ['HOME'] = os.environ['USERPROFILE']

config_file_user   = expanduser("~/.config/elastico/elastico.yml")
config_file_system = "/etc/elastico/elastico.yml"

if exists(config_file_user):
    config_file_default = config_file_user
elif exists(config_file_system):
    config_file_default = config_file_system
else:
    config_file_default = None

# configure main function
# -----------------------
main.configure(
    compiler_factory=config_factory(Config,
        prefix = 'arguments',
        config_file=arg( '--config-file', '-C',
            help="File to read configuration from",
            default = config_file_default,
            ),
    ),
    debug=True,
    verbosity=True,
    prog="elastico",
    )

@arg('--at',
    help="simulate running this program at given time",
    config="at",
    default=dt_isoformat(datetime.utcnow(), 'T', 'seconds')
    )
def arg_at(value):
    return dt_isoformat(to_dt(value))

# add global arguments
# --------------------
main.add_arguments(
    arg('--host', '-H', help="Elasticsearch host. (CFG: elasticsearch.hosts)", config="elasticsearch.hosts"),
    arg('--netrc', help="get netrc entry <machine>. (CFG: netrc.machine)", config="netrc.machine"),
    arg('--netrc-file', help="set netrc file to read. (CFG: netrc.file)", config="netrc.file"),
    arg('--output-format', '-F', help="set output format", choices=['json', 'yaml'], default='yaml'),
    arg_at,
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

