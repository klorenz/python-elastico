"""This module provides ConfigFactory class.
"""

from .config import Config
import yaml, copy

from argdeco import ConfigDict
from os.path import exists, join

class ConfigFactory:
    """This class provides a factory producing a new Config object
    """

    def __init__(self, source=None):
        """Initialized usually from a config argument passed at commandline.

        :param source:
            If source is empty, :func:`create` will always produce an empty
            config object for the start (only `arguments` populated by given
            keywords.)

            If source is '-', data is read from stdin and parsed by YAML
            parser.  So you can pass YAML or JSON data.  This will be the
            initial content of the :class:`Config` object.

            If source is a filename and file exists, this file is read each
            time :func:`create` is run and parsed by YAML parser and a new
            a :class:`Config` object is produced from this data.
        """
        if isinstance(source, dict):
            self.config = source
        elif not source:
            self.config = {}
        elif source == '-':
            self.config = yaml.load(sys.stdin)
        elif exists(source):
            self.config = {}
            self.config_file = source

        self.arg_config = ConfigDict()

    def load_from_file(self, file_name):
        self.config_file = file_name

    def __setitem__(self, name, value):
        self.arg_config[name] = value

    # def update(self, *args, **kwargs):
    #     self.config.update(*args, **kwargs)

    def create(self, **kwargs):
        """Produce a new :class:`Config` object.

        :param **kwargs:
            Keyword arguments are used to populate config's `arguments`
            dictionary.
        """

        config = copy.deepcopy(self.config)
        config = Config(config)

        if hasattr(self, 'config_file'):
            config.include_file(self.config_file)
            config.set_filename(self.config_file)

        # #_action, _args, _kwargs = main.command.compile_args()
        #
        # action = main.command.get_action(name)
            #
        # for k,v in kwargs:
        #     main.command.get_config_name(action, v)

        #config['arguments'] = self.arg_config

        #config.update(self.arg_config)

        config['arguments'] = kwargs

        return config
