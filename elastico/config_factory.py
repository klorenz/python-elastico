"""This module provides ConfigFactory class.
"""

from .config import Config
import yaml, copy

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

    #def upd

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

        config['arguments'] = kwargs

        return config

