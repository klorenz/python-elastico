import sys, yaml, os, io
from os.path import exists, join, isdir, dirname, isabs, abspath

import logging
log = logging.getLogger('elastico.config')

from .util import string, PY3

from argdeco import ConfigDict, main
class Undefined:
    pass

from .formatter import ElasticoFormatter

formatter = ElasticoFormatter()

class Config(ConfigDict):
    @classmethod
    def object(cls, value=None, file=None):
        if value is None:
            value = {}

        if isinstance(value, string):
            if not PY3:
                if not isinstance(value, unicode):
                    value = value.decode('utf-8')
            value = yaml.load(io.StringIO(value))

        cfg = cls()
        cfg.update(value)
        cfg.set_filename(file)
        return cfg

    @classmethod
    def create(cls, config_file=None, arguments=None, **kwargs):
        if arguments is None:
            arguments = {}

        if kwargs:
            arguments.update(kwargs)

        if arguments:
            cfg = cls({'arguments': arguments})
        else:
            cfg = cls()

        if config_file:
            cfg.load_from_file(config_file)

        return cfg

    def load_from_file(self, file_name):
        '''argdeco's compiler_factory API'''
        file_name = abspath(file_name)
        self.config_file = file_name
        self.include_file(file_name)
        self.set_filename(file_name)

    def logging_setup(self):
        logspec = self.get('logging', {})
        if logspec:
            logspec = self.flatten(logspec)
            for k,v in logspec.items():
                if k == 'ROOT':
                    k = None
                logger = logging.getLogger(k)
                logger.setLevel(getattr(logging, v))
                log.info("change loglevel -- logger=%s, level=%s", k, v)

    def refresh(self, **kwargs):
        '''refresh this dictionary by rereading the data from disk'''
        log.info("refresh config -- config_file=%s", self.config_file)
        _arguments = self.get('arguments', {})
        _arguments.update(kwargs)
        self.clear()
        self.load_from_file(self.config_file)
        if _arguments:
            self['arguments'] = _arguments


    def get_filename(self, *configs):
        for config in configs:
            if hasattr(config, '_file'):
                return config
        return self._file

    def set_filename(self, filename):
        if filename is not None:
            log.debug("func='set_filename' filename=%r", filename)
            self._file = filename
            self._dir = dirname(filename)

    def __getattr__(self, name):
        #log.debug("func='__getattr__' name=%r", name)

        # if name == '_dir':
        #     self._dir = '.'
        #     return self._dir
        # if name == '_file':
        #     self._file = '-'
        #     return self._file
        # if name == '_files':
        #     self._files = set()
        #     return self._files
        #
        try:
            return self[name]
        except KeyError:
            pass
        raise AttributeError(name)

    def __getitem__(self, name):
        '''first look in self['arguments'] for finding a value.
        '''
#        log.debug("__getitem__: %s", name)

        if name == '.':
            return self

        try:
            arguments = super(Config, self).__getitem__('arguments')
        except KeyError:
            if name == 'arguments': raise
            arguments = {}

        if name == 'arguments':
            result = arguments
        else:
            try:
                result = arguments[name]
            except KeyError:
                try:
                    result = super(Config, self).__getitem__(name)
                except:
                    raise KeyError(name)

        return result

    def get(self, name, default=None):
        try:
            return self[name]
        except KeyError:
            return default

    def update_from_includes(self):
        log.debug("update_from_includes starts: %s", self._file)
        for item in self.get('include', []):
            log.debug("update_from_includes item: %s", item)
            if isinstance(item, string):
                if item.endswith('/'):
                    item = {'directory': item}
                else:
                    item = {'file': item}
            update_name = item.get('update')
            append_name = item.get('append')
            assert not (update_name and append_name), "you can only specify append OR update"
            if append_name:
                action='append'
                name = append_name
            else:
                action='update'
                name = update_name

            if 'directory' in item:
                recursive = item.get('recursive', False)
                self.update_from_dir(item['directory'], name, action=action, recursive=recursive)
            else:
                self.include_file(item['file'], name, action)

        return self

    def getdir(self):
        if hasattr(self, '_dir'):
            return self._dir
        else:
            return '.'

    def include_file(self, path, name=None, action='update', auto_include=True):
        _dir = self.getdir()

        log.debug("include_file: path=%s, name=%s, action=%s, _dir=%s", path, name, action, _dir)

        if name is not None:
            if name not in self:
                if action == 'update':
                    self[name] = {}
                elif action == 'append':
                    self[name] = []

            if isinstance(self[name], dict) and not isinstance(self[name], Config):
                self[name] = Config.object(self[name], file=self._file)
            if hasattr(self[name], '_dir'):
                _dir = self[name]._dir
        else:
            assert action != 'append', "append requires a config item name"

        log.debug("include_file: path=%s, name=%s, action=%s, _dir=%s", path, name, action, _dir)
        # if action == 'update':
        #     if name is not None:
        #         _file = self[name].get('_file_')
        #         _dir  = self[name].get('_dir_')

        if not isabs(path):
            path = join(_dir, path)

        log.debug("open %s", path)

        with open(path, 'r') as f:
            for _doc in yaml.load_all(f):
                _doc = Config.object(_doc, file=path)

                if auto_include:
                    _doc.update_from_includes()

                if name is not None:
                    log.debug("%s to self[%s]", action, name)

                    getattr(self[name], action)(_doc)

                    if action == 'update':
                        if not hasattr(self[name], '_files'):
                            self[name]._files = set()

                        self[name]._files.add(path)
                        if hasattr(_doc, '_files'):
                            for f in _doc._files:
                                self[name]._files.add(f)

                        # restore _file_ and _dir_
                        # if _file is not None:
                        #     self[name]['_file_'] = _file
                        #     self[name]['_dir_'] = _dir
                        #
                        # if '_files_' not in self[name]:
                        #     self[name]['_files_'] = []
                        #     if _file:
                        #         self[name]['_files_'].append(_file)
                        #
                        # self[name]['_files_'].append(path)
                        #
                else:
                    # _file = self.get('_file_')
                    # _dir  = self.get('_dir_')
                    log.debug("update self")

                    self.update(_doc)

                    if not hasattr(self, '_files'):
                        self._files = set()

                    self._files.add(path)
                    if hasattr(_doc, '_files'):
                        for f in _doc._files:
                            self._files.add(f)

                    # if _file is not None:
                    #     self['_file_'] = _file
                    #     self['_dir_'] = _dir
                    #
                    # if '_files_' not in self:
                    #     self['_files_'] = []
                    #     if _file:
                    #         self['_files_'].append(_file)
                    #
                    # self['_files_'].append(path)

                    #if '_files_' in _doc:
                    #    self['_files_'] += _doc['_files_']
                    # if '_files_' in self:
                    #     self['_files_'].append(_doc['_file_'])


    def update_from_dir(self, path, name, action='append', recursive=False):
        '''read configuration files and extend config

        Read all yaml files from directory `path` (recursive) and extract all YAML
        documents (also multidocument YAML files) and append to configuration list
        named `name`.
        '''
        _dir = self.getdir()
        log.debug("update_from_dir:: path=%s, name=%s, action=%s, recursive=%s, _dir=%s", path, name, action, recursive, _dir)

        #import rpdb2 ; rpdb2.start_embedded_debugger('foo')

        if action == 'update':
            if name is not None:
                if not isinstance(self[name], Config):
                    self[name] = Config.object(self[name], file=self._file)

                if hasattr(self[name], '_file'):
                    if self[name]._file == '-':
                        self[name].set_filename(self._file)

                if hasattr(self[name], '_dir'):
                    _dir = self[name]._dir

        if not isabs(path):
            path = join(_dir, path)

        log.debug("  path=%s, exists=%s", path, exists(path))

        if not exists(path): return

        if recursive:
            log.debug("  is_recursive")
            for root, dirs, files in os.walk(path):
                for fn in sorted(files):
                    self.include_file(join(root,fn), name, action)
        else:
            log.debug("  content=%s" % os.listdir(path))
            for fn in sorted(os.listdir(path)):
                _fn = join(path, fn)
                log.debug('  fn=%s, _fn=%s', fn, _fn)
                if isdir(_fn): continue

                log.debug('  is no dir')
                self.include_file(_fn, name, action)

        return self


    def getval(self, name, default=None):
        return self.format(self.get(name, default))


    def format(self, current=Undefined, *data):
        def _Config(x):
            if isinstance(x, ConfigDict):
                return x
            if isinstance(x, dict):
                return Config(x)
            return x

        if current is Undefined:
            current = self

        if isinstance(current, string):
            if '{' not in current:
                result = current
            else:
                try:
                    _data = self
                    if data:
                        _data = {}
                        _data.update(self)

                        for d in data:
                            _data.update(d)

                        # make use of dotted notation possible -- is Config too heavyweight?
                        _data = dict((k,_Config(v)) for k,v in _data.items())

                    result = formatter.format(current, **_data)

                    #result = current.format(**_data)
                except KeyError:
                    result = current
                except AttributeError:
                    result = current
            log.debug("format_value result=%s", result)

        elif isinstance(current, (list, tuple)):
            result = [self.format(v) for v in current]

        elif isinstance(current, dict):
            result = {}
            for k,v in current.items():
                result[k] = self.format(v, *(list(data)+[current]))
        else:
            result = current

        return result

