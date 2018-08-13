import sys, yaml, os
from os.path import exists, join, isdir, dirname, isabs

import logging
log = logging.getLogger('elastico.config')

from .util import string

class Config(dict):
    def __contains__(self, name):
        try:
            self[name]
            return True
        except KeyError:
            return False

    def __getitem__(self, name):
        key_parts = name.split('.')
        value = super(Config, self).__getitem__(key_parts[0])
        for k in key_parts[1:]:
            value = value[k]
        return value

    def get(self, name, default=None):
        if isinstance(default, dict):
            default = Config(default)

        try:
            result = self[name]
        except KeyError:
            return default

        result = self.format_value(result)

        if isinstance(result, dict):
            return Config(result)

        return result

    def update_from_includes(self):
        log.debug("update_from_includes starts: %s", self.get('_file_', '-'))
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

    def include_file(self, path, name=None, action='update', auto_include=True):
        log.debug("include_file: path=%s, name=%s, action=%s", path, name, action)
        _dir = self.get('_dir_', '.')

        if name is not None:
            if name not in self:
                if action == 'update':
                    self[name] = {}
                elif action == 'append':
                    self[name] = []
            else:
                if isinstance(self[name], dict):
                    _dir = self[name].get('_dir_', _dir)
        else:
            assert action != 'append', "append requires a config item name"

        if action == 'update':
            if name is not None:
                _file = self[name].get('_file_')
                _dir  = self[name].get('_dir_')

        if not isabs(path):
            path = join(_dir, path)

        log.debug("open %s", path)

        with open(path, 'r') as f:
            for _doc in yaml.load_all(f):
                _doc['_file_'] = path
                _doc['_dir_'] = dirname(path)

                if auto_include:
                    _doc = Config(_doc)
                    _doc.update_from_includes()

                if name is not None:
                    getattr(self[name], action)(_doc)

                    if action == 'update':
                        # restore _file_ and _dir_
                        if _file is not None:
                            self[name]['_file_'] = _file
                            self[name]['_dir_'] = _dir

                        if '_files_' not in self[name]:
                            self[name]['_files_'] = []
                            if _file:
                                self[name]['_files_'].append(_file)

                        self[name]['_files_'].append(path)

                    #    if '_files_' in _doc:
                    #        self[name]['_files_'] += _doc['_files_']
                else:
                    _file = self.get('_file_')
                    _dir  = self.get('_dir_')

                    self.update(_doc)

                    if _file is not None:
                        self['_file_'] = _file
                        self['_dir_'] = _dir

                    if '_files_' not in self:
                        self['_files_'] = []
                        if _file:
                            self['_files_'].append(_file)

                    self['_files_'].append(path)

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
        log.debug("update_from_dir:: path=%s, name=%s, action=%s, recursive=%s", path, name, action, recursive)

        _dir = self.get('_dir_', '.')

        if action == 'update':
            if name is not None:
                _dir  = self[name].get('_dir_', _dir)

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

    def format_value(self, current=None):
        if current is None:
            current = self
        if isinstance(current, string):
            return current.format(**self)
        if isinstance(current, (list, tuple)):
            return [self.format_value(v) for v in current]
        if isinstance(current, dict):
            result = {}
            for k,v in current.items():
                result[k] = self.format_value(v)
            return result
        else:
            return current

