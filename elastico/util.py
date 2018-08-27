import sys, yaml, os, pytz, pyaml, json
from os.path import exists, join, isdir

if (sys.version_info > (3, 0)):
    PY3 = True
    string = str
else:
    PY3 = False
    string = basestring

import logging
log = logging.getLogger('elastico.util')

from datetime import datetime,date
from dateutil.parser import parse as dt_parse

def start_of_day(dt):
    return datetime.combine(to_dt(dt).date(), datetime.min.time())

def end_of_day(dt):
    return datetime.combine(to_dt(dt).date(), datetime.max.time())

def dt_isoformat(dt, sep='T', timespec='seconds'):
    if not isinstance(dt, (datetime, date)):
        dt = dt_parse(dt)

    if PY3:
        result = dt.isoformat(sep, timespec)
        result = result.rsplit('+', 1)[0]

    else:
        result = dt.isoformat(sep)
        result = result.rsplit('+', 1)[0]

        if timespec == 'hours':
            result = result.split(':')[0]
        elif timespec == 'minutes':
            result = result.rsplit(':', 1)[0]
        elif timespec == 'seconds':
            if '.' in result:
                result = result.rsplit('.', 1)[0]
        else:
            raise Exception("timespec %s not supported", timespec)

    return result+"Z"

def to_dt(x):
    if not isinstance(x, datetime):
        x = dt_parse(x)
    if x.tzinfo is None:
        return pytz.UTC.localize(x)
    else:
        return x

def get_netrc_login_data(data, name):
    """
    raises LookupError, in case "name" not in "data"
    :returns:
    """
    # netrc configuration
    nrc = data.get(name, {})

    if not nrc:
        raise LookupError("no netrc data present")

    if not isinstance(nrc, dict):
        filename = None
        machine  = nrc
    else:
        filename = nrc.get('file')
        machine  = nrc.get('machine')

    if machine is None:
        raise LookupError("no netrc data present")

    if nrc:
        import netrc
        (user, account, password) = netrc.netrc(filename).authenticators(machine)

    return (user, password)


def read_config_dir(path, config, name, recursive=False):
    '''read configuration files and extend config

    Read all yaml files from directory `path` (recursive) and extract all YAML
    documents (also multidocument YAML files) and append to configuration list
    named `name`.
    '''
    if name not in config:
        config[name] = []

    path = path.format(**config)

    if not exists(path): return

    if recursive:
        for root, dirs, files in os.walk(path):
            for fn in files:
                with open(join(root, fn), 'r') as f:
                    for _doc in yaml.load_all(f):
                        config[name].append(_doc)
    else:
        for fn in os.listdir(path):
            _fn = join(path, fn)
            if isdir(_fn): continue

            with open(_fn, 'r') as f:
                for _doc in yaml.load_all(f):
                    config[name].append(_doc)

def get_config_value(config, key, default=None):
    key_parts = key.split('.')
    try:
        result = format_value(config, config.get(key_parts[0], default))
    except Exception as e:
        log.debug("error in formatting %s", e)
        return default

    for k in key_parts[1:]:
        if k not in result:
            return default
        result = result[k]
    return result


def format_value(data, current=None):
    if current is None:
        current = data
    if isinstance(current, string):
        return current.format(**data)
    if isinstance(current, (list, tuple)):
        return [format_value(data, v) for v in current]
    if isinstance(current, dict):
        result = {}
        for k,v in current.items():
            result[k] = format_value(data, v)
        return result
    else:
        return current
    #
    # except Exception as e:
    #     log.debug("error formatting %s: %s", current, e)
    #     return default

def first_value(d):
    '''return the first value of dictionary d'''
    if PY3:
        return list(d.values())[0]
    else:
        return d.values()[0]

def write_output(config, data):
    output_format = config.get('output_format', 'yaml')
    if output_format == 'yaml':
        pyaml.p(data)
    elif output_format == 'json':
        print(json.dumps(data, indent=2))

