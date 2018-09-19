import sys, yaml, os, pytz, pyaml, json, re
from os.path import exists, join, isdir
from subprocess import Popen, PIPE
from copy import deepcopy

if (sys.version_info > (3, 0)):
    PY3 = True
    string = str

else:
    PY3 = False
    string = basestring
    Exception = StandardError

try:
    from textwrap import indent
except ImportError:
    def indent(s, ind):
        result = []
        for line in s.splitlines(1):
            result.append(ind+line)
        return ''.join(result)

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

    try:
        result = dt.isoformat(sep, timespec)
        result = result.rsplit('+', 1)[0]
    except TypeError:

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

def to_dt(x, *args, **kwargs):
    if not isinstance(x, datetime):
        x = dt_parse(x, *args, **kwargs)
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
    return get_netrc_login_data_from_value(nrc)

def get_netrc_login_data_from_value(nrc):
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

def sendmail(host='localhost', port=0, use_ssl=False,
    username=None, password=None,
    sender=None, recipients=[], message=''):

    log.debug("sendmail")

    if use_ssl:
        from smtplib import SMTP_SSL as SMTP
    else:
        from smtplib import SMTP

    smtp = SMTP()
    smtp.connect(host=host, port=port)
    # if user and password are given, use them to smtp.login(user, pass)
    if username is not None:
        smtp.login(username, password)

    result = smtp.sendmail(sender, recipients, message)
    smtp.quit()
    return result


def run_command(kwargs, data=None):
    log = logging.getLogger('elastico.util.command')

    log.debug("run_command -- kwargs=%s", kwargs)

    if isinstance(kwargs, string):
        kwargs = {'args': kwargs, 'shell': True}
    elif isinstance(kwargs, (list, tuple)):
        kwargs = {'args': kwargs}
    else:
        kwargs = dict(kwargs)

    if isinstance(kwargs['args'], string):
        if 'shell' not in kwargs:
            kwargs['shell'] = True

    def _get_capture_value(name):
        if name in kwargs:
            return kwargs.pop(name)
        elif data is not None and name in data:
            return data[name]
        else:
            return False
        return

    capture_stdout = _get_capture_value('stdout')
    capture_stderr = _get_capture_value('stderr')

    if 'input' in kwargs:
        input = kwargs.pop('input')
        kwargs['stdin'] = PIPE
    else:
        input = None

    log.info("Popen -- kwargs=%s", kwargs)
    p = Popen(stdout=PIPE, stderr=PIPE, **kwargs)
    (stdout, stderr) = p.communicate(input)
    result = p.wait()

    if data is not None:
        _result = {}
        if capture_stdout:
            if stdout.count("\n".encode('utf-8')) == 1:
                stdout = stdout.strip()
            _result['stdout'] = stdout
        if capture_stderr:
            _result['stderr'] = stderr
        _result['exit_code'] = result

        data['result'] = _result

    return (result, stdout, stderr)


    log.debug("capture_stdout=%s, capture_stderr=%s", capture_stdout, capture_stderr)

    if rule is not None:
        if capture_stdout:
            if stdout.count("\n".encode('utf-8')) == 1:
                stdout = stdout.strip()
            rule['result.stdout'] = stdout
        if capture_stderr:
            rule['result.stderr'] = stderr
        rule['result.exit_code'] = result

    log.debug("rule: %s", rule)

    return (result, stdout, stderr)


def stripped(s, count=100):
    if len(s) > count:
        s = s[:count]+"..."
    return s

def get_alerts(_alerts, context):
    from .config import Config

    if isinstance(_alerts, list):
        result = {}
        for a in _alerts:
            result[a['type']] = a
        _alerts = result
    else:
        for k,v in _alerts:
            if 'type' not in v:
                v['type'] = k

    return Config.object(_alerts)

def F(s):
    return s.format(**sys._getframe(1).f_locals)

def slugify(s, strip_=False, prefix_=None, suffix_=None):
    log.debug("func='slugify' s=%r", s)
    result = re.sub(r'[^\w]+', '_', s.lower())
    if result == '_':
        result = 'x'
    if prefix_ is not None:
        if result.startswith('_'):
            result = prefix_+result
    if suffix_ is not None:
        if result.endswith('_'):
            result = result+suffix_
    if strip_:
        result = result.strip('_')
    # if result.endswith('_'):
    #     result += 'x'
    # if result.startswith('_'):
    #     #result = 'x'+result
    log.debug("func='slugify' result=%r", result)
    return result

