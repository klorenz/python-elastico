"""alerter -- a simple alerter module

"""

from datetime import datetime, timedelta
from dateutil.parser import parse as dt_parse
from itertools import product
from subprocess import Popen, PIPE
from copy import deepcopy
from .notifier import Notifier

#from ..config import Config

import logging, sys, json, pyaml, re
log = logging.getLogger('elastico.alerter')

from .util import to_dt, PY3, dt_isoformat, format_value, get_config_value
from .util import stripped, get_alerts

from .config import Config

if PY3:
    unicode = str
    string = str
else:
    string = basestring
    Exception = StandardError

def indent(indent, s):
    if isinstance(indent, int):
        indent = " "*indent
    return "".join([ indent+line for line in s.splitlines(1) ])


class NotificationError(Exception):
    pass

class Alerter:
    '''alerter alerts.

    here more doc.
    '''
    LAST_CHECK = {}

    def __init__(self, es_client=None, config={}, config_base="alerter"):
        self.es = es_client
        self.config = config
        self.STATUS = {}
        self.status_index_dirty = False

    def wipe_status_storage(self):
        '''remove all status storages'''
        result = self.es.indices.delete('elastico-alerter-*')
        log.debug("wipe_status_storage: %s", result)
        return result

    def get_status_storage_index(self):
        date = to_dt(self.config['at'])
        return date.strftime('elastico-alerter-%Y-%m-%d')

    def refresh_status_storage_index(self):
        if self.es:
            try:
                self.es.indices.refresh(self.get_status_storage_index())
            except:
                pass

    def write_status(self, rule):
        storage_type = self.config.get('alerter.status_storage', 'memory')

        now = to_dt(dt_isoformat(datetime.utcnow(), 'T', 'seconds'))
        #rule['@timestamp'] = to_dt(self.get_rule_value(rule, 'run_at', now))
        rule['@timestamp'] = timestamp = dt_isoformat(self.config['at'])
        if 'at' in rule:
            rule['at'] = dt_isoformat(rule['at'])

        log.debug("rule to write to status: %s", rule)

        key  = rule.get('key')
        type = rule.get('type')

        if storage_type == 'elasticsearch':
            index = self.get_status_storage_index()
            #_rule = Config.object(rule).format_value()
            if 'match' in rule and not isinstance(rule['match'], string):
                rule['match'] = json.dumps(rule['match'])
            if 'match_query' in rule and not isinstance(rule['match_query'], string):
                rule['match_query'] = json.dumps(rule['match_query'])


            result = self.es.index(index=index, doc_type="elastico_alert_status", body=rule)
            #self.es.indices.refresh(index)
            log.debug("index result: %s", result)
            self.status_index_dirty = True

        elif storage_type == 'filesystem':
            storage_path = self.config.get('alerter.status_storage_path', '')
            assert storage_path, "For status_storage 'filesystem' you must configure 'status_storage_path' "

            path = "{}/{}-{}-latest.yaml".format(storage_path, type, key)
            path = "{}/{}-{}-latest.yaml".format(storage_path, type, key)

            with open(path, 'w') as f:
                json.dump(rule, f)

            # for history
            dt = dt_isoformat(timestamp, '_', 'seconds')
            path = "{}/{}-{}-{}.json".format(storage_path, type, key, dt)
            with open(path, 'w') as f:
                json.dump(rule, f)

        elif storage_type == 'memory':
            if type not in self.STATUS:
                self.STATUS[type] = {}
            self.STATUS[type][key] = rule

    def read_status(self, rule=None, key=None, type=None):
        storage_type = self.config.get('alerter.status_storage', 'memory')

        if key is None:
            key  = rule.get('key')
        if type is None:
            type = rule.get('type')

        log.debug("read_status storage_type=%r, key=%r, type=%s", storage_type, key, type)

        if storage_type == 'elasticsearch':
            if self.status_index_dirty:
                self.refresh_status_storage_index()

            results = self.es.search(index="elastico-alerter-*", body={
                'query': {'bool': {'must': [
                    {'term': {'key': key}},
                    {'term': {'type': type}}
                ]}},
                'sort': [{'@timestamp': 'desc'}],
                'size': 1
            })

            if results['hits']['total']:
                result = results['hits']['hits'][0]['_source']
                if 'match' in result:
                    try:
                        result['match'] = json.loads(result['match'])
                    except:
                        pass
                if 'match_query' in result:
                    try:
                        result['match_query'] = json.loads(result['match_query'])
                    except:
                        pass
                return result

            else:
                return None

        elif storage_type == 'filesystem':
            storage_path = self.config.get('alerter.status_storage_path')
            assert storage_path, "For status_storage 'filesystem' you must configure 'status_storage_path' "
            path = "{}/{}-{}-latest.yaml".format(storage_path, type, key)
            with open(path, 'r') as f:
                return json.load(f)

        elif storage_type == 'memory':
            return self.STATUS.get(type, {}).get(key)


    def do_alert(self, alert_data, all_clear=False):
        notifier = Notifier(self.config, alert_data, prefixes=['alerter'])

        # set future status
        if all_clear:
            alert_data['status'] = 'ok'
            subject = alert_data.getval('subject.ok', '')
        else:
            alert_data['status'] = 'alert'
            subject = alert_data.getval('subject.alert', '')

        if isinstance(alert_data.get('subject'), string):
            subject = alert_data.getval('subject')

        if not subject:
            type = alert_data['type']
            name = alert_data['name']
            status  = alert_data['status'].upper()
            subject = '[elastico] {} - {} {}'.format(status, type, name)

        # remove_subject = False
        # if 'message.subject' not in alert_data:
        #     remove_subject = True
        #     alert_data['message.subject'] = subject
        #
        log.info("      notification subject %s", subject)
        notifier.notify(subject=subject)

    def get_query(self, rule, name):
        body = None
        query = rule.getval(name)

        # list of filters
        if isinstance(query, list):
            filters = query

        # lucene query string
        if isinstance(query, string):
            filters = [{'query_string': {'query': query.strip()}}]

        # complete search body (including timerange, if any)
        if isinstance(query, dict):
            return query

        timestamp_field = rule.getval('timestamp_field', '@timestamp')
        timeframe = rule.getval('timeframe', {'minutes': 15})

        if 'endtime' in rule:
            endtime = to_dt(rule.getval('endtime'))
        else:
            endtime = to_dt(self.config['at'])

        if 'starttime' in rule:
            starttime = to_dt(rule.getval('starttime'))
        else:
            starttime = endtime - timedelta(**timeframe)

        starttime = dt_isoformat(starttime, 'T', 'seconds')#+"Z"
        endtime   = dt_isoformat(endtime, 'T', 'seconds')#+"Z"

        return {
            'query': {'bool': {'must': [
                    {'range': {timestamp_field: {'gte': starttime, 'lte': endtime}}}
                ] + filters
                }},
            'sort': [{timestamp_field: 'desc'}],
            'size': 1
        }


    def do_match(self, rule):
        body = self.get_query(rule, 'match')
        index = rule.get('index')
        body['size'] = 1

        assert index, "index must be present in rule %s" % rule.getval('name')
        rule['match_query'] = body

        key = rule.getval('key')
        type = rule.getval('type')

        results = self.es.search(index=index, body=body)
        log.debug("results: %s", results)
        rule['match_hits_total'] = results['hits']['total']
        if rule['match_hits_total']:
            rule['match_hit'] = Config.object(results['hits']['hits'][0])


        # there should be at least min_matches
        min_total = rule.get('matches_min')
        # there should be at most max_matches
        max_total = rule.get('matches_max')
        # ... otherwise we will alert

        # first check if totals are within given bounds
        _result = False
        if min_total is None and max_total is None:
            _result = results['hits']['total'] > 0
        if min_total is not None and max_total is not None:
            _result = results['hits']['total'] >= min_total
            _result = _result and results['hits']['total'] <= max_total

        elif min_total is not None:
            _result = _result or results['hits']['total'] >= min_total

        elif max_total is not None:
            _result = _result or results['hits']['total'] <= max_total

        log.info("match -- key=%r type=%r hits=%r min=%r max=%r trigger=%r "
            "index=%r match_query=%s",
            key, type, results['hits']['total'], min_total, max_total, _result,
            index, json.dumps(rule['match_query']))

        rule['alert_trigger'] = _result
        return _result


    def do_some_command(self, kwargs, rule=None):
        log.debug("do_some_command: kwargs=%s, rule=%s", kwargs, rule)

        if isinstance(kwargs, string):
            kwargs = {'args': kwargs, 'shell': True}
        elif isinstance(kwargs, (list, tuple)):
            kwargs = {'args': kwargs}

        def _get_capture_value(name):
            if name in kwargs:
                return kwargs.pop(name)
            elif rule is not None:
                return rule.get(name)
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

        log.debug("run_command: kwargs=%s", kwargs)

        p = Popen(stdout=PIPE, stderr=PIPE, **kwargs)
        (stdout, stderr) = p.communicate(input)
        result = p.wait()

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

    def do_command_succeeds(self, alert_data):
        cmd = alert_data.getval('command_succeeds')
        (result, stdout, stderr) = self.do_some_command(cmd, alert_data)

        expect_code = alert_data.get('expect.code', 0)

        log.info("command_succeeds -- "
            "cmd=%r result=%r expect=%r stdout=%r stderr=%r",
            cmd, result, expect_code, stripped(stdout), stripped(stderr))

        _result = not (result == expect_code)
        alert_data['alert_trigger'] = _result
        return _result

    def do_command_fails(self, alert_data):
        cmd = alert_data.get('command_fails')
        (result, stdout, stderr) = self.do_some_command(cmd, alert_data)

        expect_code = alert_data.get('expect.code', 0)

        log.info("command_fails -- "
            "cmd=%r result=%r expect=%r stdout=%r stderr=%r",
            cmd, result, expect_code, stripped(stdout), stripped(stderr))

        _result = not (result != expect_code)
        alert_data['alert_trigger'] = _result
        return _result

    def check_alert(self, alert_data, status=None):
        if not isinstance(alert_data, Config):
            alert_data = Config(alert_data)
        _key = alert_data.get('key')
        logger_name = alert_data.getval('logger', 'elastico.alerter.%s' % _key)
        log = logging.getLogger(logger_name)

        if status is None:
            # get last status of this alert_data
            last_rule = self.read_status(alert_data)

            if last_rule is not None:
                status = last_rule['status']
            log.debug("current_status=%r", last_rule)

        if status is None:
            alert_data['status'] = 'ok'
        else:
            alert_data['status'] = status

        need_alert = False
        if 'command_fails' in alert_data:
            need_alert = need_alert or self.do_command_fails(alert_data)

        if 'command_succeeds' in alert_data:
            need_alert = need_alert or self.do_command_succeeds(alert_data)

        if 'match' in alert_data:
            need_alert = need_alert or self.do_match(alert_data)

        if need_alert:
            log.warning("need alert -- name=%r, status=%r", alert_data.getval('name'), status)
            # new status = alert
            if status == 'alert' and last_rule:
                 delta = timedelta(**alert_data.get('realert', {'minutes': 60}))
                 wait_time = delta - ( to_dt(self.config['at']) -
                    to_dt(last_rule['@timestamp']) )
                 log.debug("delta=%r wait_time=%r", delta, wait_time)

                 if wait_time > timedelta(0):
                     alert_data['status'] = 'wait-realert'
                     log.warning("      trigger alert -> wait for realert (%s)", wait_time)
                     return alert_data

            log.info("      trigger alert")
            self.do_alert(alert_data)

        else:
            if status == 'alert':
                log.info("      trigger ok")
                self.do_alert(alert_data, all_clear=last_rule)
            else:
                log.info("      trigger nothing")

        if not alert_data.get('dry_run'):
            self.write_status(alert_data)

        # here we can expand everything

        # check result and log

        return alert_data

    def process_rules(self, action=None, **arguments):
        if 'arguments' not in self.config:
            self.config['arguments'] = {}

        self.config['arguments'].update(arguments)
        rules = self.config.get('alerter.rules', [])
        log.debug("rules: %s", rules)

        for rule in rules:
            if not rule: continue

            log.debug("rule: %s", rule)

            if isinstance(rule, string):
                rule = rules[rule]

            rule = self.config.assimilate(rule)
            # TODO: why is assimilate needed here?  should already be done

            _class_name = rule.getval('class')
            if _class_name is None:
                _class_name = rule.getval('name')

            log.debug("rule: %s", rule)
            log.info("=== RULE <%s> =========================", _class_name)

            self.process(rule, action=action)

        if self.es:
            self.refresh_status_storage_index()

    ALIAS = re.compile(r"^\s*\*(\w+)(\.\w+)*(\s+\*(\w+)(\.\w+)*)*\s*$")
    def process(self, rule, action=None):
        log = globals()['log']

        has_foreach = False

        # create a product of all items in 'each' to multiply the rule
        if 'foreach' in rule:
            data_list = []

            for key,val in rule.get('foreach', {}).items():
                log.debug("key: %s, val: %s", key, val)

                # maybe format the values
                key = rule.format(key)

                # expand *foo.bar values.
                if isinstance(val, string):
                    val = rule.format(val)

                    log.debug("val is aliases candidate")
                    _value = []
                    if self.ALIAS.match(val):
                        log.debug("there are aliases: %s", val)

                        _refs = val.strip().split()
                        for _ref in _refs:
                            _val = rule.get(_ref[1:])

                            if _val is None:
                                _val = self.config.get(_ref[1:])

                            assert _val is not None, "could not resolve reference %s mentioned in rule %s" % (_ref, rule['name'])
                            _value += _val

                        val = _value
                    else:
                        log.debug("no aliases: %s", val)

                #if val == '@'
                data_list.append([{key: rule.format(v)} for v in val])

            data_sets = product(*data_list)

            has_foreach = True

        else:
            data_sets = [({},)]

        visited_keys = []


        for data_set in data_sets:
            log.debug("data_set: %s", data_set)

            r = Config.object()

            # # copy config's data section
            # r.update(deepcopy(self.config.get('data', {})))
            #
            # # copy alerter's data section
            # r.update(deepcopy(self.config.get('alerter.data', {})))

            # copy arguments
            r.update(deepcopy(self.config.get('arguments', {})))

            # for k,v in self.config.items():
            #     if k.endswith('_defaults'): continue
            #     if k in ('arguments', 'alerter', 'digester'): continue
            #     r[k] = deepcopy(v)

            # get defaults
            defaults = self.config.get('alerter.rule_defaults', {})
            _class = rule.get('class', 'default')

            log.debug("rule class: %s", _class)
            _defaults = defaults.get(_class, {})

            log.debug("rule defaults: %s", _defaults)
            r.update(deepcopy(_defaults))

            # update data from rule
            r.update(deepcopy(rule))

            for data in data_set:
                r.update(deepcopy(data))

            _name = r.getval('name')
            _key  = r.getval('key')
            if not _key:
                _key = re.sub(r'[^\w]+', '_', _name.lower())

            # overrides from arguments
            #r.update(self.config.get('alerter.rule.%s', {}))

            logger_name = r.getval('logger', 'elastico.alerter.%s' % _key)
            log = logging.getLogger(logger_name)

            log.info("--- rule %s", _name)

            _alerts = get_alerts(r.get('alerts', []), context=r)

            for alert in _alerts:
                log.debug("process alert %s", alert)
                alert_data = Config.object()

                assert 'type' in alert

                _type = alert_data.format(alert['type'])

                defaults = self.config.get('alerter.alert_defaults', {})
                alert_data.update(deepcopy(defaults.get(_type,{})))

                defaults = r.get('alert_defaults', {})
                alert_data.update(deepcopy(defaults.get(_type,{})))

                alert_data.update(r)

                alert_data.update(alert)
                alert_data = alert_data.format()

                if 'alerts' in alert_data:
                    del alert_data['alerts']

                log.debug("alert_data (alert): %s", alert_data)

                _r_name = r.getval('name')

                if 'key' not in alert_data:
                    alert_data['key'] = re.sub(r'[^\w]+', '_', _r_name.lower())

                _key = alert_data.get('key')

                log.info("----- alert %s-%s?", _type, _key)

                visit_key = (_type, _key)
                assert visit_key not in visited_keys, \
                    "key %s already used in rule %s" % (_key, _r_name)

                assert 'match' in alert_data or 'no_match' in alert_data \
                    or 'command_succeeds' in alert_data \
                    or 'command_fails' in alert_data, \
                    "rule %s does not have a check defined" % _r_name

                log.debug("alert_data: %s", alert_data)

                # check only every now and then. default 5min
                every = timedelta(**alert_data.get('every', {'minutes': 5}))
                now = to_dt(self.config['at'])
                last_check = Alerter.LAST_CHECK.get(visit_key, now - every - timedelta(seconds=1))

                if (now - every) > last_check:
                    if action:
                        action(alert_data)
                    else:
                        self.check_alert(alert_data)

                    Alerter.LAST_CHECK[visit_key] = now
                else:
                    log.info("      next check in %s", every - (now-last_check))

            if not _alerts and action:
                action(rule)

    @classmethod
    def run(cls, config):
        '''run alerter
        '''

        from .connection import elasticsearch
        es = elasticsearch(config)

        sleep_seconds = config.get('sleep_seconds')
        alerter = Alerter(es, config)
        if sleep_seconds:
            while True:
                try:
                    alerter.process_rules()
                    time.sleep(sleep_seconds)
                except Exception as e:
                    log.error("exception occured while processing rules: %s", e)
        else:
            alerter.process_rules()

    @classmethod
    def expand_rules(cls, config):
        '''expand alert rules
        '''
        RULES = []
        def collect_rules(rule):
            RULES.append(rule.format())
            return rule

        Alerter(None, config).process_rules(action=collect_rules)
        return RULES

