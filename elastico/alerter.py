"""alerter -- a simple alerter module

"""

from datetime import datetime, timedelta
from dateutil.parser import parse as dt_parse
from itertools import product
from subprocess import Popen, PIPE
from copy import deepcopy
from .notifier import Notifier
from itertools import chain

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
    STATUS     = {}

    @classmethod
    def reset_last_check(cls):
        Alerter.LAST_CHECK = {}

    @classmethod
    def reset_status(cls):
        Alerter.STATUS = {}

    def __init__(self, es_client=None, config={}, config_base="alerter"):
        self.es = es_client
        self.config = config
        self.status_index_dirty = False
        self._refreshed = {}

    def wipe_status_storage(self):
        '''remove all status storages'''
        result = self.es.indices.delete('elastico-alerter-*')
        log.debug("wipe_status_storage: %s", result)
        return result

    def get_status_storage_index(self):
        date = self.now()
        return date.strftime('elastico-alerter-%Y-%m-%d')

    def refresh_status_storage_index(self):
        if self.es:
            try:
                self.es.indices.refresh(self.get_status_storage_index())
            except:
                pass

    def now(self):
        now = to_dt(self.config.get('at', datetime.utcnow()))
        log.debug("now: %s", now)
        return now

    def write_status(self, rule): #,
        # if self.config.get('dry_run'):
        #     return

        #doc_type="_doc"
        doc_type='elastico_alert_status'
        storage_type = self.config.get('alerter.status_storage', 'memory')

        #rule['@timestamp'] = to_dt(self.get_rule_value(rule, 'run_at', now))
        rule['@timestamp'] = timestamp = dt_isoformat(self.now())
        if 'at' in rule:
            rule['at'] = dt_isoformat(rule['at'])

        # import socket
        # rule['elastico.hostname'] = socket.gethostname()

        # get data, which is written to any status
        _status = Config(self.config.get('status_data'))
        _status.update(self.config.get('alerter.status_data'))
        rule.update(_status)

        log.debug("rule to write to status: %s", rule)
        log.debug("storage_type=%r", storage_type)

        key  = rule.get('key')
        type = rule.get('type')

        if self.config.get('dry_run'):
            # do nothing
            pass

        elif storage_type == 'elasticsearch':
            index = self.get_status_storage_index()
            # if not self.indices.exists(index):
            #     self.indices.create(index=index,body={
            #         "mappings": {
            #             doc_type: {
            #                 "properties": {
            #                     "type": {
            #                         "type": "keyword",
            #                     },
            #                     "key": {
            #                         "type"
            #                     }
            #                 }
            #             }
            #         }
            #     })

            #_rule = Config.object(rule).format_value()
            if 'match' in rule and not isinstance(rule['match'], string):
                rule['match'] = json.dumps(rule['match'])
            if 'match_query' in rule and not isinstance(rule['match_query'], string):
                rule['match_query'] = json.dumps(rule['match_query'])

            result = self.es.index(index=index, doc_type=doc_type, body=rule)
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

    #    elif storage_type == 'memory':

        if type not in Alerter.STATUS:
            Alerter.STATUS[type] = {}
        Alerter.STATUS[type][key] = rule
        log.debug("set status. type=%r key=%r", type, key)


# Get latest entry in INDEX
# POST elastico-alerter-*/_search
# {
#   "query": {
#     "match_all": {}
#   },
#   "sort": {
#     "@timestamp": "desc"
#   },
#   "size": 1
# }
#     #

# Get all entries at latest run
#
# POST elastico-alerter-*/_search
# {
#   "query": {
#     "term": {
#       "@timestamp":"2018-09-09T07:35:27Z"
#     }
#   }
# }

    def read_status(self, rule=None, key=None, type=None, filter=[]):
        storage_type = self.config.get('alerter.status_storage', 'memory')
        doc_type = 'elastico_alert_status'
        if key is None:
            key  = rule.get('key')
        if type is None:
            type = rule.get('type')

        log.debug("read_status storage_type=%r, key=%r, type=%s", storage_type, key, type)

        # return cached status
        result = Alerter.STATUS.get(type, {}).get(key)
        if result is not None:
            return result

        if storage_type == 'elasticsearch':
            if self.status_index_dirty:
                self.refresh_status_storage_index()

            results = self.es.search(index="elastico-alerter-*",
                doc_type=doc_type, body={
                'query': {'bool': {'must': [
                    {'term': {'key': key}},
                    {'term': {'type': type}}
                ]+filter}},
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
            else:
                return None

        elif storage_type == 'filesystem':
            storage_path = self.config.get('alerter.status_storage_path')
            assert storage_path, "For status_storage 'filesystem' you must configure 'status_storage_path' "
            path = "{}/{}-{}-latest.yaml".format(storage_path, type, key)
            with open(path, 'r') as f:
                result = json.load(f)

        if result is not None:
            # update cache
            if type not in self.STATUS:
                self.STATUS[type] = {}
            self.STATUS[type][key] = result

        return result


    def assert_key(self, data, name=None):
        if name is None:
            if hasattr(data, 'getval'):
                name = data.getval('name')
            else:
                name = data['name']

        if 'key' not in data:
            data['key'] = re.sub(r'[^\w]+', '_', name.lower())

        return data.get('key')

    def notify_alert(self, alert_data, all_clear=False):
        log.debug("notify_alert -- alert_data=%r", alert_data)
        notifier = Notifier(self.config, alert_data, prefixes=['alerter'])

        # set future status
        # if all_clear:
        #     alert_data['status.current'] = 'ok'
        #     subject = alert_data.getval('subject.ok', '')
        # else:
        #     alert_data['status.current'] = 'alert'
        #     subject = alert_data.getval('subject.alert', '')

        #if isinstance(alert_data.get('message.subject'), string):
        subject = alert_data.getval('message.subject', '')

        if not subject:
            type = alert_data.getval('type')
            name = alert_data.getval('name')
            status  = alert_data['status.current'].upper()
            subject = '[elastico] {} - {} {}'.format(status, type, name)

        # remove_subject = False
        # if 'message.subject' not in alert_data:
        #     remove_subject = True
        #     alert_data['message.subject'] = subject
        #
        log.info("      notification subject=%r", subject)
        notifier.notify(subject=subject)

    do_alert = notify_alert


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
            endtime = self.now()


        if 'starttime' in rule:
            starttime = to_dt(rule.getval('starttime'))
        else:
            starttime = endtime - timedelta(**timeframe)

        log.debug("starttime=%s endtime=%s", starttime, endtime)

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


    def _refresh_index(self, index):
        '''make sure index is refreshed at least every 2 minutes'''
        if self.es:
            if index not in self._refreshed:
                self._refreshed[index] = datetime.utcnow() - timedelta(minutes=3)

            if self._refreshed[index] + timedelta(minutes=2) < datetime.utcnow():
                self.es.indices.refresh(index)
                self._refreshed[index] = datetime.utcnow()

                log.info("refreshed index %s", index)


    def check_match(self, trigger, rule):
        log.debug('check_match trigger=%r rule=%r', trigger, rule)
        _rule = deepcopy(rule)
        _rule.update(trigger)
        _rule = Config(_rule)

        body = self.get_query(_rule, 'match')
        log.debug("query body: %r", body)
        index = rule.get('index')
        body['size'] = 1

        assert index, "index must be present in rule %s" % rule.getval('name')
        trigger['match_query'] = body

        key = rule.getval('key')
        type = rule.getval('type')

        if self.es:
            self._refresh_index(index)
            results = self.es.search(index=index, body=body)
            log.debug("results: %s", results)
            trigger['match_hits_total'] = results['hits']['total']
            if trigger['match_hits_total']:
                trigger['match_hit'] = Config.object(results['hits']['hits'][0])
        else:
            trigger['match_hits_total'] = 0
            results = {'hits': {'total': 0}}

        # there should be at least min_matches
        min_total = trigger.get('matches_min')
        # there should be at most max_matches
        max_total = trigger.get('matches_max')
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

        trigger['alert_trigger'] = _result
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

    def check_command(self, trigger, data):
        cmd = data.format(trigger.get('command'), trigger)
        (result, stdout, stderr) = self.do_some_command(cmd, trigger)
        data['alert_trigger'] = result != 0
        return result

    def check_require(self, items, default, invert, data):
        _result = default
        for k,v in sorted(items):
            if k == 'require': continue
            if invert:
                if not self.check_trigger(v, data):
                    _result = result
                    break
            else:
                if self.check_trigger(v, data):
                    _result = result
                    break
        return _result


    def perform_check(self, trigger, alert_data):
        need_alert = self.check_conditions(alert_data)

        log.debug("trigger=%r alert_data=%r", trigger, alert_data)

        if need_alert is not None:
            #trigger['alert_precondition']
            return need_alert

        if 'check' in alert_data:
            return self.check(alert_data['check'], alert_data)

        require = trigger.get('require')
        if require:
            items = trigger.items()
            if require == 'all':
                result = self.check_require(items, default=True, invert=True, data=alert_data)
                trigger['alert_trigger'] = result
                return result

            elif require == 'any':
                result = self.check_require(items, default=False, invert=False, data=alert_data)
                trigger['alert_trigger'] = result
                return result

            elif require == 'none':
                result = self.check_require(items, default=True, invert=False, data=alert_data)
                trigger['alert_trigger'] = result
                return result

            elif require == 'match':
                return self.check_match(trigger, alert_data)

            elif require == 'command':
                return self.check_command(trigger, alert_data)

            elif require == 'time':
                return self.check_time(trigger, alert_data)

            raise ValueError("cannot handle require %r" % require)

        else:
            # match or command
            if 'match' in trigger:
                return self.check_match(trigger, alert_data)
            elif 'command' in trigger:
                return self.check_command(trigger, alert_data)


    def check_conditions(self, alert_data):
        '''This checks conditions, and returns either False, if there is no
        alert needed or None, such that there are checked the other conditions.
        '''

        # alert conditions
        need_alert = None

        def _get_list(key):
            val = alert_data.getval(key, [])
            if not isinstance(val, list):
                val = [val]
            return val

        def _check_if(if_list, name, default, result, check_ok):
            if not if_list:
                return None

            log.debug("check name=%r default=%r result=%r check_ok=%r", name, default, result, check_ok)
            _condition_met = default
            for condition in if_list:
                log.debug("check name=%r condition=%r, check_ok=%r", name, condition, check_ok)
                if '.' in condition:
                    _r_key, _a_type = condition.rsplit('.', 1)
                    _status = self.read_status(key=_r_key, type=_a_type)
                    log.debug("check name=%r condition=%r check_ok=%r status=%r", name, condition, check_ok, _status['status']['current'])
                    if check_ok:
                        if _status['status']['current'] == 'ok':
                            _condition_met = result
                            log.debug("check status='ok' result=%r", result)
                            break
                        else:
                            log.debug("check status='alert'")
                    else:
                        if _status['status']['current'] != 'ok':
                            _condition_met = result
                            log.debug("check status='alert' result=%r", result)
                            break
                        else:
                            log.debug("check status='ok'")
                else:
                    # a rule is in alert if there is any alert active
                    _status = self.read_status(key=condition, type='rule')
                    log.debug("check name=%r condition=%r check_ok=%r alerts=%r", name, condition, check_ok, _status['alerts'])
                    if check_ok:
                        if len(_status['alerts']) == 0:
                            _condition_met = result
                            log.debug("check alerts=[] result=%r", result)
                            break
                        else:
                            log.debug("check alerts=%r result=%r", _status['alerts'], result)
                    else:
                        if len(_status['alerts']) > 0:
                            _condition_met = result
                            log.debug("check alerts=%r result=%r", _status['alerts'], result)
                            break
                        else:
                            log.debug("check alerts=[]")

            log.debug("_condition_met=%r", _condition_met)

            if _condition_met is True:
                return None
            else:
                alert_data['alert_condition_fails'] = name
                return False

        if need_alert is None:
            # check if all are True => if one is ok, result is False
            need_alert = _check_if(
                _get_list('if') + _get_list('if-all'),
                name='if-all',
                # if all are in alert, condition is met
                default=True, check_ok=True, result=False
            )
            log.info("if-all: need_alert=%s", need_alert)

        if need_alert is None:
            # check if at least one is true
            # => starting with True, if one is alert result is True
            need_alert = _check_if(
                _get_list('if-any'),
                name='if-any',
                # at last one is in alert mode
                default=False, check_ok=False, result=True
            )
            log.info("if-any: need_alert=%s", need_alert)

        if need_alert is None:
            # if-none is met, if all statuses are "ok"
            need_alert = _check_if(
                _get_list('if-not') + _get_list('if-none'),
                name='if-none',
                default=True, check_ok=False, result=False
            )
            log.info("if-none: need_alert=%s", need_alert)

        if need_alert is None:
            now = self.now()
            if 'if-before' in alert_data:
                before = to_dt(alert_data['if-before'], default=now)
                if now >= before:
                    need_alert = False

            if 'if-after' in alert_data:
                after = to_dt(alert_data['if-after'], default=now)
                if now < after:
                    need_alert = False

        log.info("check_conditions: need_alert=%s", need_alert)

        return need_alert


    def check_alert(self, alert_data, status=None):
        if not isinstance(alert_data, Config):
            alert_data = Config(alert_data)

        _key = alert_data.get('key')

        logger_name = alert_data.getval('logger', 'elastico.alerter.%s' % _key)
        log = logging.getLogger(logger_name)

        log.debug("check_alert")

        if status is None:
            # get last status of this alert_data
            last_rule = self.read_status(alert_data)

            if last_rule is not None:
                if isinstance(last_rule['status'], string):
                    status = last_rule['status']
                else:
                    status = last_rule['status']['current']
            log.debug("current_status=%r", last_rule)

        if status is None:
            alert_data['status.previous'] = 'ok'
            alert_data['status.current']  = 'ok'
        else:
            alert_data['status.previous'] = status
            alert_data['status.current'] = status

        need_alert = self.perform_check(alert_data, alert_data)

        log.debug("checks performed -- name=%r, status=%r, need_alert=%r, alert_data=%r", alert_data.getval('name'), status, need_alert, alert_data)
        if not need_alert:
            alert_data['status.current'] = 'ok'
        else:
            alert_data['status.current'] = 'alert'

            log.warning("need alert -- name=%r, status=%r", alert_data.getval('name'), status)
            # new status = alert
            if status != 'ok' and last_rule:
                realert = alert_data.get('realert', {'minutes': 60})

                if realert['enabled'] is False:
                    if 'status.realert' in alert_data:
                        alert_data['status.realert'] = -1

                    return alert_data
                # else it is assumed, that realert is a dictionary, which can
                # be passed to timedelta

                # calculate wait time till next re-alert
                now = self.now()
                try:
                    delta = timedelta(seconds=int(last_rule['status']['realert']))
                except Exception as e:
                    log.error("error", exc_info=1)
                    delta = timedelta(**realert)

                time_passed = now - to_dt(last_rule['@timestamp'])

                log.info("delta=%r time_passed=%r", delta, time_passed)

                # if there is still wait time left,
                if delta > time_passed:
                    wait_time = delta - time_passed
                    log.info("wait_time=%r", wait_time)

                    #alert_data['status.realert'] = 'wait'
                    alert_data['status.realert'] = wait_time.total_seconds()
                    log.warning("      trigger alert -> wait for realert (%s)", wait_time)
                    return alert_data

                else:
                    if alert_data['status.previous'] != 'ok':
                        alert_data['status.current'] = 'realert'
                    alert_data['status.realert'] = 0
                    log.warning("      trigger alert -> %s", alert_data['status.current'])

        return alert_data

    def iterate_alerts(self):
        visited = set()
        for rule in self.iterate_rules():
            alerts = []
            for alert in self.get_rule_alerts(rule):
                self.validate_alert(alert, visited_keys=visited)
                alerts.append(alert)

            yield (rule, alerts)

    def alert_init_status(self, alert):
        log.debug("alert_init_status: %s", alert.__class__.__name__)
        alert_status = Config(self.read_status(alert))

        now = self.now()
        every = timedelta(**alert.get('every', {'minutes': 1}))

        # initialize new status
        if alert_status:
            #last_check = self.now()
            last_check = to_dt(alert_status['@timestamp'])
            log.debug("alert_status=%r", alert_status)
            alert['status.previous'] = alert_status['status.current']
            alert['status.current'] = alert_status['status.current']
        else:
            last_check = None
            alert['status.current'] = alert['status.previous'] = 'ok'

        log.debug("last_check=%r", last_check)

        # do next check, if needed
        if last_check is None or (now - every) >= last_check:
            alert['status.next_check'] = 0
        else:
            next_check = (every - (now-last_check))
            alert['status.next_check'] = next_check.total_seconds()
            log.info("      next check in %s", next_check)

        return alert

    def rule_init_status(self, rule):
        rule_status = self.read_status(type='rule', key=rule['key'])
        if rule_status is None:
            rule_status = {}
        rule_status['key'] = rule['key']
        rule_status['type'] = 'rule'
        rule_status['name'] = rule.getval('name')

        return Config(rule_status)


    def check_alerts(self):
        self._refreshed = {}
        log.debug("check_alerts")

        rules = self.config.get('alerter.rules', [])
        now = self.now()

        for rule, alerts in self.iterate_alerts():

            for alert in alerts:
                self.alert_init_status(alert)

                if alert['status.next_check'] == 0: # no wait time, so now
                    self.check_alert(alert)
                else:
                    log.debug("next check: %s", alert['status.next_check'])

            rule_status = self.rule_init_status(rule)

            was_ok = all([ a['status.previous'] == 'ok' for a in alerts])
            now_ok = all([ a['status.current'] == 'ok' for a in alerts])
            was_alert = lambda a: a['status.previous'] != 'ok'
            was_alert = [ x for x in filter(was_alert, alerts)]
            now_alert = not now_ok

            log.debug("was_ok=%r now_ok=%r was_alert=%r", was_ok, now_ok, was_alert)

            if was_ok and not now_ok:
                rule_status['status.start'] = dt_isoformat(now)
                rule_status['status.id'] = '{}_{}'.format(
                    rule_status['key'], rule_status['status.start'])

            # helper function to always return a list (if string or list)
            def _get_list(D,n):
                l = D.get(n, [])
                if not isinstance(l, list):
                    l = [l]
                return l


            # update list of notifications done on this rule
            if was_ok:
                done_notify = []
            else:
                done_notify = _get_list(rule_status, 'trigger')

            notify_lists = [_get_list(a, 'trigger') for a in was_alert]
            done_notify = list(set(chain(done_notify, *notify_lists)))
            rule_status['trigger'] = done_notify

            # update list of alerts done on this rule
            if was_ok:
                done_alerts = []
            else:
                done_alerts = _get_list(rule_status, 'alerts')
            alerts_list = [ a['type'] for a in was_alert ]
            done_alerts = list(set(chain(done_alerts, alerts_list)))
            rule_status['alerts'] = done_alerts

            # get severity of the alert
            S = self.config['alerter'].get('severity', {})
            severity = max([ a['status.current'] != 'ok' and S.get(a['type'], 1) or S.get('ok', 0) for a in alerts ]    )
            rule_status['status.severity'] = severity

            if was_alert and now_ok:
                # have to send all-clear for this rule
                rule_status['status.end'] = dt_isoformat(now)
                all_clear = self.init_all_clear(rule, rule_status['trigger'])
                self.do_alert(all_clear)
                rule_status['all_clear'] = all_clear

            for alert in alerts:
                if 'status' not in alert:
                    alert['status'] = {}

                alert['status'].update(rule_status.get('status', {}))

                if was_ok and now_alert:
                    status_current = alert['status.current']
                    status_realert = alert.get('status.realert')

                    if status_current != 'ok' and not status_realert:
                        self.do_alert(alert)

                self.write_status(alert)

            self.write_status(rule_status)

        if self.es:
            self.refresh_status_storage_index()


    ALIAS = re.compile(r"^\s*\*(\w+)(\.\w+)*(\s+\*(\w+)(\.\w+)*)*\s*$")

    def get_rule_datasets(self, rule):
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

        else:
            data_sets = [({},)]

        return data_sets

    def waiting_process(self, visited, waiting):
        for key,val in [item for item in waiting.items()]:
            done = True
            # make sure, that all prerequisites are visited before
            for dep in val['depends']:
                if dep not in visited:
                    done = False
                    break
            if done:
                yield val['item']
                del waiting[key]

    def waiting_add(self, key, item, waiting, dependencies):
        dep = dependencies
        if dep:
            if isinstance(dep, string):
                dep = [dep]
            waiting[key] = {
                'item': item,
                'depends': set(dep)
                }
            return True
        return False

    def iterate_rules(self):
        rule_waiting = {}
        visited = set()

        for raw_rule in self.iterate_raw_rules():
            log.debug("raw rule: %r", raw_rule)
            for rule in self.expand_raw_rule(raw_rule):
                # get rule level prerequisites
                prerequisites = rule.get('depends', [])
                log.debug("expanded rule: %r", rule)

                # get alert-level prerequisites and transform to rule level
                for alert_name, alert in rule.get('alerts', {}).items():
                    for condition in ('if', 'if-not'):
                        cond_deps = alert.get(condition, [])
                        if isinstance(cond_deps, string):
                            cond_deps = [cond_deps]

                        prerequisites += [ cd.rsplit('.', 1)[0]
                                            for cd in cond_deps ]

                key = rule.getval('key')
                if self.waiting_add(key, rule, rule_waiting, prerequisites):
                    continue
                visited.add(rule['key'])
                yield rule

        while rule_waiting:
            _before = len(rule_waiting)
            for rule in self.waiting_process(visited, rule_waiting):
                visited.add(rule['key'])
                yield rule
            _after = len(rule_waiting)
            assert _before != _after, "rules waiting for dependencies resolved did not reduce "

    def iterate_raw_rules(self):
        if 'arguments' not in self.config:
            self.config['arguments'] = {}

        rules = self.config.get('alerter.rules', [])

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

        #    self.process(rule, action=action)
#            log = globals()['log']

#            now = self.now()

            yield rule

    def expand_raw_rule(self, rule):
        data_sets = self.get_rule_datasets(rule)

        for data_set in data_sets:
        #    self.compose_rule(rule, data_set)

            log.debug("data_set: %s", data_set)

            r = Config.object()

            # # copy config's data section
            # r.update(deepcopy(self.config.get('data', {})))
            #
            # # copy alerter's data section
            # r.update(deepcopy(self.config.get('alerter.data', {})))

            # copy arguments

            # TODO: do not copy arguments!!!
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

            if 'foreach' in r:
                del r['foreach']

            for data in data_set:
                r.update(deepcopy(data))

            _name = r.getval('name')
            _key = self.assert_key(r, _name)
            _disabled = self.config.get('alerter.disabled', [])
            log.warning('key=%r disabled=%r', _key, _disabled)
            if _key in _disabled:
                log.warning('msg="rule %s disabled => skipping" key=%r', _name, _key)
                # TODO: maybe put also skipped rules as "skipped" into index
                continue

            yield r

            # overrides from arguments
            #r.update(self.config.get('alerter.rule.%s', {}))

    def get_rule_alerts(self, rule):
        _key = rule.getval('key')
        _name = rule.getval('name')
        logger_name = rule.getval('logger', 'elastico.alerter.%s' % _key)
        log = logging.getLogger(logger_name)

        log.info("rule=%r logger=%r", _name, logger_name)

        _alerts = deepcopy(rule.get('alerts', {}))

        collected_alerts = []

        for k,alert in _alerts.items():
            log.debug("process alert %s", alert)

            alert_data = Config.object()

            log.debug("get_rule_alerts 1: %s", alert_data.__class__.__name__)

            if 'type' not in alert:
                alert['type'] = k

            _type = alert_data.format(alert['type'])

            defaults = self.config.get('alerter.alert_defaults', {})
            alert_data.update(deepcopy(defaults.get(_type,{})))

            defaults = rule.get('alert_defaults', {})
            alert_data.update(deepcopy(defaults.get(_type,{})))

            alert_data.update(rule)

            alert_data.update(alert)
            alert_data = Config(alert_data.format())

            assert alert_data['type'] == _type, \
                "type has not been expanded in format :("

            assert alert_data['name'] == rule.getval('name'), \
                "name has not been expanded in format :("

            if 'alerts' in alert_data:
                del alert_data['alerts']

            log.debug("alert_data (alert): %s", alert_data)

            #_r_name = r.getval('name')
            _key = self.assert_key(alert_data)

            log.info("alert? -- key=%r, type=%r", _key, _type)

            log.debug("get_rule_alerts: %s", alert_data.__class__.__name__)

            yield alert_data

    def get_alert_type_key(self, alert_data):
        return alert_data['type'], alert_data['key']

    def get_alert_key_type(self, alert_data):
        return alert_data['key'], alert_data['type']

    def validate_alert(self, alert_data, visited_keys):
        visit_key = self.get_alert_type_key(alert_data)

        assert visit_key not in visited_keys, \
            "key %(key)r already used in rule %(name)r" % alert_data

        assert 'match' in alert_data or 'no_match' in alert_data \
            or 'command' in alert_data \
            or 'check' in alert_data, \
            "rule %(name)r does not have a check defined" % alert_data

        # assert 'severity' in alert_data, \
        #     "alert %(type)r in rule %(name)r has no severity defined" % alert_data

        log.debug("alert_data: %s", alert_data)
        return alert_data



    def init_all_clear(self, rule, notify):
        all_clear = Config.object()
        all_clear.update(rule)
        all_clear['type'] = 'all-clear'
        all_clear['status.current'] = 'ok'
        all_clear['trigger'] = notify
        self.assert_key(all_clear)
        all_clear.update(rule.get('all_clear', {}))
        log.info("all_clear=%r", all_clear)

        _all_clear = rule.get('all_clear')
        if _all_clear:
            all_clear.update(_all_clear)
            del all_clear['all_clear']

        #log.info("all_clear=%r", all_clear)
        return all_clear


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

