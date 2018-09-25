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
from .util import stripped, get_alerts, slugify

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

    def read_status(self, rule={}, key=None, type=None, filter=[]):
        storage_type = self.config.get('alerter.status_storage', 'memory')
        doc_type = 'elastico_alert_status'
        if key is None:
            key  = rule.get('key')
        if type is None:
            type = rule.get('type', 'rule')

        log_key = "func='read_status' key=%r type=%r" % (key, type)

        log.debug("%s storage_type=%r", log_key, storage_type)

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
            assert name is not None, "Name is not set in data=%s" % (data,)

            data['key'] = slugify(name, strip_=False, prefix_='x', suffix_='x')

        return data.get('key')

    def notify_alert(self, alert_data, all_clear=False):
        type = alert_data.getval('type')
        key = alert_data.getval('key')
        log_key = "func='notify_alert' key=%r type=%r" % (key, type)
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
        log.info("%s subject=%r", log_key, subject)
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
        log_key = "func='check_match' key=%(key)r type=%(type)r" % rule

        log.debug('%s trigger=%r rule=%r', log_key, trigger, rule)
        _rule = deepcopy(rule)
        _rule.update(trigger)
        _rule = Config(_rule)

        query_body = self.get_query(_rule, 'match')
        log.debug("%s query_body=%r", log_key, query_body)

        index = rule.get('index')
        query_body['size'] = 1

        assert index, "index must be present in rule %s" % rule.getval('name')
        trigger['match_query'] = query_body

        key = rule.getval('key')
        type = rule.getval('type')

        #test_data = self.config.get('alerter.test-data.{}.{}.match'.format(key,type))
        test_data = None
        if test_data:
            results = test_data
        elif self.es:
            self._refresh_index(index)
            results = self.es.search(index=index, body=query_body)
            log.debug("%s results=%r", log_key, results)
        else:
            results = {'hits': {'total': 0}}

        trigger['match_hits_total'] = results['hits']['total']
        if trigger['match_hits_total']:
            trigger['match_hit'] = Config.object(results['hits']['hits'][0])

        log.debug("%s match_hits_total=%r", log_key, trigger['match_hits_total'])

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

        log.info("%s msg='match' hits=%r min=%r max=%r alert_trigger=%r "
            "index=%r match_query=%s",
            log_key, results['hits']['total'], min_total, max_total, _result,
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
        #test_data = self.config.get('alerter.test-data.{}.{}.commandI#'.format(key,type))
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
        log_key = "func='perform_check' key=%(key)r type=%(type)r" % alert_data

        log.debug("%s need_alert=%r", log_key, need_alert)

        log.debug("%s trigger=%r alert_data=%r", log_key, trigger, alert_data)

        if need_alert is not None:
            alert_data['status.current'] = 'precondition'
            alert_data['status.precondition'] = need_alert
            #trigger['alert_precondition']
            return need_alert
        else:
            if 'precondition' in alert_data['status']:
                del alert_data['status.precondition']

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

            log_key = "func='_check_if' key=%r type=%r name=%r" % (
                alert_data.get('key'), alert_data.get('type'), name)

            log.debug("%s default=%r result=%r check_ok=%r",
                log_key, default, result, check_ok)

            _condition_met = default
            for condition in if_list:
                log.debug("%s condition=%r, check_ok=%r", log_key, condition, check_ok)
                if '.' in condition:
                    _r_key, _a_type = condition.rsplit('.', 1)
                    _r_key = slugify(_r_key)
                    _a_type = slugify(_a_type)

                    _status = self.read_status(key=_r_key, type=_a_type)
                    if not _status:
                        continue

                    log.debug("%s condition=%r check_ok=%r status_current=%r",
                        log_key, condition, check_ok,
                        _status['status']['current'])

                    if check_ok:
                        if _status['status']['current'] == 'ok':
                            _condition_met = result
                            log.debug("%s status='ok' result=%r", log_key, result)
                            break
                        else:
                            log.debug("%s status='alert'", log_key)
                    else:
                        if _status['status']['current'] != 'ok':
                            _condition_met = result
                            log.debug("%s status='alert' result=%r", log_key, result)
                            break
                        else:
                            log.debug("%s status='ok'", log_key)
                else:
                    _condition = slugify(condition)
                    # a rule is in alert if there is any alert active
                    _status = self.read_status(key=_condition, type='rule')
                    if not _status:
                        continue

                    log.debug("%s condition=%r check_ok=%r alerts=%r",
                        log_key, condition, check_ok, _status['alerts'])

                    if check_ok:
                        if len(_status['alerts']) == 0:
                            _condition_met = result
                            log.debug("%s alerts=[] result=%r", log_key, result)
                            break
                        else:
                            log.debug("%s alerts=%r result=%r",
                                log_key, _status['alerts'], result)
                    else:
                        if len(_status['alerts']) > 0:
                            _condition_met = result
                            log.debug("%s alerts=%r result=%r", log_key,
                                _status['alerts'], result)
                            break
                        else:
                            log.debug("%s alerts=[]", log_key)

            log.debug("%s _condition_met=%r", log_key, _condition_met)

            if _condition_met is True:
                result = None
            else:
                alert_data['alert_condition_fails'] = name
                result = False

            log.info("%s result=%r", log_key, result)
            return result

        log_key = "func='check_conditions' key=%r "\
                  "type=%r" % (alert_data.get('key'), alert_data.get('type'))

        if need_alert is None:
            # check if all are True => if one is ok, result is False
            need_alert = _check_if(
                _get_list('if') + _get_list('if-all'),
                name='if-all',
                # if all are in alert, condition is met
                default=True, check_ok=True, result=False
            )

        if need_alert is None:
            # check if at least one is true
            # => starting with True, if one is alert result is True
            need_alert = _check_if(
                _get_list('if-any'),
                name='if-any',
                # at last one is in alert mode
                default=False, check_ok=False, result=True
            )

        if need_alert is None:
            # if-none is met, if all statuses are "ok"
            need_alert = _check_if(
                _get_list('if-not') + _get_list('if-none'),
                name='if-none',
                default=True, check_ok=False, result=False
            )

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

        log.info("%s need_alert=%s", log_key, need_alert)

        return need_alert


    def check_alert(self, alert_data, status=None):
        if not isinstance(alert_data, Config):
            alert_data = Config(alert_data)

        _key  = alert_data.getval('key')
        _type = alert_data.getval('type')

        log_key = "func='read_status' key=%r type=%r" % (_key, _type)
        log.debug("%s", log_key)

        if status is None:
            # get last status of this alert_data
            last_rule = self.read_status(alert_data)

            if last_rule is not None:
                if isinstance(last_rule['status'], string):
                    status = last_rule['status']
                else:
                    status = last_rule['status']['current']
            log.debug("%s current_status=%r", log_key, last_rule)

        if status is None:
            alert_data['status.previous'] = 'ok'
            alert_data['status.current']  = 'ok'
        else:
            alert_data['status.previous'] = status
            alert_data['status.current'] = status

        need_alert = self.perform_check(alert_data, alert_data)

        log.debug("%s msg='checks performed' name=%r status=%r need_alert=%r "
            "alert_data=%r", log_key, alert_data.getval('name'), status,
            need_alert, alert_data)

        if not need_alert:
            alert_data['status.current'] = 'ok'
        else:
            alert_data['status.current'] = 'alert'

            log.warning("%s msg='need alert' name=%r status=%r", log_key,
                alert_data.getval('name'), status)

            # new status = alert
            if status != 'ok' and last_rule:
                realert = alert_data.get('realert', {'minutes': 60})

                if realert.get('enabled') is False:
                    if 'status.realert' in alert_data:
                        alert_data['status.realert'] = -1

                    return alert_data
                # else it is assumed, that realert is a dictionary, which can
                # be passed to timedelta

                # calculate wait time till next re-alert
                now = self.now()
                delta = 0
                try:
                    delta = timedelta(seconds=int(last_rule['status']['realert']))
                except Exception as e:
                    log.error("error", exc_info=1)

                if not delta:
                    factor = float(alert_data.get('realert.factor', 1))
                    max_len = alert_data.get('realert.timespan_max', {})
                    min_len = alert_data.get('realert.timespan_min', {'seconds': 10})
                    rewind = alert_data.get('realert.rewind', True)
                    count = int(last_rule.get('status.realert_count', 0))

                    _realert = {}
                    _realert.update(alert_data.get('realert', {}))
                    for k in ['factor', 'timespan_max', 'timespan_min', 'rewind']:
                        if k in _realert:
                            del _realert[k]

                    delta_s = timedelta(**_realert).total_seconds()
                    delta = timedelta(seconds=delta_s*(factor**count))
                    if max_len:
                        max_delta = timedelta(**max_len)
                        if delta > max_delta:
                            if rewind:
                                delta = timedelta(seconds=delta_s)
                            else:
                                delta = max_delta

                    if min_len:
                        min_delta = timedelta(**min_len)
                        if delta < min_delta:
                            if rewind:
                                delta = timedelta(seconds=delta_s)
                            else:
                                delta = min_delta


                time_passed = now - to_dt(last_rule['@timestamp'])

                log.info("%s delta=%r time_passed=%r", log_key, delta, time_passed)

                # if there is still wait time left,
                if delta > time_passed:
                    wait_time = delta - time_passed
                    log.info("%s wait_time=%r", log_key, wait_time)

                    wait_time_s = wait_time.total_seconds()

                    alert_data['status.realert'] = wait_time_s
                    log.info("%s status_realert=%r", log_key, wait_time_s)

                    return alert_data

                else:
                    if alert_data['status.previous'] != 'ok':
                        alert_data['status.current'] = 'realert'
                    alert_data['status.realert'] = 0
                    count = int(last_rule.get('status.realert_count', 0))
                    alert_data['status.realert_count'] = count + 1

                    log.warning("%s status_current=%r msg='trigger alert'",
                        log_key, alert_data['status.current'])

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
        log_key = "func='alert_init_status' key=%(key)r type=%(type)r" % alert

        log.debug("%s msg='class(alert) is %s'", log_key,
            alert.__class__.__name__)

        alert_status = Config(self.read_status(alert))

        now = self.now()
        every = timedelta(**alert.get('every', {'minutes': 1}))

        # initialize new status
        if alert_status:
            #last_check = self.now()
            last_check = to_dt(alert_status['@timestamp'])
            log.debug("%s alert_status=%r", log_key, alert_status)
            alert['status.previous'] = alert_status['status.current']
            alert['status.current'] = alert_status['status.current']

            if 'status.realert' in alert_status:
                alert['status.realert'] = alert_status['status.realert']
        else:
            last_check = None
            alert['status.current'] = alert['status.previous'] = 'ok'

        log.debug("%s last_check=%r", log_key, last_check)

        next_check = timedelta(seconds=alert_status.get('status.next_check',0))
        next_check_s = next_check.total_seconds()

        log.debug("%s next_check=%r", log_key, next_check)

        if next_check_s > 0:
            next_check = (next_check - (now-last_check))
        elif last_check is None:
            next_check = timedelta(seconds=0)
        else:
            next_check = (every - (now-last_check))

        next_check_s = next_check.total_seconds()
        log.debug("%s next_check_s=%r", log_key, next_check_s)

        alert['status.next_check'] = next_check_s > 0 and next_check_s or 0

        log.info("%s every=%r last_check=%r now=%r next_check=%r", log_key, every, last_check, now, alert['status.next_check'])

        return alert


    def rule_init_status(self, rule):
        key = rule.getval('key')
        log_key = "func='alert_init_status' key=%r" % key
        log.debug("%s", log_key)

        rule_status = self.read_status(type='rule', key=rule['key'])
        if rule_status is None:
            rule_status = {}
        rule_status['key'] = rule['key']
        rule_status['type'] = 'rule'
        rule_status['name'] = rule.getval('name')

        return Config(rule_status)


    def check_alerts(self):
        self._refreshed = {}

        log.debug("func='check_alerts'")

        rules = self.config.get('alerter.rules', [])
        now = self.now()

        for rule, alerts in self.iterate_alerts():
            key = rule.getval('key')
            log_key = "func='check_alerts' key=%r" % key
            log.debug("%s", log_key)

            for alert in alerts:
                self.alert_init_status(alert)
                type = alert.getval('type')

                log.debug("%s type=%r status_next_check=%r",
                    log_key, type, alert['status.next_check'])

                if alert['status.next_check'] == 0: # no wait time, so now
                    self.check_alert(alert)

            rule_status = self.rule_init_status(rule)

            was_ok = all([ a['status.previous'] == 'ok' for a in alerts])
            now_ok = all([ a['status.current'] == 'ok' for a in alerts])

            was_alert = all([ a['status.previous'] != 'ok' for a in alerts])

            now_alert = lambda a: a['status.current'] != 'ok'
            now_alert = [ x for x in filter(now_alert, alerts)]

            log.debug("%s was_ok=%r now_ok=%r was_alert=%r",
                log_key, was_ok, now_ok, was_alert)

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



            # update list of alerts done on this rule
            if was_ok:
                done_alerts = []
            else:
                done_alerts = _get_list(rule_status, 'alerts')
            alerts_list = [ a['type'] for a in now_alert ]
            done_alerts = sorted(list(set(chain(done_alerts, alerts_list))))
            rule_status['alerts'] = done_alerts

            # get severity of the alert
            S = self.config['alerter'].get('severity', {})
            severity = max([ a['status.current'] != 'ok' and S.get(a['type'], 1) or S.get('ok', 0) for a in alerts ]    )
            rule_status['status.severity'] = severity

            if was_alert and now_ok:
                # have to send all-clear for this rule
                for a in alerts:
                    if 'status.realert' in a:
                        del a['status']['realert']

                rule_status['status.end'] = dt_isoformat(now)
                all_clear = self.init_all_clear(rule, rule_status['triggers'], status=rule_status['status'], alerts=rule_status['alerts'])
                self.do_alert(all_clear)
                rule_status['all_clear'] = all_clear
                rule_status['alerts'] = []
                rule_status['triggers'] = []

            for alert in alerts:
                if 'status' not in alert:
                    alert['status'] = {}

                alert['status'].update(rule_status.get('status', {}))

                if now_alert:
                    status_current = alert['status.current']
                    status_realert = alert.get('status.realert', 0)

                    if status_current != 'ok' and status_realert == 0:
                        self.do_alert(alert)

                self.write_status(alert)

            # update list of notifications done on this rule
            if was_ok:
                done_notify = []
            else:
                done_notify = _get_list(rule_status, 'triggers')

            notify_list = [ k for a in alerts for k in a.get('triggered', {}).keys() ]
            done_notify = sorted(list(set(chain(done_notify, notify_list))))
            rule_status['triggers'] = done_notify

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
                    assert dep in waiting, "there is no rule with key %s, prerequisite of %s"%(dep, key)

                    log.debug("not_visited=%r", dep)
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

    def __getattr__(self, name):
        if name == 'prerequisites':
            [ r for r in self.iterate_rules() ]
            return self.prerequisites

        raise AttributeError(name)

    def dependency_tree(self):
        # under construction
        tree = {}
        nodes = {}
        parents = {}

        for key, reqs in self.prerequisites.items():
            log.debug("key: %s, reqs: %s", key, reqs)
            if key not in nodes:
                nodes[key] = {}

            if not reqs:
                tree[key] = nodes[key]

            for r_key in reqs:
                if r_key not in nodes:
                    nodes[r_key] = {}
                nodes[r_key][key] = nodes[key]

        return tree

    def get_rule_prerequisites(self, rule):
        key = rule.getval('key')
        prerequisites = rule.getval('depends', [])
        log.debug("expanded rule: %r", rule)

        for condition in ('if', 'if-not', 'if-all',
            'if-any', 'if-none'):

            cond_deps = rule.getval(condition, [])

            if isinstance(cond_deps, string):
                cond_deps = [cond_deps]

            prerequisites += cond_deps

        # get alert-level prerequisites and transform to rule level
        for alert_name, alert in rule.get('alerts', {}).items():
            for condition in ('if', 'if-not', 'if-all',
                'if-any', 'if-none'):

                cond_deps = alert.get(condition, [])
                cond_deps = rule.format(cond_deps, alert)

                if isinstance(cond_deps, string):
                    cond_deps = [cond_deps]

                prerequisites += [ cd.rsplit('.', 1)[0]
                                    for cd in cond_deps ]
        log.debug("key=%r prerequisites=%r", key, prerequisites)

        return prerequisites


        # for k,vs in parents.items():
        #     if k not in nodes:
        #         nodes[k] = {}
        #
        #     for v in vs:
        #         if v not in nodes:
        #             nodes[v] = {}
        #         nodes[v][k] =
        #     if not vs:
        #         tree[k] = {}
        #     else:
        #         for v in vs:
        #             if v in tree:
        #                 tree[v].append(k)
        #             else:
        #                 nodes[v] = {}
        #
    #def dependency_tree(self):
    # def iterate_prerequisites(self, tree={}):
    #     visited = {}
    #     waiting = {}
    #     tree = {}
    #     nodes = {}
    #     for key, reqs in self.prerequisites.items()
    #   _     if not reqs:
    #             tree[key] = nodes[key] = {}
    #         else:
    #             for r in reqs:
    #                 if r in nodes:
    #                     if key not in nodes[r]:
    #                         if key not in nodes:
    #                             nodes[key] = {}
    #                         nodes[r][key] = nodes[key]


    def iterate_rules(self, ordered=True):
        rule_waiting = {}
        visited = set()
        self.prerequisites = {}

        for raw_rule in self.iterate_raw_rules():
            log.debug("raw rule: %r", raw_rule)

            for rule in self.expand_raw_rule(raw_rule):
                # get rule level prerequisites
                if ordered:
                    prerequisites = self.get_rule_prerequisites(rule)

                    key = rule.getval('key')
                    self.prerequisites[key] = set(prerequisites)

                    if self.waiting_add(key, rule, rule_waiting, prerequisites):
                        continue

                visited.add(rule['key'])
                yield rule

        while rule_waiting:
            log.debug("rule_waiting=%r msg='before'", [x for x in rule_waiting.keys()])
            _before = len(rule_waiting)
            for rule in self.waiting_process(visited, rule_waiting):
                visited.add(rule.getval('key'))
                yield rule
            _after = len(rule_waiting)
            log.debug("rule_waiting=%r msg='after'", [x for x in rule_waiting.keys()])

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
            assert _name is not None, "you have to specify a name in rule: %r" % rule
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

        # TODO: if you use if-not conditions, make sure, that key/type is really existant

        log.debug("alert_data: %s", alert_data)
        return alert_data



    def init_all_clear(self, rule, notify, status=None, alerts=None):
        all_clear = Config.object()
        #all_clear.update(rule)
        all_clear['key'] = rule.getval('key')
        all_clear['name'] = rule.getval('name')
        all_clear['type'] = 'all-clear'
        if status is not None:
            all_clear['status'] = deepcopy(status)
        if alerts is not None:
            all_clear['alerts'] = deepcopy(alerts)

        all_clear['status.current'] = 'ok'
        all_clear['triggers'] = notify
        self.assert_key(all_clear)
        all_clear.update(rule.get('all_clear', {}))
        log.info("all_clear=%r", all_clear)

        _all_clear = rule.get('all_clear')
        if _all_clear:
            all_clear.update(_all_clear)
            if 'all_clear' in all_clear:
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

