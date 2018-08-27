"""alerter -- a simple alerter module

"""

from datetime import datetime, timedelta
from dateutil.parser import parse as dt_parse
from itertools import product
from subprocess import Popen, PIPE
from copy import deepcopy

#from ..config import Config

import logging, sys, json, pyaml, re
log = logging.getLogger('elastico.alerter')

from .util import to_dt, PY3, dt_isoformat, format_value, get_config_value
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

    def __init__(self, es_client=None, config={}, config_base="alerter"):
        self.es = es_client
        self.config = config
        self.STATUS = {}

    def wipe_status_storage(self):
        '''remove all status storages'''
        result = self.es.indices.delete('elastico-alert-*')
        log.debug("wipe_status_storage: %s", result)
        return result

    def get_status_storage_index(self):
        date = to_dt(self.config['at'])
        return date.strftime('elastico-alert-%Y-%m-%d')

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
            result = self.es.index(index=index, doc_type="elastico_alert_status", body=rule)
            self.es.indices.refresh(index)
            log.debug("index result: %s", result)

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

        if storage_type == 'elasticsearch':
            results = self.es.search(index="elastico-alerter-*", body={
                'query': {'bool': {'must': [
                    {'term': {'key': key}},
                    {'term': {'type': type}}
                ]}},
                'sort': [{'@timestamp': 'desc'}],
                'size': 1
            })

            if results['hits']['total']:
                return results['hits']['hits'][0]['_source']
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

    def compose_message_text(self, alert, rule):
        if 'message.plain' not in alert:
            import markdown
            data = indent(4, pyaml.dump(rule, dst=unicode))+"\n"
            alert['message.data'] = data

            text = alert.get('message.text', '')
            if alert.get('message.type') != 'text_only':
                if text.strip():
                    text = text.rstrip() + "\n\n"+data
                else:
                    text = data

            log.debug("input for debug: %s", text)

            html = markdown.markdown(text)

            alert['message.plain'] = text
            alert['message.html'] = html

        return alert['message.plain'], alert['message.html']

    def notify_command(self, alert, rule, all_clear=None):
        cmd = alert.get('command')
        if not rule.get('dry_run'):
            (result, stdout, stderr) = self.do_some_command(cmd, alert)

    def notify_email(self, alert, rule, all_clear=None):
        smtp_host    = alert.get('smtp.host', 'localhost')
        smtp_ssl     = alert.get('smtp.ssl', False)
        smtp_port    = alert.get('smtp.port', 0)

        email_from   = alert.get('email.from', 'noreply')
        email_cc     = alert.get('email.cc', [])
        email_to     = alert.get('email.to', [])
        email_bcc    = alert.get('email.bcc', [])

        log.debug("alert_email(): %s", alert)

        log.debug("email_to: %s", email_to)

        if not isinstance(email_cc, list) : email_cc  = [email_cc]
        if not isinstance(email_to, list) : email_to  = [email_to]
        if not isinstance(email_bcc, list): email_bcc = [email_bcc]

        recipients = email_to + email_cc + email_bcc

        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText

        # Create message container - the correct MIME type is multipart/alternative.
        msg = MIMEMultipart('alternative')

        def _set_email_header(key, value):
            log.info("alert_email: %s: %s", key, value)
            if isinstance(value, list):
                msg[key] = ", ".join(value)
            else:
                msg[key] = value

            rule['email.%s' % key.lower()] = msg[key]

        _set_email_header('From', email_from)
        _set_email_header('Subject', alert['message.subject'])
        _set_email_header('To', email_to)

        if email_cc:
            _set_email_header('Cc', email_cc)

        log.info("alert_email: Bcc: %s", email_bcc)
        recipients = email_to + email_cc + email_bcc

        # Record the MIME types of both parts - text/plain and text/html.
        part1 = MIMEText(alert['message.plain'], 'plain')
        part2 = MIMEText(alert['message.html'], 'html')

        # Attach parts into message container.
        # According to RFC 2046, the last part of a multipart message, in this case
        # the HTML message, is best and preferred.
        msg.attach(part1)
        msg.attach(part2)

        email_message = msg.as_string()

        log.info("Send email alert: smtp_host=%s, smtp_port=%s, smtp_ssl=%s", smtp_host, smtp_port, smtp_ssl)
        log.info("alert_email: Text: %s", alert['message.plain'])
        log.info("alert_email: HTML: %s", alert['message.html'])

        if not rule.get('dry_run'):
            result = self.email_sendmail(
                host=smtp_host,
                port=smtp_port,
                use_ssl=smtp_ssl,
                username=None,
                password=None,
                sender=email_from,
                recipients=recipients,
                message=email_message
            )

            if result:
                for recipient in recipients:
                    if recipient not in result:
                        result[recipient] = {'status': 200, 'message': 'ok'}
                    else:
                        status, msg = result[recipient]
                        result[recipient] = {'status': status, 'message': msg}

                raise NotificationError("Some recipients had errors", result)


    def email_sendmail(host='localhost', port=0, use_ssl=False,
        username=None, password=None,
        sender=None, recipients=[], message=''):

        if use_ssl:
            from smtplib import SMTP_SSL as SMTP
        else:
            from smtplib import SMTP

        smtp = SMTP()
        smtp.connect(host=smtp_host, port=smtp_port)
        # if user and password are given, use them to smtp.login(user, pass)
        if username is not None:
            smtp.login(username, password)

        result = smtp.sendmail(from_address, recipients, email_message)
        smtp.quit()
        return result


    def do_alert(self, rule, all_clear=False):
        log.info("do alert for: %s %s", rule.__class__.__name__, rule)

        if all_clear:
            rule['status'] = 'ok'
        else:
            rule['status'] = 'alert'

        key = rule.get('key')
        type = rule.get('type')

        log.info('Alert (%s): %s has status %s', type, key, rule['status'])

        notification_specs = self.config.get('alerter.notifications', {})
        log.info("notification_specs: %s", notification_specs)

        notifications = {}
        _notify = rule.get('notify', [])
        if isinstance(_notify, dict):
            _tmp = []
            for k,v in _notify.items():
                _notification = deepcopy(v)
                _notification['notification'] = k
                _tmp.append(_notification)
            _notify = _tmp

        for notification in _notify:
            try:
                alert = Config.object(rule)

                if isinstance(notification, string):
                    alert.update(deepcopy(notification_specs[notification]))
                    alert['notification'] = notification

                else:
                    alert.update(deepcopy(notification))
                    notification = alert['notification']

                log.info("process notification %s %s", alert.__class__.__name__, alert)

                name = rule.get('name')
                type = rule.get('type')
                key  = rule.get('key')

                if all_clear:
                    subject = rule.get('subject.ok', '')
                else:
                    subject = rule.get('subject.alert', '')

                if not subject:
                    status = rule['status'].upper()
                    subject = '[elastico] {} - {} {}'.format(status, type, name)

                alert['message.subject'] = subject
                self.compose_message_text(alert, rule)

                getattr(self, 'notify_'+alert['transport'])(alert, rule, all_clear)

                if self.config.get('dry_run'):
                    alert['status'] = 'dry_run'
                else:
                    alert['status'] = 'ok'

                notifications[notification] = alert.format_value()
            except Exception as e:
                log.error('Error while processing notification %s', notification, exc_info=1)

                rule['status'] = 'error'

                args = e.args[1:]
                if len(args) > 1:
                    details = dict( (str(i), a) for a in enumerate(args, 1)  )
                elif len(args) == 1:
                    details = args[0]
                if len(args) == 0:
                    details = None

                if hasattr(e, 'message'):
                    message = e.message
                else:
                    message = e.__class__.__name__+"("+str(e)+")"

                alert['error'] = {
                    'message': e.message,
                    'details': details,
                }

                log.debug('alert[error]: %s', alert['error'])

        rule['notifications'] = _n = {}
        for n_name,notification in notifications.items():
            _n[n_name] = {}
            for k,v in notification.items():
                if k not in rule or k in ('status', 'error', 'result'):
                    _n[n_name][k] = v

            # we do not need plain as composition of text and data
            # we do not need data (as in rule)
            # we do not need to store the HTML text
            del _n[n_name]['message']['plain']
            del _n[n_name]['message']['html']
            del _n[n_name]['message']['data']


    def get_query(self, rule, name):
        body = None
        query = rule.get(name)

        # list of filters
        if isinstance(query, list):
            filters = query

        # lucene query string
        if isinstance(query, string):
            filters = [{'query_string': {'query': query.strip()}}]

        # complete search body (including timerange, if any)
        if isinstance(query, dict):
            return query

        timestamp_field = rule.get('timestamp_field', '@timestamp')
        timeframe = rule.get('timeframe', {'minutes': 15})

        if 'endtime' in rule:
            endtime = to_dt(rule.get('endtime'))
        else:
            endtime = to_dt(self.config['at'])

        if 'starttime' in rule:
            starttime = to_dt(rule.get('starttime'))
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

        assert index, "index must be present in rule"
        rule['match_query'] = body
        results = self.es.search(index=index, body=body)
        log.debug("results: %s", results)
        rule['match_hits_total'] = results['hits']['total']
        if rule['match_hits_total']:
            rule['match_hit'] = results['hits']['hits'][0]

        min_total = rule.get('matches_min')
        max_total = rule.get('matches_max')
        if min_total is None and max_total is None:
            min_total = 1

        _result = True
        if min_total is not None:
            _result = _result and results['hits']['total'] >= min_total
        if max_total is not None:
            _result = _result and results['hits']['total'] <= max_total

        rule['alert_trigger'] = _result
        return _result


    def do_some_command(self, kwargs, rule=None):
        log.debug("do_some_command: kwargs=%s, rule=%s", kwargs, rule)
        if isinstance(kwargs, string):
            kwargs = {'args': kwargs, 'shell': True}

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

    def do_command_succeeds(self, alert_rule):
        cmd = alert_rule.get('command_succeeds')
        (result, stdout, stderr) = self.do_some_command(cmd, alert_rule)

        _result = result == alert_rule.get('expect.code', 0)
        rule['alert_trigger'] = _result
        return _result

    def do_command_fails(self, alert_rule):
        cmd = alert_rule.get('command_fails')
        (result, stdout, stderr) = self.do_some_command(cmd, alert_rule)

        _result = result != alert_rule.get('expect.code', 0)
        rule['alert_trigger'] = _result
        return _result

    def check_alert(self, rule, status=None):
        if status is None:
            # get last status of this rule
            try:
                last_rule = self.read_status(rule)

                if last_rule is not None:
                    status = last_rule['status']
            except:
                log.warning("could not read status from last run of rule %s for type %s", rule['key'], rule['type'])

        if status is None:
            rule['status'] = 'ok'
        else:
            rule['status'] = status

        need_alert = False
        if 'command_fails' in rule:
            need_alert = need_alert or self.do_command_fails(rule)

        if 'command_succeeds' in rule:
            need_alert = need_alert or self.do_command_succeeds(rule)

        if 'match' in rule:
            need_alert = self.do_match(rule)

        if need_alert:
            # new status = alert
            if status == 'alert' and last_rule:
                 delta = timedelta(**rule.get('realert', {'minutes': 60}))
                 if to_dt(last_rule['@timestamp']) < to_dt(datetime.utcnow()):
                     rule['status'] = 'wait-realert'
                     return rule

            self.do_alert(rule)

        else:
            if status == 'alert':
                self.do_alert(rule, all_clear=last_rule)

        if not rule.get('dry_run'):
            self.write_status(rule)

        # here we can expand everything

        # check result and log

        return rule

    def process_rules(self, action=None, **arguments):
        if 'arguments' not in self.config:
            self.config['arguments'] = {}

        self.config['arguments'].update(arguments)

        for rule in self.config.get('alerter.rules', []):
            if not rule: continue

            log.debug("rule: %s", rule)
            log.info("=== RULE <%s> =========================", rule.get('class', rule.get('name')))

            self.process(Config.object(rule), action=action)

    ALIAS = re.compile(r"^\s*\*(\w+)(\.\w+)*(\s+\*(\w+)(\.\w+)*)*\s*$")
    def process(self, rule, action=None):
        has_foreach = False
        # create a product of all items in 'each' to multiply the rule
        if 'foreach' in rule:
            data_list = []

            for key,val in rule.get('foreach', {}).items():
                log.debug("key: %s, val: %s", key, val)
                # expand *foo.bar values.
                if isinstance(val, string):
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
                data_list.append([{key: v} for v in val])

            data_sets = product(*data_list)

            has_foreach = True

        else:
            data_sets = [({},)]

        visited_keys = []

        for data_set in data_sets:
            log.debug("data_set: %s", data_set)

            # get arguments
            r = Config.object(deepcopy(self.config.get('arguments', {})))

            # get defaults
            defaults = self.config.get('alerter.rule_defaults', {})
            _class = rule.get('class', 'default')

            log.debug("rule class: %s", _class)
            _defaults = defaults.get(_class, {})

            log.debug("rule defaults: %s", _defaults)
            r.update(deepcopy(_defaults))

            # update data from rule
            r.update(rule.format_value())

            if 'foreach' in r:
                del r['foreach']
            _alerts = r.get('alerts', [])
            if 'alerts' in r:
                del r['alerts']

            for data in data_set:
                r.update(deepcopy(data))

            log.info("--- rule %s", r.get('name'))

            if isinstance(_alerts, dict):
                _tmp = []
                for k,v in _alerts.items():
                    _value = Config.object({'type':k})
                    _value.update(deepcopy(v))
                    _tmp.append(_value)
                _alerts = _tmp

            for alert in _alerts:
                log.debug("process alert %s", alert)
                alert_rule = Config.object()

                assert 'type' in alert

                defaults = self.config.get('alerter.alert_defaults', {})
                alert_rule.update(deepcopy(defaults.get(alert.get('type'),{})))

                defaults = rule.get('alert_defaults', {})
                alert_rule.update(deepcopy(defaults.get(alert.get('type'),{})))

                alert_rule.update(r.format_value())

                if hasattr(alert, 'format_value'):
                    alert_rule.update(alert.format_value())
                else:
                    alert_rule.update(alert)

                log.debug("alert_rule (alert): %s", alert_rule)

                if 'key' not in alert_rule:
                    alert_rule['key'] = re.sub(r'[^\w]+', '_', r.get('name').lower())

                log.info("----- alert %s-%s", alert_rule['type'], alert_rule['key'])

                visit_key = (alert_rule.get('key'), alert_rule.get('type'))
                assert visit_key not in visited_keys, \
                    "key %s already used in rule %s" \
                    % (alert_rule.get('key'), r.get('name'))

                assert 'match' in alert_rule or 'no_match' in alert_rule \
                    or 'command_succeeds' in alert_rule \
                    or 'command_fails' in alert_rule

                log.debug("alert_rule: %s", alert_rule)

                if action:
                    action(alert_rule.format_value())
                else:
                    self.check_alert(alert_rule.format_value())

            if not _alerts:
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
                    log.error("exception occured while processing rules", exc_info=1)
        else:
            alerter.process_rules()

    @classmethod
    def expand_rules(cls, config):
        '''expand alert rules
        '''
        RULES = []
        def collect_rules(rule):
            RULES.append(rule)
            return rule

        Alerter(None, config).process_rules(action=collect_rules)
        return RULES

