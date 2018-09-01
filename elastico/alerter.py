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
        self.status_index_dirty = False

    def wipe_status_storage(self):
        '''remove all status storages'''
        result = self.es.indices.delete('elastico-alert-*')
        log.debug("wipe_status_storage: %s", result)
        return result

    def get_status_storage_index(self):
        date = to_dt(self.config['at'])
        return date.strftime('elastico-alert-%Y-%m-%d')

    def refresh_status_storage_index(self):
        if self.es:
            self.es.indices.refresh(self.get_status_storage_index())

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

    def compose_message_text(self, message, rule, **kwargs):
        '''compose message text from text with data from alert and rule

        '''
        import markdown
        data  = indent(4, pyaml.dump(rule, dst=unicode))+"\n"
        #if message
        plain = message.get('plain', '{message.text}\n{message.data}')
        text  = message.get('text', '')
        text  = rule.format(text, Config(kwargs))
        plain = rule.format(plain, Config(kwargs), Config({'message': {'data': data, 'text': text}}))
        html  = markdown.markdown(plain)

        return (text, data, plain, html)

    def notify_command(self, message, alert, rule, all_clear=None):
        cmd = alert.get('command')
        cmd = alert.format(cmd, message)

        if not rule.get('dry_run'):
            (result, stdout, stderr) = self.do_some_command(cmd, alert)

    def notify_email(self, message, alert, rule, all_clear=None):

        log.debug('alert: %s', alert)

        def _get(name, default=None):
            if name in alert:
                return alert[name]
            if name in rule:
                return rule[name]
            if name in self.config:
                return self.config[name]
            return default

        smtp_host    = _get('smtp.host', 'localhost')
        smtp_ssl     = _get('smtp.ssl', False)
        smtp_port    = _get('smtp.port', 0)

        email_from   = _get('email.from', 'noreply')
        email_cc     = _get('email.cc', [])
        email_to     = _get('email.to', [])
        email_bcc    = _get('email.bcc', [])

        log.debug("alert_email(): %s", alert)

        log.debug("email_to: %s", email_to)

        if not isinstance(email_cc, list) : email_cc  = [email_cc]
        if not isinstance(email_to, list) : email_to  = [email_to]
        if not isinstance(email_bcc, list): email_bcc = [email_bcc]

        recipients = email_to + email_cc + email_bcc

        assert recipients, "you must specify email recipient"

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
        _set_email_header('Subject', message['subject'])
        _set_email_header('To', email_to)

        if email_cc:
            _set_email_header('Cc', email_cc)

        log.info("alert_email: Bcc: %s", email_bcc)
        recipients = email_to + email_cc + email_bcc

        # Record the MIME types of both parts - text/plain and text/html.
        part1 = MIMEText(message['plain'], 'plain')
        part2 = MIMEText(message['html'], 'html')

        # Attach parts into message container.
        # According to RFC 2046, the last part of a multipart message, in this case
        # the HTML message, is best and preferred.
        msg.attach(part1)
        msg.attach(part2)

        email_message = msg.as_string()

        log.info("Send email alert: smtp_host=%s, smtp_port=%s, smtp_ssl=%s", smtp_host, smtp_port, smtp_ssl)
        log.info("alert_email: Text: %s", message['plain'])
        log.info("alert_email: HTML: %s", message['html'])

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


    def email_sendmail(self, host='localhost', port=0, use_ssl=False,
        username=None, password=None,
        sender=None, recipients=[], message=''):

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

    def get_notifications(self, alert_data):
        # get the list of notification_specs
        notification_specs = self.config.get('alerter.notifications', {})
        log.info("notification_specs: %s", notification_specs)

        notifications = {}
        _notify = alert_data.get('notify', [])
        if isinstance(_notify, dict):
            _tmp = []
            for k,v in _notify.items():
                _notification = deepcopy(v)
                _notification['notification'] = k
                _tmp.append(_notification)
            _notify = _tmp

        return _notify


    def do_alert(self, alert_data, all_clear=False):
        '''Use alert data to create a notification and transport it via
        given transport'''

        assert isinstance(alert_data, Config), "given alert data must be Config instance"

        log.info("do alert for: %s %s", alert_data.__class__.__name__, alert_data)

        # set future status
        if all_clear:
            alert_data['status'] = 'ok'
        else:
            alert_data['status'] = 'alert'

        # key and type must be present
        key = alert_data['key']
        type = alert_data['type']
        name = alert_data['name']
        log.info('Alert (%s): %s has status %s', type, key, alert_data['status'])

        # get the list of notification_specs
        notification_specs = self.config.get('alerter.notifications', {})
        log.info("notification_specs: %s", notification_specs)

        notifications = {}

        _notify = self.get_notifications(alert_data)

        for notify_name in _notify:
            try:
                #alert = Config.object(alert_data)
                nspec = Config.object()

                if isinstance(notify_name, string):
                    nspec.update(deepcopy(notification_specs[notify_name]))
                    nspec['notification'] = notify_name

                else:
                    nspec.update(deepcopy(notify_name))
                    notify_name = nspec['notification']

                log.info("process notification %s %s", nspec.__class__.__name__, nspec)

                if all_clear:
                    subject = alert_data.get('subject.ok', '')
                else:
                    subject = alert_data.get('subject.alert', '')

                if not subject:
                    status  = alert_data['status'].upper()
                    subject = '[elastico] {} - {} {}'.format(status, type, name)

                log.info("      notification subject %s", subject)
                nspec['message.subject'] = subject
                text, data, plain, html = self.compose_message_text(
                    alert_data.get('message', {}),
                    alert_data,
                    _ = alert_data.get('match_hit._source', {})
                    )

                nspec['message.text'] = text

                message = {
                    'text': text,
                    'data': data,
                    'plain': plain,
                    'html': html,
                    'subject': subject,
                }

                getattr(self, 'notify_'+nspec['transport'])(message, nspec, alert_data, all_clear)

                if self.config.get('dry_run'):
                    nspec['status'] = 'dry_run'
                else:
                    nspec['status'] = 'ok'

                notifications[notify_name] = alert_data.format(nspec)

            except Exception as e:
                # log.error('Error while processing notification %s: %s', notify_name, e)

                nspec['status'] = 'error'

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

                log.error("      notification error %s", message)
                nspec['error'] = {
                    'message': message,
                    'details': details,
                }

                log.debug('nspec[error]: %s', nspec['error'])

            log.info("      notification %s -> %s", notify_name, nspec['status'])

        alert_data['notifications'] = _n = {}
        for n_name,notification in notifications.items():
            _n[n_name] = {}
            for k,v in notification.items():
                if k not in alert_data or k in ('status', 'error', 'result'):
                    _n[n_name][k] = v

        log.warning("Done notifications: %s", alert_data)

            # we do not need plain as composition of text and data
            # we do not need data (as in rule)
            # we do not need to store the HTML text
            # del _n[n_name]['message']['plain']
            # del _n[n_name]['message']['html']
            # del _n[n_name]['message']['data']


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
            rule['match_hit'] = Config.object(results['hits']['hits'][0])

        # there should be at least min_matches
        min_total = rule.get('matches_min')
        # there should be at most max_matches
        max_total = rule.get('matches_max')
        # ... otherwise we will alert

        if min_total is None and max_total is None:
            max_total = 0

        # first check if totals are within given bounds
        _result = True
        if min_total is not None:
            _result = _result and results['hits']['total'] >= min_total
        if max_total is not None:
            _result = _result and results['hits']['total'] <= max_total

        # then invert the result
        _result = not _result

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

        log.info("run_command: kwargs=%s", kwargs)
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
        cmd = alert_data.get('command_succeeds')
        (result, stdout, stderr) = self.do_some_command(cmd, alert_data)

        _result = not (result == alert_data.get('expect.code', 0))
        alert_data['alert_trigger'] = _result
        return _result

    def do_command_fails(self, alert_data):
        cmd = alert_data.get('command_fails')
        (result, stdout, stderr) = self.do_some_command(cmd, alert_data)

        _result = not (result != alert_data.get('expect.code', 0))
        alert_data['alert_trigger'] = _result
        return _result

    def check_alert(self, alert_data, status=None):
        if status is None:
            # get last status of this alert_data
            try:
                last_rule = self.read_status(alert_data)

                if last_rule is not None:
                    status = last_rule['status']
            except:
                log.warning("could not read status from last run of alert_data %s for type %s", alert_data['key'], alert_data['type'])

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
            need_alert = self.do_match(alert_data)

        if need_alert:
            log.warning("need alert: %s", alert_data['name'])
            # new status = alert
            if status == 'alert' and last_rule:
                 delta = timedelta(**alert_data.get('realert', {'minutes': 60}))
                 wait_time = delta - ( to_dt(datetime.utcnow()) -
                    to_dt(last_rule['@timestamp']) )

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

            # overrides from arguments
            r.update(self.config.get('alerter.rule.%s', {}))

            log.info("--- rule %s", r.get('name'))

            _alerts = r.get('alerts', [])

            if isinstance(_alerts, dict):
                _tmp = []
                for k,v in _alerts.items():
                    _value = Config.object({'type': r.format(k)})
                    _value.update(deepcopy(v))
                    _tmp.append(_value)
                _alerts = _tmp

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

                if 'alerts' in alert_data:
                    del alert_data['alerts']

                log.debug("alert_data (alert): %s", alert_data)

                _r_name = r.getval('name')

                if 'key' not in alert_data:
                    alert_data['key'] = re.sub(r'[^\w]+', '_', _r_name.lower())

                _key = alert_data.getval('key')

                log.info("----- alert %s-%s?", _type, _key)

                visit_key = (_type, _key)
                assert visit_key not in visited_keys, \
                    "key %s already used in rule %s" % (_key, _r_name)

                assert 'match' in alert_data or 'no_match' in alert_data \
                    or 'command_succeeds' in alert_data \
                    or 'command_fails' in alert_data

                log.debug("alert_data: %s", alert_data)

                if action:
                    action(alert_data)
                else:
                    self.check_alert(alert_data)

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

# TODO: have to refactor Config, such that formatting is not done implicitely
# TODO: need a formatter, which can work with dict + defaults, and this formatter must be used in new Config
