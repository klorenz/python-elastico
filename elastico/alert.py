from datetime import datetime, timedelta
from dateutil.parser import parse as dt_parse
from itertools import product

import logging, sys, json, pyaml
log = logging.getLogger('elastico.alert')

from .util import to_dt, PY3, dt_isoformat

if PY3:
    unicode = str
    string = str
else:
    string = basestring

def indent(indent, s):
    if isinstance(indent, int):
        indent = " "*indent
    return "".join([ indent+line for line in s.splitlines(1) ])

class Alerter:
    '''alerter alerts.

    here more doc.
    '''

    def __init__(self, es_client=None, config={}):
        self.es = es_client
        self.config = config
        self.STATUS = {}

    def get_config_value(self, key, default=None):
        key_parts = key.split('.')
        result = self.format_value(self.config, self.config.get(key_parts[0], default))
        for k in key_parts[1:]:
            if k not in result:
                return default

            result = result[k]
        return result

    def get_rule_value(self, rule, key, default=None):
        key_parts = key.split('.')
        result = self.format_value(rule, rule.get(key_parts[0], default))
        for k in key_parts[1:]:
            if k not in result:
                return default

            result = result[k]
        return result

    def wipe_status_storage(self):
        '''remove all status storages'''
        result = self.es.indices.delete('elastico-alert-*')
        log.debug("wipe_status_storage: %s", result)
        return result

    def get_status_storage_index(self):
        now = to_dt(dt_isoformat(datetime.utcnow(), 'T', 'seconds'))
        date = to_dt(self.get_config_value('arguments.run_at', now))
        return date.strftime('elastico-alert-%Y-%m-%d')

    def write_status(self, rule):
        storage_type = self.get_config_value('status_storage', 'memory')

        now = to_dt(dt_isoformat(datetime.utcnow(), 'T', 'seconds'))
        #rule['@timestamp'] = to_dt(self.get_rule_value(rule, 'run_at', now))
        rule['@timestamp'] = timestamp = dt_isoformat(to_dt(self.get_config_value('arguments.run_at', now)))
        if 'run_at' in rule:
            rule['run_at'] = dt_isoformat(rule['run_at'])

        log.debug("rule to write to status: %s", rule)

        key  = self.get_rule_value(rule, 'key')
        type = self.get_rule_value(rule, 'type')

        if storage_type == 'elasticsearch':
            index = self.get_status_storage_index()
            result = self.es.index(index=index, doc_type="elastico_alert_status", body=rule)
            self.es.indices.refresh(index)
            log.debug("index result: %s", result)

        elif storage_type == 'filesystem':
            storage_path = self.get_config_value('status_storage_path', '')
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
        storage_type = self.get_config_value('status_storage', 'memory')

        if key is None:
            key  = self.get_rule_value(rule, 'key')
        if type is None:
            type = self.get_rule_value(rule, 'type')

        if storage_type == 'elasticsearch':
            results = self.es.search(index="elastico-alert-*", body={
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
            storage_path = self.get_config_value('status_storage_path')
            assert storage_path, "For status_storage 'filesystem' you must configure 'status_storage_path' "
            path = "{}/{}-{}-latest.yaml".format(storage_path, type, key)
            with open(path, 'r') as f:
                return json.load(f)

        elif storage_type == 'memory':
            return self.STATUS.get(type, {}).get(key)

    def compose_message_text(self, alert, rule):
        if 'message_text' not in alert:
            import markdown
            text = self.get_rule_value(alert, 'message', '')
            if self.get_rule_value(alert, 'alert_message') != 'text_only':
                text = text.rstrip() + "\n\n"+indent(4, pyaml.dump(rule, dst=unicode))+"\n"

            log.debug("input for debug: %s", text)

            html = markdown.markdown(text)

            alert['message_text'] = text
            alert['message_html'] = html

        return alert['message_text'], alert['message_html']


    def alert_email(self, alert, rule, all_clear=None):
        smtp_host    = self.get_rule_value(alert, 'smtp_host', 'localhost')
        smtp_ssl     = self.get_rule_value(alert, 'smtp_ssl', False)
        smtp_port    = self.get_rule_value(alert, 'smtp_port', 0)

        email_from   = self.get_rule_value(alert, 'email_from', 'noreply')
        email_cc     = self.get_rule_value(alert, 'email_cc', [])
        email_to     = self.get_rule_value(alert, 'email_to', [])
        email_bcc    = self.get_rule_value(alert, 'email_bcc', [])

        log.debug("alert_email(): %s", alert)

        type = self.get_rule_value(rule, 'type')
        key  = self.get_rule_value(rule, 'key')

        if all_clear:
            email_subject = self.get_rule_value(rule, 'subject_all_clear', '')
            if not email_subject:
                email_subject = '[elastico] OK - {} {}'.format(type, key)

        else:
            email_subject = self.get_rule_value(rule, 'subject', '')
            log.debug("email_subject (from rule): %s", email_subject)
            if not email_subject:
                email_subject = "[elastico] ALERT - {} {}".format(type, key)

        if not isinstance(email_cc, list) : email_cc  = [email_cc]
        if not isinstance(email_to, list) : email_to  = [email_to]
        if not isinstance(email_bcc, list): email_bcc = [email_bcc]

        recipients = email_to + email_cc + email_bcc

        text, html = self.compose_message_text(alert, rule)

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

            rule['email_%s' % key.lower()] = msg[key]

        _set_email_header('From', email_from)
        _set_email_header('Subject', email_subject)
        _set_email_header('To', email_to)

        if email_cc:
            _set_eamil_header('Cc', email_cc)

        log.info("alert_email: Bcc: %s", email_bcc)
        recipients = email_to + email_cc + email_bcc

        # Record the MIME types of both parts - text/plain and text/html.
        part1 = MIMEText(text, 'plain')
        part2 = MIMEText(html, 'html')

        # Attach parts into message container.
        # According to RFC 2046, the last part of a multipart message, in this case
        # the HTML message, is best and preferred.
        msg.attach(part1)
        msg.attach(part2)

        email_message = msg.as_string()

        log.info("Send email alert: smtp_host=%s, smtp_port=%s, smtp_ssl=%s", smtp_host, smtp_port, smtp_ssl)
        log.info("alert_email: Text: %s", text)
        log.info("alert_email: HTML: %s", html)

        if not rule.get('dry_run'):
            self.email_sendmail(
                host=smtp_host,
                port=smtp_port,
                use_ssl=smtp_ssl,
                username=None,
                password=None,
                sender=email_from,
                recipients=recipients,
                message=email_message
            )

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

        smtp.sendmail(from_address, recipients, email_message)

    def alert_command(self, alert, rule):
        #
        pass

    #def alert_

    def do_alert(self, rule, all_clear=False):
        log.info("do alert for: %s", rule)

        if all_clear:
            rule['status'] = 'ok'
        else:
            rule['status'] = 'alert'

        key = self.get_rule_value(rule, 'key')
        type = self.get_rule_value(rule, 'type')

        log.info('Alert (%s): %s has status %s', type, key, rule['status'])

        for alert in rule.get('notify', []):
            log.info("process notification %s", alert)
            getattr(self, 'alert_'+alert['transport'])(alert, rule, all_clear)

    def get_query(self, rule, name):
        body = None
        query = self.get_rule_value(rule, name)

        # list of filters
        if isinstance(query, list):
            filters = query

        # lucene query string
        if isinstance(query, string):
            filters = [{'query_string': {'query': query}}]

        # complete search body (including timerange, if any)
        if isinstance(query, dict):
            return query

        timestamp_field = self.get_rule_value(rule, 'timestamp_field', '@timestamp')
        timeframe = self.get_rule_value(rule, 'timeframe', {'minutes': 60})

        if 'endtime' in rule:
            endtime = to_dt(self.get_rule_value(rule, 'endtime'))
        else:
            run_at = self.get_config_value("arguments.run_at")
            if run_at:
                endtime = to_dt(run_at)
            else:
                endtime = datetime.utcnow() #.isoformat('T', 'seconds')+"Z"

        if 'starttime' in rule:
            starttime = to_dt(self.get_rule_value(rule, 'starttime'))
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
        index = self.get_rule_value(rule, 'index')
        assert index, "index must be present in rule"
        results = self.es.search(index=index, body=body)
        rule['match_hits_total'] = results['hits']['total']
        if rule['match_hits_total']:
            rule['match_hit'] = results['hits']['hits'][0]
        rule['match_hits'] = results['hits']['total'] > 0

        return rule['match_hits']

    def do_no_match(self, rule):
        body = self.get_query(rule, 'no_match')
        body['size'] = 0
        index = self.get_rule_value(rule, 'index')
        assert index, "index must be present in rule"

        results = self.es.search(index=index, body=body)

        rule['no_match_hits_total'] = results['hits']['total']
        rule['no_match_hits'] = results['hits']['total'] == 0

        return rule['no_match_hits']

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

        need_alert = False
        if 'match' in rule:
            need_alert = self.do_match(rule)

        if 'no_match' in rule:
            need_alert = need_alert or self.do_no_match(rule)

        if need_alert:
            # new status = alert
            if status == 'alert' and last_rule:
                 delta = timedelta(**self.get_rule_value(rule, 'realert', {'minutes': 60}))
                 if to_dt(last_rule['@timestamp']) + delta < datetime.utcnow():
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


    def format_value(self, rule, current=None):
        try:
            if current is None:
                current = rule
            if isinstance(current, string):
                return current.format(**rule)
            if isinstance(current, (list, tuple)):
                return [self.format_value(rule, v) for v in current]
            if isinstance(current, dict):
                result = {}
                for k,v in current.items():
                    result[k] = self.format_value(rule, v)
                return result
            else:
                return current
        except Exception as e:
            log.debug("error formatting %s: %s", current, e)
            return current

    def process_rules(self, config=None, action=None, **arguments):
        if 'arguments' not in self.config:
            self.config['arguments'] = {}
        self.config['arguments'].update(arguments)

        for rule in self.config.get('rules', []):
            self.process(rule, action=action)

    def process(self, rule, action=None):
        has_foreach = False
        # create a product of all items in 'each' to multiply the rule
        if 'foreach' in rule:
            data_list = []

            for key,val in rule['foreach'].items():
                data_list.append([{key: v} for v in val])

            data_sets = product(*data_list)

            has_foreach = True

        else:
            data_sets = [({},)]

        visited_keys = []

        for data_set in data_sets:
            log.debug("data_set: %s", data_set)

            # get arguments
            r = self.get_config_value('arguments', {}).copy()

            # get defaults
            defaults = self.get_config_value('rule_defaults', {})
            _class = self.get_rule_value(rule, 'class', 'default')
            r.update(defaults.get(_class, {}))

            # update data from rule
            r.update(rule)

            if 'foreach' in r:
                del r['foreach']
            if 'alerts' in r:
                del r['alerts']

            for data in data_set:
                r.update(data)

            log.debug("rule: %s", r)

            for alert in rule['alerts']:
                log.debug("process alert %s", alert)

                alert_rule = {}

                defaults = self.get_config_value('alert_defaults', {})
                log.debug("defaults: %s", defaults)

                alert_rule.update(defaults.get(alert['type'],{}))

                log.debug("alert_rule (defaults): %s", alert_rule)
                alert_rule.update(r)

                alert_rule.update(alert)
                log.debug("alert_rule (alert): %s", alert_rule)

                if has_foreach:
                    assert 'key' in alert_rule
                else:
                    if 'key' not in alert_rule:
                        alert_rule['key'] = r['name']

                visit_key = (alert_rule['key'], alert_rule['type'])
                assert visit_key not in visited_keys, "key %s already used in rule %s" % (alert_rule['key'], r['name'])

                assert 'match' in alert_rule or 'no_match' in alert_rule

                log.debug("alert_rule: %s", alert_rule)

                if action:
                    action(alert_rule)
                else:
                    self.check_alert(alert_rule)

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

        from .connection import elasticsearch
        es = elasticsearch(config)
        Alerter(es, config).process_rules(config, action=collect_rules)
        return RULES


