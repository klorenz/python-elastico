from copy import deepcopy
from .config import Config
from .util import run_command, string, PY3, get_netrc_login_data_from_value, indent

from pprint import pformat

if PY3:
    unicode = str

import logging, pyaml
log = logging.getLogger('elastico.notifier')

class BaseNotifier:
    def __init__(self, config, data=None, prefixes=[]):
        assert isinstance(config, Config), "config must be Config instance"
        if data is None:
            data = Config.object()

        assert isinstance(data, Config), "data must be Config instance"

        self.config = config
        self.data = data
        self.prefixes = prefixes

    def update_data(self, data, value=None):
        if value is None:
            self.data.update(data)
        else:
            self.data[data] = value

    def get_value(self, name, default=None, configs=None):
        for cfg in configs:
            try:
                return cfg[name]
            except KeyError:
                pass
        try:
            return self.data[name]
        except KeyError:
            pass

        try:
            return self.config[name]
        except KeyError:
            return default






class EmailNotifier(BaseNotifier):

    def notify(self, message, *configs):
        _get = lambda n,d=None: self.get_value(n,d,configs=configs)

        smtp_host    = _get('smtp.host', 'localhost')
        smtp_ssl     = _get('smtp.ssl', False)
        smtp_port    = _get('smtp.port', 0)

        try:
            (username, password) = get_netrc_login_data_from_value(_get('smtp.netrc', {}))
        except LookupError:
            username = _get('smtp.username', None)
            password = _get('smtp.password', None)

        email_from   = _get('email.from', 'noreply')
        email_cc     = _get('email.cc', [])
        email_to     = _get('email.to', [])
        email_bcc    = _get('email.bcc', [])

        if not isinstance(email_cc, list) : email_cc  = [email_cc]
        if not isinstance(email_to, list) : email_to  = [email_to]
        if not isinstance(email_bcc, list): email_bcc = [email_bcc]

        recipients = email_to + email_cc + email_bcc

        assert recipients, "you must specify email recipient"

        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText

        (plain, html) = (None, None)

        if message.get('plain'):
            plain = MIMEText(message['plain'], 'plain')
        if message.get('html'):
            html = MIMEText(message['html'], 'html')

        if plain and html:
            msg = MIMEMultipart('alternative')
            msg.attach(plain)
            msg.attach(html)
        elif plain:
            msg = plain
        elif html:
            msg = html

        def _set_email_header(key, value):
            log.info("alert_email: %s: %s", key, value)
            if isinstance(value, list):
                msg[key] = ", ".join(value)
            else:
                msg[key] = value

            self.update_data({'email.%s' % key.lower(): msg[key]})

        _set_email_header('From', email_from)
        _set_email_header('Subject', message['subject'])
        _set_email_header('To', email_to)

        if email_cc:
            _set_email_header('Cc', email_cc)

        log.info("alert_email: Bcc: %s", email_bcc)

        email_message = msg.as_string()

        from .util import sendmail

        sendmail_result = sendmail(
                host=smtp_host,
                port=smtp_port,
                use_ssl=smtp_ssl,
                username=username,
                password=password,
                sender=email_from,
                recipients=recipients,
                message=email_message
                )

        result = {}
        if sendmail_result:
            for recipient in recipients:
                if recipient not in sendmail_result:
                    result[recipient] = {'status': 200, 'message': 'ok'}
                else:
                    status, msg = result[recipient]
                    result[recipient] = {'status': status, 'message': msg}

            raise NotificationError("Some recipients had errors", result)

        return sendmail_result


class CommandNotifier(BaseNotifier):
    def notify(self, message, *configs):
        _get = lambda n,d=None: self.get_value(n,d,configs=configs)

        cmd = _get('command')
        cmd = self.data.format(cmd, message)

        if not self.config.get('dry_run'):
            (result, stdout, stderr) = run_command(cmd, self.data)

class UrlNotifier(BaseNotifier):
    def notify(self, message, *configs):
        _get = lambda n,d=None: self.get_value(n,d,configs=configs)
        # telegram_bot_token =
        # get
        # self.data.format

class TelegramNotifier(BaseNotifier):
    def notify(self, message, *configs):
        _get = lambda n,d=None: self.get_value(n,d,configs=configs)
        # telegram_bot_token =
        # get
        # self.data.format


class Notifier(BaseNotifier):
    transports = {
        'email': EmailNotifier,
        'command': CommandNotifier,
    }

    def compose_message_text(self, message, rule, **kwargs):
        '''compose message text from text with data from alert and rule
        '''

        log.debug("compose_message_text message=%r, rule=%r, kwargs=%r",
            message, rule, kwargs)

        if isinstance(message, string):
            message = {'text': message}

        import markdown

        try:
            data  = indent(pyaml.dump(rule, dst=unicode), " "*4)+"\n"
        except Exception as e:
            log.error("could not convert data to YAML -- message='%s', rule=%r", e, rule)

            data = "Could not convert data to YAML.\n\n"
            data += indent(pformat(rule)," "*4)

        try:
            #if message
            plain = message.get('plain', '{message.text}\n---------\n\n{message.data}')
            text  = message.get('text', '')
            text  = rule.format(text, self.config, Config(kwargs))
            plain = rule.format(plain, self.config, Config(kwargs), Config({'message': {'data': data, 'text': text}}))
            html  = markdown.markdown(plain)
        except Exception as e:
            import traceback
            log.error("could not compose message -- message=%r, kwargs=%r", e, kwargs)
            text = "Could not compose text or plain message:\n\n"
            text += traceback.format_exc()
            text += "\n\n"+data

            plain = text
            html = None

        return (text, data, plain, html)

    def transport_notification(self, message, notify_spec, data):
        notify_class = Notifier.transports[notify_spec['type']]
        notifier = notify_class(self.config, notify_spec)
        notifier.notify(message, notify_spec, data)

    def notify(self, notify=None, data=None, subject=None, text=None):
        if data is None:
            data = self.data
        if notify is None:
            notify = data.get('trigger', [])

        # compose predefined notifications
        notify_specs = self.config.get('actions', {})
        for prefix in self.prefixes:
            notify_specs.update(self.config.get('%s.actions' % prefix, {}))

        notify_specs.update(data.get('actions',{}))
        log.debug("notify_specs=%r", notify_specs)

        # normalize notify data
        if isinstance(notify, dict):
            _tmp = []
            for k,v in notify.items():
                _notification = deepcopy(v)
                _notification['action'] = k
                _tmp.append(_notification)
            notify = _tmp

        notifications = {}
        for notify_name in notify:
            try:
                notify_spec = Config.object()

                if isinstance(notify_name, string):
                    notify_spec.update(deepcopy(notify_specs[notify_name]))
                    notify_spec['action'] = notify_name

                else:
                    notify_spec.update(deepcopy(notify_name))
                    notify_name = notify_spec['action']

                underscore = Config(data.get('match_hit._source', {}))

                text, data_s, plain, html = self.compose_message_text(
                    data.get('message', {}),
                    data,
                    _ = underscore,
                    trigger = data,
                    )

                log.debug("data: %r", data)

                if subject is None:
                    try:
                        subject = data.getval('message.subject',
                            '[elastico] notification')
                    except:
                        subject = '[elastico] notification'

                message = {
                    'text': text,
                    'data': data_s,
                    'plain': plain,
                    'html': html,
                    'subject': subject,
                }

                notify_spec['message.subject'] = subject
                notify_spec['message.text'] = text

                log.debug("notify_spec: %r", notify_spec)
                self.transport_notification(message, notify_spec, data.format())

                if self.config.get('dry_run'):
                    notify_spec['status'] = 'dry_run'
                else:
                    notify_spec['status'] = 'ok'

                notifications[notify_name] = data.format(notify_spec)

            except Exception as e:
                # log.error('Error while processing notification %s: %s', notify_name, e)

                notify_spec['status'] = 'error'

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

                log.error("      notification error %s", message, exc_info=1)
                notify_spec['error'] = {
                    'message': message,
                    'details': details,
                }

                log.debug('nspec[error]: %s', notify_spec['error'])

            log.info("      notification %s -> %s", notify_name, notify_spec['status'])

            self.update_data('triggered', notifications)

