import time
import logging
import sys
from datetime import datetime, timedelta
from .notifier import Notifier
from .config import Config
from .util import to_dt, dt_isoformat, get_alerts

log = logging.getLogger('elastico.server')

class Server:
    '''This is a simple class for a server.
    '''

    def __init__(self, config, prefix=None, run=None):
        self.config = config
        self.prefix = prefix
        self.func   = run

        before_5s = to_dt(datetime.utcnow() - timedelta(seconds=5))
        if before_5s < to_dt(self.config.get('at')) < to_dt(datetime.utcnow()):
            self.run_now = True
        else:
            self.run_now = False

    def get_value(self, name, default=None):
        if self.prefix:
            return self.config.get('%s.%s' % (prefix, name), default)
        else:
            return self.config.get(name, default)

    def run(self, count=None, sleep_seconds=None):
        counter = 0
        error_count = 0
        while True:
            if self.run_now:
                _at = dt_isoformat(to_dt(datetime.utcnow()), timespec='seconds')
            else:
                _at = dt_isoformat(
                    to_dt(self.config.get('at')) +
                    timedelta(seconds=int(sleep_seconds))
                    )

            self.config.refresh(at=_at)

            if count is None:
                count = int(self.get_value('serve.count', -1))
            if sleep_seconds is None:
                sleep_seconds = float(self.get_value('serve.sleep_seconds', 60))

            log.info("run -- counter=%r, count=%r, sleep_seconds=%r, at=%r",
                counter, count, sleep_seconds, _at)

            if count > 0:
                if counter >= count:
                    break

            try:
                self.func()
                error_count = 0
            except Exception as e:
                import traceback
                error_count += 1

                log.error("fatal error running server function -- "
                    "message=%r error_count=%r, args=%r", e, error_count, e.args[1:], exc_info=1)

                notifier = Notifier(self.config, prefixes=[self.prefix])
                alerts = get_alerts(self.get_value('serve.alerts', []), context=self.config)
                for alert in alerts:
                    if error_count >= alert.get('error_count', 1):
                        notify = alert.get('notify', [])
                        subject = '[elastico] %s -- exception in server function' % alert.get('type', 'error')

                        notifier.notify(notify=notify, data=Config({
                            'message': {
                                'subject': subject,
                                'text': "error_count=%s\nargs=%r\n\n" % (error_count, args) +
                                    traceback.format_exc()
                            }
                        }))

                if error_count > 10:
                    subject = '[elastico] too many errors, giving up' % error_count

                if error_count > 10:
                    sys.exit(1)

            time.sleep(sleep_seconds)
            counter += 1
