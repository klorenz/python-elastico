import time
import logging
import sys
from .notifier import Notifier
from .config import Config

log = logging.getLogger('elastico.server')

class Server:
    '''This is a simple class for a server.
    '''

    def __init__(self, config, prefix=None, run=None):
        self.config = config
        self.prefix = prefix
        self.func   = run

    def get_value(self, name, default=None):
        if self.prefix:
            return self.config.get('%s.%s' % (prefix, name), default)
        else:
            return self.config.get(name, default)

    def run(self, count=None, sleep_seconds=None):
        counter = 0
        error_count = 0
        while True:
            self.config.refresh()

            if count is None:
                count = int(self.get_value('serve.count'))
            if sleep_seconds is None:
                sleep_seconds = float(self.get_value('serve.sleep_seconds', 60))

            log.info("run -- counter=%r, count=%r, sleep_seconds=%r",
                counter, count, sleep_seconds)

            logspec = self.get_value('logging', {})
            if logspec:
                logspec = self.config.flatten(logspec)
                for k,v in logspec:
                    if k == 'ROOT':
                        k = None
                    logger = logging.getLogger(k)
                    logger.setLevel(getattr(logging, v))
                    log.info("change loglevel -- logger=%s, level=%s", k, v)

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
                    "message=%r error_count=%r", e, error_count)

                notifier = Notifier(self.config, prefixes=[self.prefix])
                notify = self.get_value('serve.error_notify', [])
                subject = '[elastico] fatal error in server function'

                if error_count > 10:
                    subject = '[elastico] too many errors, giving up' % error_count

                notifier.notify(notify=notify, data=Config({
                    'message': {
                        'subject': subject,
                        'text': "error_count=%s\n\n" % error_count +
                            traceback.format_exc()
                    }
                }))

                if error_count > 10:
                    sys.exit(1)

            time.sleep(sleep_seconds)
            counter += 1
