from string import Formatter
import logging
log = logging.getLogger('elastico.formatter')

class ElasticoFormatter(Formatter):

    def format_field(self, value, format_spec):
        log.debug("value=%s, format_spec=%s", value, format_spec)
        if format_spec.endswith('gb'):
            result = ('{:'+format_spec[:-2]+'f}GB').format(value/1000000000.0)
        elif format_spec.endswith('mb'):
            result = ('{:'+format_spec[:-2]+'f}MB').format(value/1000000.0)
        else:
            result = super(ElasticoFormatter, self).format_field(value, format_spec)

        log.debug("result=%s", result)

        return result

