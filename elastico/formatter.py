from string import Formatter
import logging
log = logging.getLogger('elastico.formatter')

class ElasticoFormatter(Formatter):

    def format_field(self, value, format_spec):
        log.debug("format_field -- value=%r, format_spec=%r", value, format_spec)

        if format_spec.endswith('gb'):
            result = ('{:'+format_spec[:-2]+'f}').format(value/1000000000.0)
        elif format_spec.endswith('mb'):
            result = ('{:'+format_spec[:-2]+'f}').format(value/1000000.0)
        elif format_spec.endswith('json'):
            try:
                indent=int(format_spec[:-4])
            except:
                indent=None

            result = json.dumps(value, indent=indent)
        else:
            result = super(ElasticoFormatter, self).format_field(value, format_spec)

        log.debug("result=%r", result)

        return result

