from string import Formatter
import logging, json
log = logging.getLogger('elastico.formatter')
from .util import indent

class ElasticoFormatter(Formatter):

    def format_field(self, value, format_spec):
        log.debug("format_field -- value=%r, format_spec=%r", value, format_spec)

        if format_spec.endswith('gb'):
            result = ('{:'+format_spec[:-2]+'f}').format(value/1000000000.0)
        elif format_spec.endswith('mb'):
            result = ('{:'+format_spec[:-2]+'f}').format(value/1000000.0)
        elif format_spec.endswith('json'):
            try:
                ind=int(format_spec[:-4])
            except:
                ind=None

            result = json.dumps(value, indent=ind)
        elif format_spec.endswith('indent'):
            try:
                first, rest = format_spec[:-6].split('.')
                first = " "*int(first)
                rest = " "*int(rest)
            except:
                first=''
                try:
                    rest = " "*int(format_spec[:-6])
                except:
                    rest=''

            result = indent(value, rest)
        else:
            result = super(ElasticoFormatter, self).format_field(value, format_spec)

        log.debug("result=%r", result)

        return result

    # def convert_field(self, value, conversion):
    #     if conversion == 'json':
    #         result = json.dumps(value, indent=2)
    #     else:
    #         parent = super(ElasticoFormatter, self)
    #         result = parent.convert_field(value, conversion)
    #
    #     return result
    # 
