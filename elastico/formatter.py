from string import Formatter
import logging, json
log = logging.getLogger('elastico.formatter')
from .util import indent, slugify

class ElasticoFormatter(Formatter):

    def format_field(self, value, format_spec):
        log.debug("format_field -- value=%r, format_spec=%r", value, format_spec)

        if format_spec.endswith('gb'):
            result = ('{:'+format_spec[:-2]+'f}').format(value/1000000000.0)
        elif format_spec.endswith('mb'):
            result = ('{:'+format_spec[:-2]+'f}').format(value/1000000.0)
        elif format_spec.endswith('slugify'):
            result = slugify(value, strip_=True)
        elif format_spec.endswith('kibana-discover'):
            pass
            # in case of value beeing a string, must set lucene query, else
            # if list, this is a part of a query - must query
            # if dict, this is a complete query
            # https://kibana.moduleworks.com/app/kibana#/discover?_g=()&_a=(columns:!(_source),filters:!(('$state':(store:appState),meta:(alias:!n,disabled:!f,index:'heartbeat-*',key:query,negate:!f,type:custom,value:'%7B%22bool%22:%7B%22must%22:%5B%7B%22term%22:%7B%22monitor.host%22:%22cal2.moduleworks.com%22%7D%7D%5D%7D%7D'),query:(bool:(must:!((term:(monitor.host:cal2.moduleworks.com))))))),index:'heartbeat-*',interval:auto,query:(language:kuery,query:'host.name:%20mail'),sort:!('@timestamp',desc))
            # https://kibana.moduleworks.com/app/kibana#/discover?_g=()&_a=(columns:!(_source),filters:!(('$state':(store:appState),meta:(alias:!n,disabled:!f,index:'heartbeat-*',key:query,negate:!f,type:custom,value:'%7B%22bool%22:%7B%22must%22:%5B%7B%22term%22:%7B%22monitor.host%22:%22cal2.moduleworks.com%22%7D%7D%5D%7D%7D'),query:(bool:(must:!((term:(monitor.host:cal2.moduleworks.com))))))),index:'heartbeat-*',interval:auto,query:(language:lucene,query:'host.name:%20mail'),sort:!('@timestamp',desc))

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
