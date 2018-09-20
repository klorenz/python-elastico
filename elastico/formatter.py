from string import Formatter
import logging, json
log = logging.getLogger('elastico.formatter')
from .util import indent, slugify
from urllib.parse import urlencode

class ElasticoFormatter(Formatter):

    def format_field(self, value, format_spec):
        log.debug("format_field -- value=%r, format_spec=%r", value, format_spec)

        if format_spec.endswith('gb'):
            result = ('{:'+format_spec[:-2]+'f}').format(value/1000000000.0)
        elif format_spec.endswith('mb'):
            result = ('{:'+format_spec[:-2]+'f}').format(value/1000000.0)
        elif format_spec.endswith('slugify'):
            result = slugify(value, strip_=True)
#         elif format_spec.endswith('kibana-discover'):
#             kibana_url = value.get('kibana_url')
#             if not kibana_url:
#                 kibana_url = '/discover?'
#             else:
#                 kibana_url = '{}/app/kibana#/discover?'.format(kibana_url)
#
#             match = value.get('match')
#             lucene_query = ''
#             if isinstance(match, string):
#                 lucene_query = urlencode(match)
#             filters = ''
#
#             index = value.get('kibana_index')
#             if index is None:
#                 index = value.get('index')
#
#             _g = {
#                 'refreshInterval': {
#                     'display': 'Off',
#                     'pause': False,
#                     'value': 0},
#                 'time': {
#                     # from isodatetime mode absolute to isodatetime Z
#                     'from': 'now-15m',
#                     'mode': 'quick',
#                     'to': 'now'
#                 }
#             }
#
#             _a = {
#                 'columns': ['_source'],
#                 'filters': [
#
#                 ]
#                 'index': index,
#                 'interval': 'auto',
#                 'query': {'language': 'lucene', 'query': lucene_query},
#                 'sort': ['@timestamp', 'desc']
#             }
#
#             _a2 = {'columns': ['_source'], 'filters': [{'$state': {'store': 'appState'}, 'meta': {'alias': None, 'disabled': False, 'index': 'dd5cc910-b083-11e8-93e0-cdcffe2ec1a0', 'key': 'query', 'negate': False, 'type': 'custom', 'value': '%7B%22term%22:%7B%22type%22:%22fatal%22%7D%7D'}, 'query': {'term': {'type': 'fatal'}}}], 'index': 'dd5cc910-b083-11e8-93e0-cdcffe2ec1a0', 'interval': 'auto', 'query': {'language': 'lucene', 'query': ''}, 'sort': ['@timestamp', 'desc']}
#
# https://kibana.domain/app/kibana#/discover?_g=(refreshInterval:(display:Off,pause:!f,value:0),time:(from:'2018-09-19T21:52:43.131Z',mode:absolute,to:'2018-09-19T22:07:43.136Z'))&_a=(columns:!(_source),filters:!(('$state':(store:appState),meta:(alias:!n,disabled:!f,index:dd5cc910-b083-11e8-93e0-cdcffe2ec1a0,key:query,negate:!f,type:custom,value:'%7B%22term%22:%7B%22type%22:%22fatal%22%7D%7D'),query:(term:(type:fatal)))),index:dd5cc910-b083-11e8-93e0-cdcffe2ec1a0,interval:auto,query:(language:lucene,query:''),sort:!('@timestamp',desc))
#             return kibana_rul + "_g=()&_a=(columns:!(_source),filters:!(('$state':(store:appState),meta:(alias:!n,disabled:!f,index:'heartbeat-*',key:query,negate:!f,type:custom,value:'%7B%22bool%22:%7B%22must%22:%5B%7B%22term%22:%7B%22monitor.host%22:%22cal2.domain%22%7D%7D%5D%7D%7D'),query:(bool:(must:!((term:(monitor.host:cal2.domain))))))),index:'heartbeat-*',interval:auto,query:(language:kuery,query:'host.name:%20mail'),sort:!('@timestamp',desc))
#
#             # https://kibana.domain/app/kibana#/discover?_g=(refreshInterval:(display:Off,pause:!f,value:0),time:(from:now-15m,mode:quick,to:now))&_a=(columns:!(_source),index:dd5cc910-b083-11e8-93e0-cdcffe2ec1a0,interval:auto,query:(language:lucene,query:'elastico.alerter:%20main%20AND%20host_name:%20cal2'),sort:!('@timestamp',desc))
#
#             # this returns the exact   https://kibana_urlkibana.domain/app/kibana#
#             #/discover?_g=()&_a=(columns:!(_source),filters:!(('$state':(store:appState),meta:(alias:!n,disabled:!f,index:'heartbeat-*',key:query,negate:!f,type:custom,value:'%7B%22bool%22:%7B%22must%22:%5B%7B%22term%22:%7B%22monitor.host%22:%22cal2.domain%22%7D%7D%5D%7D%7D'),query:(bool:(must:!((term:(monitor.host:cal2.domain))))))),index:'heartbeat-*',interval:auto,query:(language:kuery,query:'host.name:%20mail'),sort:!('@timestamp',desc))
#             pass
#             # in case of value beeing a string, must set lucene query, else
#             # if list, this is a part of a query - must query
#             # if dict, this is a complete query
#             # https://kibana_urlkibana.domain/app/kibana#/discover?_g=()&_a=(columns:!(_source),filters:!(('$state':(store:appState),meta:(alias:!n,disabled:!f,index:'heartbeat-*',key:query,negate:!f,type:custom,value:'%7B%22bool%22:%7B%22must%22:%5B%7B%22term%22:%7B%22monitor.host%22:%22cal2.domain%22%7D%7D%5D%7D%7D'),query:(bool:(must:!((term:(monitor.host:cal2.domain))))))),index:'heartbeat-*',interval:auto,query:(language:kuery,query:'host.name:%20mail'),sort:!('@timestamp',desc))
#             # https://kibana.domain/app/kibana#/discover?_g=()&_a=(columns:!(_source),filters:!(('$state':(store:appState),meta:(alias:!n,disabled:!f,index:'heartbeat-*',key:query,negate:!f,type:custom,value:'%7B%22bool%22:%7B%22must%22:%5B%7B%22term%22:%7B%22monitor.host%22:%22cal2.domain%22%7D%7D%5D%7D%7D'),query:(bool:(must:!((term:(monitor.host:cal2.domain))))))),index:'heartbeat-*',interval:auto,query:(language:lucene,query:'host.name:%20mail'),sort:!('@timestamp',desc))

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
