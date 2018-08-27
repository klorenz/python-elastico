from elasticsearch import Elasticsearch
from .util import get_netrc_login_data
import logging
log = logging.getLogger('elastico.connection')

def elasticsearch(config={}):
    # elasticsearch configuration
    elasticsearch = config.get('elasticsearch', {})

    try:
        (user, password) = get_netrc_login_data(config, 'elasticsearch.netrc')
        elasticsearch['http_auth'] = (user, password)
        del elasticsearch['netrc']
    except LookupError:
        try:
            (user, password) = get_netrc_login_data(config, 'netrc')
            elasticsearch['http_auth'] = (user, password)
        except LookupError:
            pass

    log.debug("elasticsearch: %s", elasticsearch)

    es = Elasticsearch(**elasticsearch)
    return es
