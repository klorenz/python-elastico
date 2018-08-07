from elasticsearch import Elasticsearch
from .util import get_netrc_login_data


def elasticsearch(config={}):
    # elasticsearch configuration
    elasticsearch = config.get('elasticsearch', {})

    try:
        (user, password) = get_netrc_login_data(config, 'netrc')
        elasticsearch['http_auth'] = (user, password)
    except LookupError:
        pass

    es = Elasticsearch(**elasticsearch)
    return es
