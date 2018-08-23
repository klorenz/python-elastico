import yaml, io, pyaml, re
from textwrap import dedent
from elastico.util import PY3, to_dt, dt_isoformat
from elastico.alert import Alerter
from elastico.config import Config

if PY3:
    unicode = str

def make_config(s):
    return Config.object(s)

def test_alerter_expand_rules():
    import logging
    logging.getLogger().setLevel(logging.DEBUG)

    config = Config.object("""
        foo: bar
        alert:
            alert_defaults:
                honey:
                    a: a_value
                boney:
                    b: '{foo}'

            rules:
              - name: foo
                index: an_index
                alerts:
                - type: honey
                  match: x
                - type: boney
                  match: y
    """)

    data = [x for x in Alerter.expand_rules(config)]

    assert data == [
        {'a': 'a_value', 'key': 'foo', 'match': 'x', 'type': 'honey', 'index': 'an_index', 'name': 'foo'},
        {'b': 'bar', 'key': 'foo', 'match': 'y', 'type': 'boney', 'index': 'an_index', 'name': 'foo'}
        ]

def test_alerter_expand_rules_foreach():
    import logging
    logging.getLogger().setLevel(logging.DEBUG)

    config = Config.object("""
        foo: bar
        alert:
            alert_defaults:
                honey:
                    a: a_value
                boney:
                    b: '{foo}'

            rules:
              - name: foo
                foreach:
                    host:
                        - foo
                        - bar
                    mount_point:
                        - x
                        - y
                index: an_index
                alerts:
                - type: honey
                  key: '{name}-{host}-{mount_point}'
                  match: x

                - type: boney
                  key: '{name}-{host}-{mount_point}'
                  match: y
    """)

    data = [x for x in Alerter.expand_rules(config)]
    expected = []
    for host in ['foo', 'bar']:
        for mount_point in ['x', 'y']:
            expected.append({
                'a': 'a_value',
                'match': 'x',
                'type': 'honey',
                'index': 'an_index',
                'name': 'foo',
                'key': '{name}-{host}-{mount_point}',
                'host': host,
                'mount_point': mount_point
            })
            expected.append({
                'b': 'bar',
                'key': '{name}-{host}-{mount_point}',
                'match': 'y',
                'type': 'boney',
                'index': 'an_index',
                'name': 'foo',
                'host': host,
                'mount_point': mount_point
            })


def test_alerter_alert(monkeypatch):
    alerter = Alerter(config=make_config("""
        alert:
            rules:
                - name: test
                  alerts:
                  - type: warning
                    match: x
                  - type: fatal
                    match: y
    """))

    def mock_matching_succeeds(rule):
        if rule['match'] == 'x':
            rule['match_hits_total'] = 4
            rule['match_hit'] = {'foo': 'bar'}
            rule['match_hits'] = True
            return True
        if rule['match'] == 'y':
            rule['match_hits_total'] = 0
            rule['match_hits'] = False
            return False
        return True

    monkeypatch.setattr(alerter, 'do_match', mock_matching_succeeds)

    at = to_dt("2018-05-05 10:07:00")
    alerter.process_rules(at=at)

    at_s = dt_isoformat(at)

    assert alerter.STATUS == {
        'fatal': {
            'test': {
                'status': 'ok',
                '@timestamp': at_s,
                'at': at_s,
                'match_hits': False,
                'name': 'test',
                'key': 'test',
                'type': 'fatal',
                'match': 'y',
                'match_hits_total': 0
            }
        },
        'warning': {
            'test': {
                'name': 'test',
                '@timestamp': at_s,
                'at': at_s,
                'status': 'alert',
                'match_hit': {'foo': 'bar'},
                'match_hits': True,
                'key': 'test',
                'type': 'warning',
                'match': 'x',
                'match_hits_total': 4
            }
        }
    }

def test_alerter_alert_elasticsearch(monkeypatch):
    from elastico.connection import elasticsearch
    es = elasticsearch()

    try:
        alerter = Alerter(config=Config.object("""
            status_storage: elasticsearch
            alert:
                rules:
                    - name: test
                      alerts:
                      - type: warning
                        match: x
                      - type: fatal
                        match: y
        """), es_client=es)

        def mock_matching_succeeds(rule):
            if rule['match'] == 'x':
                rule['match_hits_total'] = 4
                rule['match_hit'] = {'foo': 'bar'}
                rule['match_hits'] = True
                return True
            if rule['match'] == 'y':
                rule['match_hits_total'] = 0
                rule['match_hits'] = False
                return False
            return True

        monkeypatch.setattr(alerter, 'do_match', mock_matching_succeeds)

        at = to_dt("2018-05-05 10:02:00")
        alerter.process_rules(at=at)

        status = {}
        status['warning'] = alerter.read_status(key='test', type='warning')
        status['fatal'] = alerter.read_status(key='test', type='fatal')

        at_s = dt_isoformat(at)

        assert status == {
            'fatal': {
                '@timestamp': at_s,
                'at': at_s,
                'name': 'test',
                'status': 'ok',
                'match_hits': False,
                'key': 'test',
                'type': 'fatal',
                'match': 'y',
                'match_hits_total': 0
            },
            'warning': {
                '@timestamp': at_s,
                'at': at_s,
                'name': 'test',
                'status': 'alert',
                'match_hit': {'foo': 'bar'},
                'match_hits': True,
                'key': 'test',
                'type': 'warning',
                'match': 'x',
                'match_hits_total': 4
            }
        }
    finally:
        alerter.wipe_status_storage()

def test_alerter_alert_filesystem(monkeypatch, tmpdir):
    from elastico.connection import elasticsearch
    es = elasticsearch()

    try:
        alerter = Alerter(config=Config.object("""
            status_storage: filesystem
            status_storage_path: %s
            alert:
                rules:
                    - name: test
                      alerts:
                      - type: warning
                        match: x
                      - type: fatal
                        match: y
        """ % tmpdir.strpath), es_client=es)

        def mock_matching_succeeds(rule):
            if rule['match'] == 'x':
                rule['match_hits_total'] = 4
                rule['match_hit'] = {'foo': 'bar'}
                rule['match_hits'] = True
                return True
            if rule['match'] == 'y':
                rule['match_hits_total'] = 0
                rule['match_hits'] = False
                return False
            return True

        monkeypatch.setattr(alerter, 'do_match', mock_matching_succeeds)

        at = to_dt("2018-05-05 10:02:00")
        alerter.process_rules(at=at)

        status = {}
        status['warning'] = alerter.read_status(key='test', type='warning')
        status['fatal'] = alerter.read_status(key='test', type='fatal')

        at_s = dt_isoformat(at)

        assert status == {
            'fatal': {
                '@timestamp': at_s,
                'at': at_s,
                'name': 'test',
                'status': 'ok',
                'match_hits': False,
                'key': 'test',
                'type': 'fatal',
                'match': 'y',
                'match_hits_total': 0
            },
            'warning': {
                '@timestamp': at_s,
                'at': at_s,
                'name': 'test',
                'status': 'alert',
                'match_hit': {'foo': 'bar'},
                'match_hits': True,
                'key': 'test',
                'type': 'warning',
                'match': 'x',
                'match_hits_total': 4
            }
        }
    finally:
        alerter.wipe_status_storage()

def test_alerter_match():
    from elastico.connection import elasticsearch
    from elasticsearch.helpers import bulk

    es = elasticsearch()

    index  = "test-alerter-match"
    values = [ 20, 21, 19, 15, 12, 11, 4, 5, 6, 21, 22]

    documents = [
        {
            "_index": index,
            "_type": "doc",
            "_id": i,
            "value": v,
            "@timestamp": to_dt("2018-05-05 10:%02d:00" % i),
        } for i,v in enumerate(values)
    ]

    try:
        success, failed = bulk(es, documents)
        assert len(failed) == 0, "error bulk importing test data"
        es.indices.refresh(index)
        #assert False

        alerter = Alerter(config = Config.object("""
            alert:
                rules:
                    - name: value-check
                      timeframe:
                        minutes: 5
                      alerts:
                        - type: fatal
                          match: "value:[0 TO 10]"
                          index: test-alerter-match
                        - type: warning
                          match: "value:[10 TO 13]"
                          index: test-alerter-match
        """), es_client=es)

        at = to_dt("2018-05-05 10:02:00")
        alerter.process_rules(at=at)

        at_s = dt_isoformat(at)

        assert alerter.STATUS == {
            'fatal': {
                'value_check': {
                    'name': 'value-check',
                    '@timestamp': at_s,
                    'at': at_s,
                    'timeframe':{'minutes': 5},
                    'index': 'test-alerter-match',
                    'key': 'value_check',
                    'match': 'value:[0 TO 10]',
                    'match_hits': False,
                    'match_hits_total': 0,
                    'status': 'ok',
                    'type': 'fatal'
                }
            },
            'warning': {
                'value_check': {
                    'name': 'value-check',
                    '@timestamp': at_s,
                    'at': at_s,
                    'timeframe':{'minutes': 5},
                    'index': 'test-alerter-match',
                    'key': 'value_check',
                    'match': 'value:[10 TO 13]',
                    'match_hits': False,
                    'match_hits_total': 0,
                    'status': 'ok',
                    'type': 'warning'
                }
            }
        }

        at = to_dt("2018-05-05 10:07:00")
        alerter.process_rules(at=at)
        at_s = dt_isoformat(at)

        assert alerter.STATUS == {
            'fatal': {
                'value_check': {
                    'name': 'value-check',
                    '@timestamp': at_s,
                    'at': at_s,
                    'timeframe':{'minutes': 5},
                    'index': 'test-alerter-match',
                     'key': 'value_check',
                     'match': 'value:[0 TO 10]',
                     'match_hit': {
                         '_id': '7',
                         '_index': 'test-alerter-match',
                         '_score': None,
                         '_source': {
                             '@timestamp': '2018-05-05T10:07:00',
                             'value': 5
                         },
                         '_type': 'doc',
                         'sort': [1525514820000]
                     },

                     'match_hits': True,
                     'match_hits_total': 2,
                     'status': 'alert',
                     'type': 'fatal'
                }
            },
            'warning': {
                'value_check': {
                    'name': 'value-check',
                    '@timestamp': at_s,
                    'at': at_s,
                    'timeframe':{'minutes': 5},
                    'index': 'test-alerter-match',
                    'key': 'value_check',
                    'match': 'value:[10 TO 13]',
                    'match_hit': {
                        '_id': '5',
                        '_index': 'test-alerter-match',
                        '_score': None,
                        '_source': {
                            '@timestamp': '2018-05-05T10:05:00',
                            'value': 11
                        },
                        '_type': 'doc',
                        'sort': [1525514700000]
                    },
                    'match_hits': True,
                    'match_hits_total': 2,
                    'status': 'alert',
                    'type': 'warning'
                }
            }
        }



    finally:
        es.indices.delete(index)

def test_alerter_email(monkeypatch):
    alerter = Alerter(config=Config.object("""
        alert:
            alert_defaults:
                hummhomm:
                    notify:
                    - transport: email
                      email:
                        to: treebeard@middle.earth

            rules:
                - name: test
                  alerts:
                  - type: hummhomm
                    match: x
                  - type: fatal
                    match: y
    """))

    def mock_matching_succeeds(rule):
        if rule['match'] == 'x':
            rule['match_hits_total'] = 4
            rule['match_hit'] = {'foo': 'bar'}
            rule['match_hits'] = True
            return True
        if rule['match'] == 'y':
            rule['match_hits_total'] = 0
            rule['match_hits'] = False
            return False
        return True

    def mock_matching_fails(*args):
        return False

    monkeypatch.setattr(alerter, 'do_match', mock_matching_succeeds)
    from smtplib import SMTP

    mock_args = {}
    def mock_sendmail(**kwargs):
        mock_args['sendmail'] = kwargs

    monkeypatch.setattr(alerter, 'email_sendmail', mock_sendmail)

    at = to_dt("2018-05-05 10:07:00")
    alerter.process_rules(at=at)

    message = mock_args['sendmail']['message']
    del mock_args['sendmail']['message']

    assert mock_args['sendmail'] == {
        'host': 'localhost',
        'port': 0,
        'use_ssl': False,
        'username': None,
        'password': None,
        'sender': 'noreply',
        'recipients': ['treebeard@middle.earth'],
    }

    msg = re.sub('===============\d+==', '===============11111==', message)

    # python 2.7 compatibility
    prefix = 'Content-Type: multipart/alternative; boundary="===============11111=="\n'
    if not PY3:
        prefix = ('Content-Type: multipart/alternative;\n'
                  ' boundary="===============11111=="\n')

    assert msg == prefix + dedent("""\
            MIME-Version: 1.0
            From: noreply
            Subject: [elastico] ALERT - hummhomm test
            To: treebeard@middle.earth

            --===============11111==
            Content-Type: text/plain; charset="us-ascii"
            MIME-Version: 1.0
            Content-Transfer-Encoding: 7bit



                at: 2018-05-05 10:07:00
                key: test
                match: x
                match_hit:
                  foo: bar
                match_hits: true
                match_hits_total: 4
                name: test
                notify:
                  - email:
                      to: treebeard@middle.earth
                    transport: email
                status: alert
                type: hummhomm


            --===============11111==
            Content-Type: text/html; charset="us-ascii"
            MIME-Version: 1.0
            Content-Transfer-Encoding: 7bit

            <pre><code>at: 2018-05-05 10:07:00
            key: test
            match: x
            match_hit:
              foo: bar
            match_hits: true
            match_hits_total: 4
            name: test
            notify:
              - email:
                  to: treebeard@middle.earth
                transport: email
            status: alert
            type: hummhomm
            </code></pre>
            --===============11111==--
         """)

# def test_get_rule_value():
#     alerter = Alerter()
#     rule = {'foo': {'bar': 'value'}}
#     assert alerter.get_rule_value(rule, "foo.bar") == 'value'

