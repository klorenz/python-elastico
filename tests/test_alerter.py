import yaml, io, pyaml, re
from textwrap import dedent
from elastico.util import PY3, to_dt
if PY3:
    unicode = str

def make_config(s):
    return yaml.load(io.StringIO(dedent(unicode(s))))


def test_alerter_expand_rules():
    import logging
    logging.getLogger().setLevel(logging.DEBUG)

    from elastico.alert import Alerter
    config = make_config("""
        foo: bar
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
        {'a': 'a_value', 'key': 'foo', 'match': 'x', 'type': 'honey'},
        {'b': 'bar', 'key': 'foo', 'match': 'y', 'type': 'boney'}
        ]


def test_alerter_alert(monkeypatch):
    from elastico.alert import Alerter
    alerter = Alerter(config=make_config("""
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

    alerter.process_rules()

    assert alerter.STATUS == {
        'fatal': {
            'test': {
                'status': 'ok',
                'match_hits': False,
                'key': 'test',
                'type': 'fatal',
                'match': 'y',
                'match_hits_total': 0
            }
        },
        'warning': {
            'test': {
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
    from elastico.alert import Alerter
    from elastico.connection import elasticsearch
    es = elasticsearch()

    try:
        alerter = Alerter(config=make_config("""
            storage_type: elasticsearch
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

        alerter.process_rules()

        status = {}
        status['warning'] = alerter.read_status(key='test', type='warning')
        status['fatal'] = alerter.read_status(key='test', type='fatal')

        assert status == {
            'fatal': {
                'status': 'ok',
                'match_hits': False,
                'key': 'test',
                'type': 'fatal',
                'match': 'y',
                'match_hits_total': 0
            },
            'warning': {
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
    from elastico.alert import Alerter
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
        bulk(es, documents)
        es.indices.refresh(index)

        alerter = Alerter(config = make_config("""
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

        alerter.process_rules(runtime=to_dt("2018-05-05 10:02:00"))

        assert alerter.STATUS == {
            'fatal': {
                'value-check': {
                    'index': 'test-alerter-match',
                    'key': 'value-check',
                    'match': 'value:[0 TO 10]',
                    'match_hits': False,
                    'match_hits_total': 0,
                    'status': 'ok',
                    'type': 'fatal'
                }
            },
            'warning': {
                'value-check': {
                    'index': 'test-alerter-match',
                    'key': 'value-check',
                    'match': 'value:[10 TO 13]',
                    'match_hits': False,
                    'match_hits_total': 0,
                    'status': 'ok',
                    'type': 'warning'
                }
            }
        }

        alerter.process_rules(runtime=to_dt("2018-05-05 10:07:00"))

        import pprint
        pprint.pprint(alerter.STATUS)


        assert alerter.STATUS == {
            'fatal': {
                'value-check': {
                    'index': 'test-alerter-match',
                     'key': 'value-check',
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
                'value-check': {
                    'index': 'test-alerter-match',
                    'key': 'value-check',
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
    from elastico.alert import Alerter
    alerter = Alerter(config=make_config("""
        alert_defaults:
            hummhomm:
                notify:
                - transport: email
                  email_to: treebeard@middle.earth

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
    alerter.process_rules()

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



                key: test
                match: x
                match_hit:
                  foo: bar
                match_hits: true
                match_hits_total: 4
                notify:
                  - email_to: treebeard@middle.earth
                    transport: email
                status: alert
                type: hummhomm


            --===============11111==
            Content-Type: text/html; charset="us-ascii"
            MIME-Version: 1.0
            Content-Transfer-Encoding: 7bit

            <pre><code>key: test
            match: x
            match_hit:
              foo: bar
            match_hits: true
            match_hits_total: 4
            notify:
              - email_to: treebeard@middle.earth
                transport: email
            status: alert
            type: hummhomm
            </code></pre>
            --===============11111==--
         """)


