import yaml, io, pyaml, re
from textwrap import dedent, indent
from elastico.util import PY3, to_dt, dt_isoformat
from elastico.alerter import Alerter
from elastico.config import Config
from pprint import pprint
from elastico.notifier import Notifier

if PY3:
    unicode = str

def make_config(s):
    return Config.object(s)


def get_test_iterator_config():
    config = Config.object("""
        alerter:
            alert_defaults:
                honey:
                    a: a_value
                boney:
                    b: '{foo}'

            rules:
              - name: dep-foo
                foo: bar
                index: an_index
                alerts:
                    honey:
                      if: foo.honey
                      match:
                        match: z
                    boney:
                      match: y

              - name: foo
                foo: bar
                index: an_index
                alerts:
                    honey:
                      match: x
                    boney:
                      match: y

              - name: xyz
                foo: bar2
                index: an_index
                alerts:
                    honey:
                        match: x1
                    boney:
                        match: y1
    """)
    config['at'] = '2018-05-05 10:02:00'
    return config

def test_alerter_iterate_rules():
    config = get_test_iterator_config()
    alerter = Alerter(config=config)
    result = [r for r in alerter.iterate_rules()]
    pprint(result)
    assert result == [
        {'alerts': {
            'boney': {'match': 'y'},
            'honey': {'match': 'x'}
            },
         'foo': 'bar',
         'index': 'an_index',
         'key': 'foo',
         'name': 'foo'},
        {'alerts': {'boney': {'match': 'y1'}, 'honey': {'match': 'x1'}},
         'foo': 'bar2',
         'index': 'an_index',
         'key': 'xyz',
         'name': 'xyz'},
        {'alerts': {
            'boney': {'match': 'y'},
            'honey': {'if': 'foo.honey', 'match': {'match': 'z'}}
            },
         'foo': 'bar',
         'index': 'an_index',
         'key': 'dep_foo',
         'name': 'dep-foo'},
         ]


def test_alerter_rule_iterate_alerts():
    config = get_test_iterator_config()
    alerter = Alerter(config=config)
    result = [r for r in alerter.iterate_alerts()]
    pprint(result)
    assert result == [
    ({'alerts': {'boney': {'match': 'y'}, 'honey': {'match': 'x'}},
   'foo':    'bar',
   'index': 'an_index',
   'key': 'foo',
   'name': 'foo'},
  [{'a': 'a_value',
    'foo': 'bar',
    'index': 'an_index',
    'key': 'foo',
    'match': 'x',
    'name': 'foo',
    'type': 'honey'},
   {'b': 'bar',
    'foo': 'bar',
    'index': 'an_index',
    'key': 'foo',
    'match': 'y',
    'name': 'foo',
    'type': 'boney'}]),
 ({'alerts': {'boney': {'match': 'y1'}, 'honey': {'match': 'x1'}},
   'foo': 'bar2',
   'index': 'an_index',
   'key': 'xyz',
   'name': 'xyz'},
  [{'a': 'a_value',
    'foo': 'bar2',
    'index': 'an_index',
    'key': 'xyz',
    'match': 'x1',
    'name': 'xyz',
    'type': 'honey'},
   {'b': 'bar2',
    'foo': 'bar2',
    'index': 'an_index',
    'key': 'xyz',
    'match': 'y1',
    'name': 'xyz',
    'type': 'boney'}]),
 ({'alerts': {'boney': {'match': 'y'},
              'honey': {'if': 'foo.honey', 'match': {'match': 'z'}}},
   'foo': 'bar',
   'index': 'an_index',
   'key': 'dep_foo',
   'name': 'dep-foo'},
  [{'a': 'a_value',
    'foo': 'bar',
    'if': 'foo.honey',
    'index': 'an_index',
    'key': 'dep_foo',
    'match': {'match': 'z'},
    'name': 'dep-foo',
    'type': 'honey'},
   {'b': 'bar',
    'foo': 'bar',
    'index': 'an_index',
    'key': 'dep_foo',
    'match': 'y',
    'name': 'dep-foo',
    'type': 'boney'}])]

def get_test_expand_rules_config():
    config = Config.object("""
        alerter:
            alert_defaults:
                honey:
                    a: a_value
                boney:
                    b: '{foo}'

            rules:
              - name: foo
                foo: bar
                index: an_index
                alerts:
                    honey:
                        match: x
                    boney:
                        match: y
    """)
    config['at'] = '2018-05-05 10:02:00'
    return config


def test_alerter_expand_alerts():
    Alerter.reset_last_check()
    Alerter.reset_status()

    config = get_test_expand_rules_config()
    alerter = Alerter(config=config)

    import logging
    logging.getLogger().setLevel(logging.DEBUG)

    data = [a for r,alerts in alerter.iterate_alerts() for a in alerts]
    pprint(data)
    assert data == [{'a': 'a_value',
          'foo': 'bar',
          'index': 'an_index',
          'key': 'foo',
          'match': 'x',
          'name': 'foo',
          'type': 'honey'},
         {'b': 'bar',
          'foo': 'bar',
          'index': 'an_index',
          'key': 'foo',
          'match': 'y',
          'name': 'foo',
          'type': 'boney'}]


def test_alerter_expand_alerts_foreach():
    import logging
    logging.getLogger().setLevel(logging.DEBUG)
    Alerter.reset_last_check()
    Alerter.reset_status()


    config = Config.object("""
        a_list:
            - foo
            - bar
        foo: bar
        alerter:
            alert_defaults:
                honey:
                    a: a_value
                boney:
                    b: '{foo}'

            rules:
              - name: foo
                foreach:
                    host: >
                        *a_list
                    mount_point:
                        - x
                        - y
                index: an_index
                alerts:
                    honey:
                          key: '{name}-{host}-{mount_point}'
                          match: x
                    boney:
                          key: '{name}-{host}-{mount_point}'
                          match: y
    """)
    config['at'] = '2018-05-05 10:02:00'

    alerter = Alerter(config=config)
    data = [a for r,alerts in alerter.iterate_alerts() for a in alerts]

    expected = []
    for host in ['foo', 'bar']:
        for mount_point in ['x', 'y']:
            expected.append({
                'a': 'a_value',
                'match': 'x',
                'type': 'honey',
                'index': 'an_index',
                'name': 'foo',
                'key': 'foo-{host}-{mount_point}'.format(host=host, mount_point=mount_point),
                'host': host,
                'mount_point': mount_point
            })
            expected.append({
                'b': '{foo}',
                'key': 'foo-{host}-{mount_point}'.format(host=host, mount_point=mount_point),
                'match': 'y',
                'type': 'boney',
                'index': 'an_index',
                'name': 'foo',
                'host': host,
                'mount_point': mount_point
            })

    assert expected == data


def test_alerter_alert(monkeypatch):
    Alerter.reset_last_check()
    Alerter.reset_status()

    def mock_matching_succeeds(rule):
        if rule['match'] == 'x':
            rule['match_hits_total'] = 4
            rule['match_hit'] = {'foo': 'bar'}
            rule['alert_trigger'] = True
            return True
        if rule['match'] == 'y':
            rule['match_hits_total'] = 0
            rule['alert_trigger'] = False
            return False
        return True

    def get_alerter(**kwargs):
        alerter = Alerter(config=make_config("""
            alerter:
                rules:
                    - name: test
                      alerts:
                        warning:
                            match: x
                        fatal:
                            match: y
        """))
        alerter.config.update(kwargs)

        monkeypatch.setattr(alerter, 'do_match', mock_matching_succeeds)
        return alerter

    at = to_dt("2018-05-05 10:07:00")
    get_alerter(at=at).check_alerts()

    at_s = dt_isoformat(at)
    pprint(Alerter.STATUS)
    assert Alerter.STATUS == {'fatal': {'test': {'@timestamp': '2018-05-05T10:07:00Z',
                    'alert_trigger': False,
                    'key': 'test',
                    'match': 'y',
                    'match_hits_total': 0,
                    'name': 'test',
                    'status': {'current': 'ok',
                               'next_check': 0,
                               'previous': 'ok'},
                    'type': 'fatal'}},
 'rule': {'test': {'@timestamp': '2018-05-05T10:07:00Z',
                   'key': 'test',
                   'name': 'test',
                   'notify': [],
                   'status.id': 'test_2018-05-05T10:07:00Z',
                   'status.start': '2018-05-05T10:07:00Z',
                   'type': 'rule'}},
 'warning': {'test': {'@timestamp': '2018-05-05T10:07:00Z',
                      'alert_trigger': True,
                      'key': 'test',
                      'match': 'x',
                      'match_hit': {'foo': 'bar'},
                      'match_hits_total': 4,
                      'name': 'test',
                      'status': {'current': 'alert',
                                 'next_check': 0,
                                 'previous': 'ok'},
                      'type': 'warning'}}}



def test_alerter_alert_elasticsearch(monkeypatch):
    from elastico.connection import elasticsearch
    Alerter.reset_last_check()
    Alerter.reset_status()
    es = elasticsearch()

    try:
        def get_alerter(**kwargs):
            alerter = Alerter(config=Config.object("""
                status_storage: elasticsearch
                alerter:
                    rules:
                        - name: test
                          alerts:
                            warning:
                                match: x
                            fatal:
                                match: y
            """), es_client=es)
            alerter.config.update(kwargs)

            def mock_matching_succeeds(rule):
                if rule['match'] == 'x':
                    rule['match_hits_total'] = 4
                    rule['match_hit'] = {'foo': 'bar'}
                    rule['alert_trigger'] = True
                    return True
                if rule['match'] == 'y':
                    rule['match_hits_total'] = 0
                    rule['alert_trigger'] = False
                    return False
                return True

            monkeypatch.setattr(alerter, 'do_match', mock_matching_succeeds)

            return alerter

        at = to_dt("2018-05-05 10:02:00")
        get_alerter(at=at).check_alerts()

        status = {}
        status['warning'] = alerter.read_status(key='test', type='warning')
        status['fatal'] = alerter.read_status(key='test', type='fatal')

        at_s = dt_isoformat(at)

        assert status == {
            'fatal': {
                '@timestamp': at_s,
                'at': at_s,
                'name': 'test',
                'status': {'current': 'ok', 'previous': 'ok'},
                'alert_trigger': False,
                'key': 'test',
                'type': 'fatal',
                'match': 'y',
                'match_hits_total': 0
            },
            'warning': {
                '@timestamp': at_s,
                'at': at_s,
                'name': 'test',
                'status': {'current': 'alert', 'previous': 'ok'},
                'match_hit': {'foo': 'bar'},
                'alert_trigger': True,
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
    Alerter.reset_last_check()
    Alerter.reset_status()
    es = elasticsearch()

    alerter = None

    try:
        def get_alerter(**kwargs):
            alerter = Alerter(config=Config.object("""
                status_storage: filesystem
                status_storage_path: %s
                alerter:
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
                    rule['alert_trigger'] = True
                    return True
                if rule['match'] == 'y':
                    rule['match_hits_total'] = 0
                    rule['alert_trigger'] = False
                    return False
                return True

            monkeypatch.setattr(alerter, 'do_match', mock_matching_succeeds)
            alerter.config.update(kwargs)
            return alerter

        at = to_dt("2018-05-05 10:02:00")
        alerter = get_alerter(at=at)
        alerter.check_alerts()

        status = {}
        status['warning'] = alerter.read_status(key='test', type='warning')
        status['fatal'] = alerter.read_status(key='test', type='fatal')

        at_s = dt_isoformat(at)

        assert status == {
            'fatal': {
                '@timestamp': at_s,
                'at': at_s,
                'name': 'test',
                'status': {'current': 'ok', 'previous': 'ok'},
                'alert_trigger': False,
                'key': 'test',
                'type': 'fatal',
                'match': 'y',
                'match_hits_total': 0
            },
            'warning': {
                '@timestamp': at_s,
                'at': at_s,
                'name': 'test',
                'status': {'current': 'alert', 'previous': 'ok'},
                'match_hit': {'foo': 'bar'},
                'alert_trigger': True,
                'key': 'test',
                'type': 'warning',
                'match': 'x',
                'match_hits_total': 4
            }
        }
    finally:
        if alerter is not None:
            alerter.wipe_status_storage()

def test_alerter_match():
    Alerter.reset_last_check()
    Alerter.reset_status()
    from elastico.connection import elasticsearch
    from elasticsearch.helpers import bulk

    es = elasticsearch()

    index  = "test-alerter-match"
    values = [ 20, 21, 19, 15, 12, 11, 4, 5, 6, 21, 22]
    #      10: 00  01  02  03  04  05 06 07 08  09  10
    # TEST1  ------------
    # test2           ---------------------

    documents = [
        {
            "_index": index,
            "_type": "doc",
            "_id": i,
            "value": v,
            "@timestamp": dt_isoformat(to_dt("2018-05-05 10:%02d:00" % i)),
        } for i,v in enumerate(values)
    ]

    try:
        success, failed = bulk(es, documents)
        assert len(failed) == 0, "error bulk importing test data"
        es.indices.refresh(index)

        _config = Config.object("""
            alerter:
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
        """)

        alerter = Alerter(config =_config, es_client=es)

        # no matches in timeframe after
        at = to_dt("2018-05-05 10:02:00")
        alerter.process_rules(at=at)

        at_s = dt_isoformat(at)

        def _match_query(q, f, t):
            return {
                        'size': 1,
                        'sort': [{'@timestamp': 'desc'}],
                        'query': {
                            'bool': {
                                'must': [
                                    {'range': {'@timestamp': {
                                        'gte': '2018-05-05T%s:00Z' % f,
                                        'lte': '2018-05-05T%s:00Z' % t,
                                    }}},
                                    {'query_string': {'query': q}},
                                ]
                            }
                        },
                    }

        print("=== check 1 ===")
        pprint(Alerter.STATUS)

        assert Alerter.STATUS == {
            'fatal': {
                'value_check': {
                    'name': 'value-check',
                    '@timestamp': at_s,
                    'at': at_s,
                    'timeframe':{'minutes': 5},
                    'index': 'test-alerter-match',
                    'key': 'value_check',
                    'match': 'value:[0 TO 10]',
                    'match_query': _match_query('value:[0 TO 10]', '09:57', '10:02'),
                    'alert_trigger': False,
                    'match_hits_total': 0,
                    'status': {'current': 'ok', 'previous': 'ok'},
                    'type': 'fatal'
                }
            },
            'rule': {'value_check': {'@timestamp': at_s,
                          'alerts': [],
                          'key': 'value_check',
                          'name': 'value-check',
                          'notify': [],
                          'type': 'rule'}},
            'warning': {
                'value_check': {
                    'name': 'value-check',
                    '@timestamp': at_s,
                    'at': at_s,
                    'timeframe':{'minutes': 5},
                    'index': 'test-alerter-match',
                    'key': 'value_check',
                    'match': 'value:[10 TO 13]',
                    'match_query': _match_query('value:[10 TO 13]', '09:57', '10:02'),
                    'alert_trigger': False,
                    'match_hits_total': 0,
                    'status': {'current': 'ok', 'previous': 'ok'},
                    'type': 'warning'
                }
            }
        }

        alerter = Alerter(config =_config, es_client=es)
        at = to_dt("2018-05-05 10:07:00")
        alerter.process_rules(at=at)
        at_s = dt_isoformat(at)

        start_s = at_s

        print("=== check 2 ===")
        pprint(Alerter.STATUS)

        assert Alerter.STATUS == {
            'fatal': {
                'value_check': {
                    'name': 'value-check',
                    '@timestamp': at_s,
                    'at': at_s,
                    'timeframe':{'minutes': 5},
                    'index': 'test-alerter-match',
                     'key': 'value_check',
                     'match': 'value:[0 TO 10]',
                    'match_query': _match_query('value:[0 TO 10]', '10:02', '10:07'),
                     'match_hit': {
                         '_id': '7',
                         '_index': 'test-alerter-match',
                         '_score': None,
                         '_source': {
                             '@timestamp': '2018-05-05T10:07:00Z',
                             'value': 5
                         },
                         '_type': 'doc',
                         'sort': [1525514820000]
                     },

                     'alert_trigger': True,
                     'match_hits_total': 2,
                     'status': {'current': 'alert', 'previous': 'ok'},
                     'type': 'fatal'
                }
            },
            'rule': {'value_check': {'@timestamp': at_s,
                        'start': start_s,
                          'alerts': [],
                          'key': 'value_check',
                          'name': 'value-check',
                          'notify': [],
                          'type': 'rule'}},
            'warning': {
                'value_check': {
                    'name': 'value-check',
                    '@timestamp': at_s,
                    'at': at_s,
                    'timeframe':{'minutes': 5},
                    'index': 'test-alerter-match',
                    'key': 'value_check',
                    'match': 'value:[10 TO 13]',
                    'match_query': _match_query('value:[10 TO 13]', '10:02', '10:07'),
                    'match_hit': {
                        '_id': '5',
                        '_index': 'test-alerter-match',
                        '_score': None,
                        '_source': {
                            '@timestamp': '2018-05-05T10:05:00Z',
                            'value': 11
                        },
                        '_type': 'doc',
                        'sort': [1525514700000]
                    },
                    'alert_trigger': True,
                    'match_hits_total': 2,
                    'status': {'current': 'alert', 'previous': 'ok'},
                    'type': 'warning'
                }
            }
        }

        alerter = Alerter(config =_config, es_client=es)
        at = to_dt("2018-05-05 10:20:00")
        alerter.process_rules(at=at)
        at_s = dt_isoformat(at)

        print("=== check 3 ===")
        pprint(Alerter.STATUS)

        assert Alerter.STATUS == {
            'fatal': {
                'value_check': {
                    'name': 'value-check',
                    '@timestamp': at_s,
                    'at': at_s,
                    'timeframe':{'minutes': 5},
                    'index': 'test-alerter-match',
                     'key': 'value_check',
                     'match': 'value:[0 TO 10]',
                    'match_query': _match_query('value:[0 TO 10]', '10:15', '10:20'),
                     'alert_trigger': False,
                     'match_hits_total': 0,
                     'status': {'current': 'ok', 'previous': 'alert'},
                     'type': 'fatal'
                }
            },
            'rule': {'value_check': {'@timestamp': at_s,
                        'start': start_s,
                        'end': at_s,
                          'alerts': list(set(['fatal', 'warning'])),
                          'key': 'value_check',
                          'name': 'value-check',
                          'notify': [],
                          'type': 'rule'}},
            'warning': {
                'value_check': {
                    'name': 'value-check',
                    '@timestamp': at_s,
                    'at': at_s,
                    'timeframe':{'minutes': 5},
                    'index': 'test-alerter-match',
                    'key': 'value_check',
                    'match': 'value:[10 TO 13]',
                    'match_query': _match_query('value:[10 TO 13]', '10:15', '10:20'),
                    'alert_trigger': False,
                    'match_hits_total': 0,
                    'status': {'current': 'ok', 'previous': 'alert'},
                    'type': 'warning'
                }
            }
        }


    finally:
        es.indices.delete(index)

def test_alerter_email(monkeypatch):
    Alerter.reset_last_check()
    Alerter.reset_status()
    alerter = Alerter(config=Config.object("""
        alerter:
            alert_defaults:
                hummhomm:
                    notify:
                    - notification: treebeard
                      transport: email
                      email:
                        to: 'treebeard@middle.earth'

            rules:
                - name: test
                  alerts:
                  - type: hummhomm
                    match: x
                    message:
                        text: >
                            humm homm
                  - type: fatal
                    match: y
    """))

    def mock_matching_succeeds(rule):
        if rule['match'] == 'x':
            rule['match_hits_total'] = 4
            rule['match_hit'] = {'foo': 'bar'}
            rule['alert_trigger'] = True
            return True
        if rule['match'] == 'y':
            rule['match_hits_total'] = 0
            rule['alert_trigger'] = False
            return False
        return True

    def mock_matching_fails(*args):
        return False

    monkeypatch.setattr(alerter, 'do_match', mock_matching_succeeds)
    from smtplib import SMTP

    from elastico import util

    mock_args = {}
    def mock_sendmail(**kwargs):
        mock_args['sendmail'] = kwargs

    monkeypatch.setattr(util, 'sendmail', mock_sendmail)

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

            humm homm

            ---------

                alert_trigger: true
                at: 2018-05-05 10:07:00+00:00
                key: test
                match: x
                match_hit:
                  foo: bar
                match_hits_total: 4
                message:
                  text: |
                    humm homm
                name: test
                notify:
                  - email:
                      to: 'treebeard@middle.earth'
                    notification: treebeard
                    transport: email
                status:
                  current: alert
                  previous: ok
                type: hummhomm


            --===============11111==
            Content-Type: text/html; charset="us-ascii"
            MIME-Version: 1.0
            Content-Transfer-Encoding: 7bit

            <p>humm homm</p>
            <hr />
            <pre><code>alert_trigger: true
            at: 2018-05-05 10:07:00+00:00
            key: test
            match: x
            match_hit:
              foo: bar
            match_hits_total: 4
            message:
              text: |
                humm homm
            name: test
            notify:
              - email:
                  to: 'treebeard@middle.earth'
                notification: treebeard
                transport: email
            status:
              current: alert
              previous: ok
            type: hummhomm
            </code></pre>
            --===============11111==--
         """)

# def test_get_rule_value():
#     alerter = Alerter()
#     rule = {'foo': {'bar': 'value'}}
#     assert alerter.get_rule_value(rule, "foo.bar") == 'value'

def test_alerter_command():
    Alerter.reset_status()

    alerter = Alerter(config=Config.object("""
        alerter:
            notifications:
                sound:
                    transport: command
                    command: "echo 'humm'"
                    stdout: true

            alert_defaults:
                hummhomm1:
                    notify:
                      - sound
                hummhomm2:
                    notify:
                      - sound
                hummhomm3:
                    notify:
                      - sound

            rules:
                - name: test
                  alerts:
                    hummhomm1:
                      command_succeeds: >
                        bash -c "exit 0"
                    hummhomm2:
                      command_fails: >
                        bash -c "exit 1"
                    hummhomm3:
                      command_succeeds: >
                        bash -c "exit 1"
    """))

    at = to_dt("2018-05-05 10:07:00")
    alerter.process_rules(at=at)

    pprint(Alerter.STATUS, indent=2)
    assert Alerter.STATUS == {
        'hummhomm1': { 'test': { '@timestamp': '2018-05-05T10:07:00Z',
                           'alert_trigger': False,
                           'at': '2018-05-05T10:07:00Z',
                           'command_succeeds': 'bash -c "exit 0"\n',
                           'key': 'test',
                           'name': 'test',
                           'notify': ['sound'],
                           'result': {'exit_code': 0},
                           'status': {'current': 'ok', 'previous': 'ok'},
                           'type': 'hummhomm1'}},
  'hummhomm2': { 'test': { '@timestamp': '2018-05-05T10:07:00Z',
                           'alert_trigger': False,
                           'at': '2018-05-05T10:07:00Z',
                           'command_fails': 'bash -c "exit 1"\n',
                           'key': 'test',
                           'name': 'test',
                           'notify': ['sound'],
                           'result': {'exit_code': 1},
                           'status': {'current': 'ok', 'previous': 'ok'},
                           'type': 'hummhomm2'}},
  'hummhomm3': { 'test': { '@timestamp': '2018-05-05T10:07:00Z',
                           'alert_trigger': True,
                           'at': '2018-05-05T10:07:00Z',
                           'command_succeeds': 'bash -c "exit 1"\n',
                           'key': 'test',
                           'name': 'test',
                           'notifications': { 'sound': { 'command': 'echo '
                                                                    "'humm'",
                                                         'message': { 'subject': '[elastico] '
                                                                                 'ALERT '
                                                                                 '- '
                                                                                 'hummhomm3 '
                                                                                 'test',
                                                                      'text': ''},
                                                         'notification': 'sound',
                                                         'result': { 'exit_code': 0,
                                                                     'stdout': b'humm'},
                                                         'status': 'ok',
                                                         'stdout': True,
                                                         'transport': 'command'}},
                           'notify': ['sound'],
 'result': {'exit_code': 1},
                           'status': {'current': 'alert', 'previous': 'ok'},
                           'type': 'hummhomm3'}},
  'rule': { 'test': { '@timestamp': '2018-05-05T10:07:00Z',
                      'alerts': [],
                      'key': 'test',
                      'name': 'test',
                      'notify': [],
                      'start': '2018-05-05T10:07:00Z',
                      'type': 'rule'}}}


def test_do_alert(monkeypatch):
    alerter = Alerter(config=Config.object({
        'dry_run': True,
        'alerter':{
            'notifications': {
                'an-email': {
                    'transport': 'email',
                    'email': {
                        'to': 'a@b.c',
                    }
                }
            }
        }
    }))
    alert_data = Config({
        'key': 'the_key',
        'type': 'the_type',
        'name': 'the_name',
        'status': {'current': 'alert'},
        'notify': [
            'an-email'
        ]
    })
    results = []
    class MySMTP:
        def connect(self, *args, **kwargs):
            results.append(('connect', args, kwargs))
        def login(self, *args, **kwargs):
            results.append(('login', args, kwargs))
        def sendmail(self, *args, **kwargs):
            results.append(('sendmail', args, kwargs))
        def quit(self, *args, **kwargs):
            results.append(('quit', args, kwargs))

    mysmtp = MySMTP

    import smtplib
    monkeypatch.setattr("smtplib.SMTP", mysmtp)

    alerter.do_alert(alert_data)
    pprint(alert_data)
    pprint(results)
    assert results[0] == ('connect', tuple(), {'host': 'localhost', 'port': 0})
    assert results[1][0] == 'sendmail'
        # have to check the other items
    assert results[2] == ('quit', tuple(), dict())
    assert alert_data == {
        'key': 'the_key',
        'name': 'the_name',
        'notifications': {
            'an-email': {
                'email': {
                    'from': 'noreply',
                    'subject': '[elastico] ALERT - the_type the_name',
                    'to': 'a@b.c',
                },
                'message': {
                    'subject': '[elastico] ALERT - '
                                'the_type the_name',
                    'text': ''},
                 'notification': 'an-email',
                 'status': 'dry_run',
                 'transport': 'email'}},
 'notify': ['an-email'],
 'status': {'current': 'alert'},
 'type': 'the_type'}

def test_compose_message():
    notifier = Notifier(Config())

    (text, data, plain, html) = notifier.compose_message_text(
        {'text': 'hello {name.firstname}', 'plain': '{message.text}'},
        Config({'name': {'firstname': 'Esmeralda'}}),
    )

    assert text == 'hello Esmeralda'
    assert data == indent(dedent('''\
        name:
          firstname: Esmeralda

        '''), " "*4)
    assert plain == text
    assert html == dedent('''\
        <p>hello Esmeralda</p>''')


