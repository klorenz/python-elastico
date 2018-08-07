import yaml, io, pyaml, re
from textwrap import dedent
from elastico.util import PY3
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

    assert msg == dedent("""\
            Content-Type: multipart/alternative; boundary="===============11111=="
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


# def test_alert_email():
#     alerter = Alerter(config=make_config("""
#         rules:
#             - name: test
#               alerts:
#               - type: warning
#                 match: x
#               - type: fatal
#                 match: y
#     """))
#
#     #monkeypatch.setattr(smtplib, 'sendmail',
#
# #def test_alerter_status_memory():
#
