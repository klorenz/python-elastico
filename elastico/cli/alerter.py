"""cli.alerter -- control alerter

With ``alerter`` command you can control the :py:mod:`~elastico.alerter`
module.

For more help on a command, run::

   elastico alerter <command> -h

"""
from .cli import command, opt, arg
from ..alerter import Alerter
from ..connection import elasticsearch
from ..util import write_output
from ..server import Server

import pyaml, logging, time, yaml, sys

logger = logging.getLogger('elastico.cli.alerter')

alerter_command = command.add_subcommands('alerter', description=__doc__)


@alerter_command("expand-rules",
    arg("--list", '-l', choices=['names', 'keys', 'types', 'alerts'], default=None),
    arg("--format", '-f', default=None),
    )
def alerter_expand_rules(config):
    """Expand rules, that you can check, if they are correct

    This command expands the rules like in a regular alerter run and prints
    them to stdout in YAML format.  This way you can check, if all variables
    and defaults are expanded as expected.
    """
    expanded_rules = Alerter.expand_rules(config)
    if config['alerter.expand-rules.list']:
        expand = config['alerter.expand-rules.list']

        if expand in ('names', 'keys', 'types'):
            for name in set([ rule[expand[:-1]] for rule in expanded_rules ]):
                print(name)

        if expand == 'alerts':
            for name in set([ "%s-%s" % (rule['type'], rule['key']) for rule in expanded_rules ]):
                print(name)

    elif config['alerter.expand-rules.format']:
        for rule in expanded_rules:
            print(config['alerter.expand-rules.format'].format(**rule))
    else:
        pyaml.p(expanded_rules)


@alerter_command('check',
    arg('--status', "-s", choices=['ok', 'alert', 'error'], default='ok'),
    arg('alert', nargs="*", default=[]),
    )
def alerter_check(config):
    raise NotImplemented("'check' command needs refactoring")

    config['arguments.dry_run'] = True

    result = []
    alerter = Alerter(elasticsearch(config), config)
    check_alerts = config.get('alerter.check.alert')
    status = config['alerter.check.status']

    def check(alert):
        logger.debug("alert: %s", alert)

        alert_id = "%s-%s" % (alert['type'], alert['key'])
        if (check_alerts
            and alert_id not in check_alerts
            and alert['key'] not in check_alerts): return

        result.append(alerter.check_alert(alert, status=status))

    alerter.process_rules(action=check)

    write_output(config, result)

# need a command, where I simulate the data input for the checks, such that
# you can check, if messages are created correctly

# need a command to display dependency tree of alert rules and alerts

@alerter_command('deps')
def alerter_deps(config):
    alerter = Alerter(config=config)
    x = pyaml.PrettyYAMLDumper.ignore_aliases
    try:
        pyaml.PrettyYAMLDumper.ignore_aliases = lambda *a: True
        s = pyaml.dumps(alerter.dependency_tree()).decode('utf-8')
        s = s.replace(": {}", '')
        s = s.replace(":", '')
        sys.stdout.write(s)
    finally:
        pyaml.PrettyYAMLDumper.ignore_aliases = x

@alerter_command('status', opt('--all')) #, arg("rule"))
def alerter_status(config):
    alerter = Alerter(elasticsearch(config), config=config)
    statuses = {}
    for rule in alerter.iterate_rules():
        key = rule.getval('key')
        status = alerter.read_status(key=key)
        if config['alerter.status.all']:
            statuses[key] = status
        else:
            if status['alerts']:
                statuses[key] = status
#    result = alerter.read_status(key='heartbeat_tcp_cal2')
#    from pprint import pprint
#    pprint(result)
    pyaml.p(statuses)


@alerter_command('show',
    arg('item', choices=('rules', 'alerts'), help="choose what to display"),
    opt('--details', '--all', '-a', help="display rule details")
)
def alerter_show(config):
    alerter = Alerter(elasticsearch(config), config)
    if config['alerter.show.item'] == 'rules':
        data = dict((r['name'], r)
            for r in [rule.format() for rule in alerter.iterate_rules(ordered=False)])

        if config['alerter.show.details']:
            pyaml.p(data)
        else:
            pyaml.p(sorted([data[k].get('key') for k in data.keys()]))
            #pyaml.p(sorted([k for k in data.keys()]))
    elif config['alerter.show.item'] == 'alerts':
        data = dict(('{}.{}'.format(*alerter.get_alert_key_type(alert)), alert)
            for rule,alerts in alerter.iterate_alerts()
            for alert in alerts
        )
        if config['alerter.show.details']:
            pyaml.p(data)
        else:
            pyaml.p(sorted([k for k in data.keys()]))


@alerter_command("run")
def alerter_run(config):
    """run alerter"""
    alerter = Alerter(elasticsearch(config), config)
    alerter.check_alerts()

@alerter_command("serve",
    arg('--sleep-seconds', '-s', type=float, default=60, config="serve.sleep_seconds"),
    arg('--count', '-c', type=int, default=0, config="serve.count"),
    )
def alerter_serve(config):
    """run alerter"""

    def _run():
        alerter = Alerter(elasticsearch(config), config)
        alerter.check_alerts()

    server = Server(config, run=_run)
    server.run()

@alerter_command("query")
def alerter_run(config):
    """run alerter"""
    pass
