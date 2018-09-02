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

import pyaml, logging, time
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

@alerter_command("run")
def alerter_run(config):
    """run alerter"""
    alerter = Alerter(elasticsearch(config), config)
    alerter.process_rules()

@alerter_command("serve",
    arg('--sleep-seconds', '-s', type=float, default=60, config="serve.sleep_seconds"),
    arg('--count', '-c', type=int, default=0, config="serve.count"),
    )
def alerter_serve(config):
    """run alerter"""

    def _run():
        alerter = Alerter(elasticsearch(config), config)
        alerter.process_rules()

    server = Server(config, run=_run)
    server.run()

@alerter_command("query")
def alerter_run(config):
    """run alerter"""
    pass
