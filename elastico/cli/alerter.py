"""cli.alerter -- control alerter

With ``alerter`` command you can control the :py:mod:`~elastico.alerter`
module.

For more help on a command, run::

   elastico alerter <command> -h

"""
from .cli import command

alerter_command = command.add_subcommands('alerter', description=__doc__)

@alerter_command("expand-rules")
def alerter_expand_rules(config):
    """Expand rules, that you can check, if they are correct

    This command expands the rules like in a regular alerter run and prints
    them to stdout in YAML format.  This way you can check, if all variables
    and defaults are expanded as expected.
    """
    pass

@alerter_command("run")
def alerter_run(config):
    """run alerter"""
    pass
