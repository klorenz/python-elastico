from .cli import command

alert_command = command.add_subcommands('alerter',)

alert_command("expand-rules")
def cmd_alert_expand_rules(config):
    pass

alert_command("run")
def cmd_alert_run(config):
    pass
