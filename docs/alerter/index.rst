ElastiCo Alerter
================

Elastico Alerter is a simple system for raising alerts.  If some condition is
met, there is raised an alarm and reraised until the problem is resolved.  Then
a final all-clear notification is sent.

For configuring alerts you define rules, alerts and notifications.

A rule consists of multiple alerts (typically different severities of the
monitored aspect) and an if an alert is triggered it can do actions for
notification.

.. highlight:: yaml

Rule
----



