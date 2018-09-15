Configuration
=============

.. highlight:: yaml

You configure ElastiCo with a YAML configuration file.

You can do it in a single file, but it is recommended to use multiple
files to keep the overview, especially if you create more complex
rules.


Basic Configuration
-------------------

Usage of format strings
"""""""""""""""""""""""

Almost everywhere you can make use of format strings, which are evaluated in
the context as specified in the configuration's documentation.

You can set up configurations like this:

.. code-block:: yaml

    alerter:
       rules:
         - name: {host_name} down
           host_name: foo

The ``host_name`` will be expanded, when using the ``name``.  For these
patterns typical :py:class:`string.Formatter` is used with some extensions:

====================  ===============  =========================================
format_spec type      example          description
====================  ===============  =========================================
gb                    ``{num:.2gb}``   format a number like 5000000000 to 5.00
mb                    ``{num:.2mb}``   format a number like 5000000 to 5.00
json                  ``{val:json}``   format whatever value is in num to json
====================  ===============  =========================================

The formatter is very useful for composing notification messages.

Please note, that although you usually format dictionaries, you can use also
the attribute way of accessing the data, so following lines are equivalent::

    {message[text]}
    {message.text}

Elasticsearch
"""""""""""""

If you want to access your local elasticsearch server (*http://localhost:9200*),
you do not need a configuration at all.  If you want to access a different
server, you can configure it with a dictionary, which is used to create an
`elasticsearch client in python`_:

.. code-block:: yaml

    elasticsearch:
      hosts:
        - https://first.host:1234
        - http://second.host:5996
      http_auth:
        - USERNAME
        - PASSWORD

If you have only a single host, you do not need a list:

.. code-block:: yaml

    elasticsearch:
      hosts: https://my.host

For a complete list of possible settings, please check out
`elasticsearch client in python`_ documentation.

If you do not want to store the password in this file (e.g. if you store the
configuration in a repository), you can use `.netrc`_ mechanism with a special
key in the dictionary:

.. code-block:: yaml

    elasticsearch:
      hosts: https://my.host
      netrc: machine_name

Which would look into :file:`~/.netrc` and look for an entry like::

    machine machine_name login USERNAME password PASSWORD

If you want to use a custom `.netrc`_ file, you can specify it in a dictionary
like this:

.. code-block:: yaml

    elasticsearch:
      hosts: https://my.host
      netrc:
        file: /path/to/file    # must be absolute or relative to
                               # current working directory
        machine: machine_name  # machine name to lookup


.. _elasticsearch client in python:
    https://elasticsearch-py.readthedocs.io/en/master/api.html#elasticsearch.Elasticsearch:

.. _.netrc: https://docs.oracle.com/cd/E36784_01/html/E36882/netrc-4.html


Logging
"""""""

You can define log levels of loggers in config file's ``logging`` section:

.. code-block:: yaml

    logging:
        ROOT: WARNING
        elastico.cli: DEBUG
        elastico.alerter: INFO

Log levels correspond to `logging log levels`_

.. _logging log levels:
   https://docs.python.org/3/library/logging.html#logging-levels

Notifications
"""""""""""""

You can predefine notifications on top level of configuration file and use them
in different contexts.  You configure notifications with dictionaries keyed
by the name:

.. code-block:: yaml

    notifications:
      mail-team:
        transport: email
        email:
          to: some@host.com
          from: elastico@my-domain.com

      send-sms:
        transport: command
        command:
          - "/path/to/send_sms"
          - "{message.subject}"
          - "+4912345678"

Message
~~~~~~~

The message is the data, which will be transported by the notifiers.  It
composed from a message record, which is usually configured in a different
context like:

.. code-block:: yaml

    message:
      text: |
        This is *Markdown* text, which is rendered to HTML.

Here a table of the possible message fields:

:``message.text``:
   This should be configured in config file.  In the email it is interpreted
   as Markdown and rendered to HTML.

   In message text you can make use of format_specs.  For convenience, if there
   is a ``match_hit`` defined in your context, following lines are equivalent::

       {match_hit._source.monitor.host}
       {_.monitor.host}

:``message.data``:
   If not specified, it is the (4 space indented) YAML representation of
   the notification's context data.

:``message.plain``:
   This is the ``text/plain`` part of the email.  Default is::

      {message.text}\n--------------\n\n{message.data}

   Which is rendered also to HTML.  Usually you will not change this.  If you
   do not want to have the data appended to the mail, you can change this to::

      {message.text}

:``message.html``:
   Usually ``message.plain`` is rendered to HTML.

:``message.subject``:
   Custom subject.


You can access the data in notification configuration as illustrated in command
above.


Email
~~~~~

For configuring email transport, you can use following fields:

==================  ===============  =========================================
  Key                 Default          Description
==================  ===============  =========================================
``smtp.host``       localhost        The SMTP Server
``smtp.ssl``        False            Use SSL
``smtp.port``       0                Port
``smtp.username``   None             username for login
``smtp.password``   None             password for login
``smtp.netrc``      {}               ``.netrc`` configuration as explained in
                                     :doc:`configuration` as alternative to
                                     specifying username and password here.
``email.from``      noreply          The sender address
``email.to``        []               Recipients
``email.cc``        []               Carbon copy recipients
``email.bcc``       []               Blind Carbon copy recipients
==================  ===============  =========================================


Command
~~~~~~~

A command can be configured in various ways:

.. code-block:: yaml

    shell-command:
      transport: command
      command: >
        echo "select * from foo" | mysql | mail -s "hello" some@recipient

This is equivalent to (``shell: True`` is implied, because command is a string):

.. code-block:: yaml

    shell-command:
      transport: command
      command:
        args: >
          echo "select * from foo" | mysql | mail -s "hello" some@recipient
        shell: True

This is equivalent to:

.. code-block:: yaml

    shell-command:
      transport: command
      command:
        args: >
          mysql | mail -s "hello" some@recipient
        input: >
          select * from foo
        shell: True

Apart from the ``input`` parameter, you can pass all arguments, which can be passed
passed to :py:class:`subprocess.Popen`.  ``input`` specifies the code to be
passed as stdin.  A common pattern is to pass the message text:

.. code-block:: yaml

    shell-command:
      transport: command
      command:
        args: mail -s "hello" some@recipient
        input: {message.text}

Which is equivalent to:

.. code-block:: yaml

    shell-command:
      transport: command
      command:
        args:
          - "mail"
          - "-s"
          - "hello"
          - "some@recipient"
        input: {message.text}

If you want to store stdout, or stderr in a resulting record (which might be
passed as status to elasticsearch), you can specify:

.. code-block:: yaml

    shell-command:
      transport: command
      command:
        args: mail -s "hello" some@recipient
        input: "{message.text}"
        stdout: true
        stderr: true

So ``input``, ``stdout`` and ``stderr`` are managed arguments and are not
directly passed to :py:class:`subprocess.Popen`.

Trigger Alerts
""""""""""""""

Alerts are triggered if some condition is met.

Trigger Type: match
~~~~~~~~~~~~~~~~~~~

An elasticsearch match.

A trigger can have:



.. code-block:: yaml

    require: all



Serve
"""""
