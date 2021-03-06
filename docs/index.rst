.. ElastiCo -- Elastic companion documentation master file, created by
   sphinx-quickstart on Mon Aug 13 23:43:14 2018.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to ElastiCo -- Elastic companion's documentation!
=========================================================

Contents:

.. toctree::
   :maxdepth: 2

   configuration
   alerter/index

.. todo::

    - document usage of index
    - document usage of alerter

    - document status records for elastico-alerter-*
    - document index creation of elastico-alerter-*

    - how does the matching work (every, timeframe)
    - how does the re-alertion work

    - document how rules are composed
    - document how alerts are composed
    - document how all_clear is composed
    - document how notifications are composed

    - how to compose messages

    - add mermaid diagrams to documentation, use tox env to generate doc + dep sphinxcontrib-mermaid

.. todo:: features

    - make a rule composer, and a alert composer, to generate  a list of all
      alert, which is sortable
    - match:
        if: key_of_rule.fatal
        if-not: key_of_rule.warning
        match: ...
    - query the alert status before notification and make it usable in notification
      "first occurance: {status.start}"


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

