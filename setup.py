#!/usr/bin/env python
from distutils.core import setup

setup(
    name         = 'elastico',
    version      = '0.6.0',
    description  = "Elasticsearch Companion - a commandline tool",
    author       = "Kay-Uwe (Kiwi) Lorenz",
    author_email = "kiwi@franka.dyndns.org",
    url          = 'https://github.com/klorenz/python-elastico',
    license      = "MIT",

    install_requires=[
        'elasticsearch',
        'PyYAML',
        'pyaml',
        'requests',
        'argdeco',
        'markdown',
        'pytz',
        'python-dateutil',
    ],
    packages=[
        'elastico', 'elastico.cli'
    ],

    # package_data = {
    #    elastico: ['subfolder/*.x', ...]
    # }
    # include_package_data = True

    entry_points={
        'console_scripts': [
            'elastico = elastico.cli:main',
        ]
    }
)
