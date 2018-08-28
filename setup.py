import os
from setuptools import setup

setup(
    name = "hello-janoskk",
    version = "1.0",
    author = "Janos Kasza",
    author_email = "janos.kasza@logmein.com",
    description = ("Hello, janoskk"),
    license='License :: OSI Approved :: MIT License',
    keywords = "",
    url = "http://logmein.com",
    packages=['logmein_host', 'pytty'],
    package_data={'pytty': ['templates/*', 'static/*']},
    include_package_data=True,
    long_description=("Hello, janoskk"),
    entry_points={
        'console_scripts': [
            'pytty = pytty.pytty:main_func',
            'logmein_host = logmein_host.snap_runner:main'
        ]
    }
) 
