import os
from setuptools import setup

setup(
    name = "logmein-host",
    version = "1.0",
    author = "LogMeIn, Inc.",
    author_email = "logmein-linux@logmein.com",
    description = ("The LogMeIn Host Software (Beta) for Linux"),
    license='License :: OSI Approved :: MIT License',
    keywords = "",
    url = "http://repository.services.logmein.com/linux/",
    packages=['logmein_host', 'pytty'],
    package_data={'pytty': ['templates/*', 'static/*']},
    include_package_data=True,
    long_description=(""),
    entry_points={
        'console_scripts': [
            'pytty = pytty.pytty:main_func',
            'logmein_host = logmein_host.snap_runner:main'
        ]
    }
)
