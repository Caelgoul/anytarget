#!/usr/bin/env python3

import io
import sys
from setuptools import find_packages, setup
from anytarget.anytarget import __author__, __version__


if sys.version_info[0] < 3:
    raise ValueError("This script requires Python 3 or later")


setup(
    name="anytarget",
    version=__version__,
    description="The script is created to seamlessly interact with (https://anytarget.io) API",
    long_description_content_type="text/markdown",
    author=__author__,
    author_email="pyplus@protonmail.com",
    license="MIT",
    install_requires=["tabulate", "requests", "tqdm", "click"],
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'anytarget = anytarget.anytarget:cli',
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "Topic :: Internet",
        "Topic :: Security",
        "Topic :: System :: Networking",
    ],
    keywords="anytarget",
    python_requires=">=3.8",
)
