#!/usr/bin/env python3

from setuptools import setup, find_packages
import os

# Read the contents of README file
this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

# Read requirements
with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
    name='discoursemap',
    version='1.1.0',
    description='Discourse forum security scanner. Written for security professionals and forum administrators.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='ibrahimsql',
    author_email='ibrahimsql@proton.me',
    url='https://github.com/ibrahmsql/discoursemap',
    packages=find_packages(),
    include_package_data=True,
    install_requires=requirements,
    entry_points={
        'console_scripts': [
            'discoursemap=discoursemap.main:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Information Technology',
        'Topic :: Security',
        'Topic :: Internet :: WWW/HTTP :: Site Management',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Operating System :: OS Independent',
        'Environment :: Console',
    ],
    keywords='discourse security scanner penetration-testing vulnerability-scanner cybersecurity',
    python_requires='>=3.8',
    project_urls={
        'Bug Reports': 'https://github.com/ibrahmsql/discoursemap/issues',
        'Source': 'https://github.com/ibrahmsql/discoursemap',
        'Documentation': 'https://github.com/ibrahmsql/discoursemap#readme',
    },
    package_data={
        'discoursemap': [
            'data/*.yaml',
            'discourse_exploits/**/*',
            'ruby_exploits/*.rb',
        ],
    },
)