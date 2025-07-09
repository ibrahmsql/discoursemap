DiscourseMap Documentation
==========================

.. image:: https://img.shields.io/badge/DiscourseMap-Security%20Scanner-red?style=for-the-badge&logo=discourse
   :alt: DiscourseMap

.. image:: https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python
   :alt: Python

.. image:: https://img.shields.io/badge/Ruby-2.7+-red?style=for-the-badge&logo=ruby
   :alt: Ruby

.. image:: https://img.shields.io/badge/License-MIT-green?style=for-the-badge
   :alt: License

Welcome to DiscourseMap's documentation!
========================================

**DiscourseMap** is a comprehensive, modular security testing framework specifically designed for Discourse forum platforms. It combines Python-based scanning modules with Ruby exploit integration to provide thorough security assessments.

🎯 Key Features
===============

* **25+ Security Modules** covering all aspects of Discourse security
* **Ruby Exploit Integration** with 25+ CVE-specific exploits
* **Modular Architecture** for easy extension and customization
* **Comprehensive Coverage** from reconnaissance to exploitation
* **Professional Reporting** with detailed findings and recommendations
* **Active Development** with regular updates and new features

📚 Table of Contents
===================

.. toctree::
   :maxdepth: 2
   :caption: Getting Started:

   installation
   quickstart
   configuration

.. toctree::
   :maxdepth: 2
   :caption: User Guide:

   usage
   modules
   examples
   reporting

.. toctree::
   :maxdepth: 2
   :caption: Advanced:

   ruby_exploits
   docker
   ci_cd
   customization

.. toctree::
   :maxdepth: 2
   :caption: API Reference:

   api/modules
   api/core
   api/utils

.. toctree::
   :maxdepth: 2
   :caption: Development:

   contributing
   changelog
   roadmap

🚀 Quick Start
==============

Install DiscourseMap:

.. code-block:: bash

   pip install discoursemap

Run a basic scan:

.. code-block:: bash

   discoursemap -u https://forum.example.com

⚠️ Legal Notice
===============

This tool is intended for **authorized security testing only**. Use only on systems you own or have explicit permission to test. Unauthorized use is prohibited and may be illegal.

📞 Support
==========

* **GitHub Issues**: https://github.com/ibrahimsql/discoursemap/issues
* **Documentation**: https://discoursemap.readthedocs.io/
* **PyPI Package**: https://pypi.org/project/discoursemap/

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`