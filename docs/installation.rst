Installation
============

DiscourseMap can be installed in several ways depending on your needs and environment.

📦 Quick Install (Recommended)
==============================

The easiest way to install DiscourseMap is via PyPI:

.. code-block:: bash

   pip install discoursemap

Verify the installation:

.. code-block:: bash

   discoursemap --help

🐳 Docker Installation
======================

For containerized environments:

.. code-block:: bash

   # Pull the image
   docker pull ghcr.io/ibrahimsql/discoursemap

   # Run a scan
   docker run --rm ghcr.io/ibrahimsql/discoursemap -u https://forum.example.com

🔧 Development Installation
===========================

For development or contributing:

.. code-block:: bash

   # Clone the repository
   git clone https://github.com/ibrahimsql/discoursemap.git
   cd discoursemap

   # Install in development mode
   pip install -e .

   # Install development dependencies
   pip install -r requirements-dev.txt

📋 Prerequisites
================

System Requirements
-------------------

* Python 3.8 or higher
* Ruby 2.7 or higher (for exploit modules)
* Git
* Internet connection

Python Dependencies
-------------------

The following Python packages are automatically installed:

* requests
* beautifulsoup4
* colorama
* pyyaml
* click
* rich

Ruby Dependencies
-----------------

For Ruby exploit modules:

.. code-block:: bash

   # Install bundler
   gem install bundler

   # Install Ruby dependencies
   bundle install

🔍 Verification
===============

To verify your installation is working correctly:

.. code-block:: bash

   # Check version
   discoursemap --version

   # Run help
   discoursemap --help

   # Test with a simple scan
   discoursemap -u https://meta.discourse.org --modules info

🚨 Troubleshooting
==================

Common Issues
-------------

**Permission Denied**

If you encounter permission issues:

.. code-block:: bash

   pip install --user discoursemap

**Ruby Not Found**

If Ruby exploits don't work:

.. code-block:: bash

   # Check Ruby installation
   ruby --version

   # Install Ruby (Ubuntu/Debian)
   sudo apt-get install ruby-full

   # Install Ruby (macOS)
   brew install ruby

**SSL Certificate Issues**

For SSL-related problems:

.. code-block:: bash

   pip install --trusted-host pypi.org --trusted-host pypi.python.org discoursemap

🔄 Updating
===========

To update to the latest version:

.. code-block:: bash

   pip install --upgrade discoursemap

🗑️ Uninstallation
=================

To remove DiscourseMap:

.. code-block:: bash

   pip uninstall discoursemap