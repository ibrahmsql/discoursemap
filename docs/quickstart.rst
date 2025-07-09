Quick Start
===========

Get started with DiscourseMap in minutes! This guide will walk you through your first security scan.

🚀 Your First Scan
==================

After installation, you can immediately start scanning:

.. code-block:: bash

   discoursemap -u https://forum.example.com

This will run a basic security assessment with default modules.

🎯 Basic Usage
==============

Command Structure
----------------

.. code-block:: bash

   discoursemap [OPTIONS] -u TARGET_URL

Essential Options
----------------

.. code-block:: bash

   # Specify target URL (required)
   -u, --url URL

   # Select specific modules
   -m, --modules MODULE1,MODULE2

   # Output format
   -o, --output FILE

   # Quiet mode
   -q, --quiet

   # Verbose output
   -v, --verbose

📊 Example Scans
================

Basic Information Gathering
--------------------------

.. code-block:: bash

   discoursemap -u https://forum.example.com --modules info

This will gather basic information about the target forum:

* Discourse version
* Server information
* Installed plugins
* User statistics

Vulnerability Assessment
-----------------------

.. code-block:: bash

   discoursemap -u https://forum.example.com --modules vulnerability,cve

This performs security testing:

* Known vulnerability checks
* CVE exploit attempts
* Security misconfigurations

Comprehensive Scan
-----------------

.. code-block:: bash

   discoursemap -u https://forum.example.com --modules all

Runs all available modules:

* Information gathering
* Vulnerability assessment
* Authentication testing
* Plugin analysis
* Configuration review

🔧 Common Scenarios
===================

Penetration Testing
------------------

.. code-block:: bash

   # Full security assessment
   discoursemap -u https://target-forum.com \
     --modules all \
     --output pentest-results.json \
     --verbose

Security Audit
-------------

.. code-block:: bash

   # Focus on configuration and compliance
   discoursemap -u https://your-forum.com \
     --modules info,config,compliance \
     --output audit-report.html

Quick Health Check
-----------------

.. code-block:: bash

   # Fast security overview
   discoursemap -u https://forum.example.com \
     --modules info,vulnerability \
     --quiet

📋 Understanding Output
=======================

Terminal Output
--------------

DiscourseMap provides real-time feedback:

.. code-block:: text

   [INFO] Starting DiscourseMap v1.0.2
   [INFO] Target: https://forum.example.com
   [INFO] Modules: info, vulnerability
   
   [+] Information Gathering
   [+] Discourse version: 3.1.0
   [+] Server: nginx/1.18.0
   [!] Potential vulnerability found: CVE-2023-XXXX
   
   [INFO] Scan completed in 45.2 seconds

Report Files
-----------

Generate detailed reports:

.. code-block:: bash

   # JSON format (machine-readable)
   discoursemap -u https://forum.example.com -o results.json

   # HTML format (human-readable)
   discoursemap -u https://forum.example.com -o report.html

   # Text format (simple)
   discoursemap -u https://forum.example.com -o findings.txt

⚙️ Configuration
================

Authentication
-------------

For authenticated scans:

.. code-block:: bash

   discoursemap -u https://forum.example.com \
     --username admin \
     --password secretpass

Proxy Support
------------

Route traffic through a proxy:

.. code-block:: bash

   discoursemap -u https://forum.example.com \
     --proxy http://127.0.0.1:8080

Custom Headers
-------------

Add custom HTTP headers:

.. code-block:: bash

   discoursemap -u https://forum.example.com \
     --headers "X-Forwarded-For: 127.0.0.1" "User-Agent: CustomBot/1.0"

🔍 Next Steps
=============

Now that you've run your first scan:

1. **Explore Modules**: Learn about specific security modules
2. **Review Reports**: Understand the findings and recommendations
3. **Advanced Usage**: Discover advanced features and customization
4. **Ruby Exploits**: Explore the integrated exploit framework

⚠️ Important Notes
==================

* **Authorization Required**: Only scan systems you own or have permission to test
* **Rate Limiting**: Use delays (``--delay``) for production systems
* **Legal Compliance**: Ensure your testing complies with local laws
* **Responsible Disclosure**: Report findings responsibly

📚 Further Reading
==================

* :doc:`modules` - Detailed module documentation
* :doc:`examples` - More usage examples
* :doc:`reporting` - Understanding reports
* :doc:`ruby_exploits` - Ruby exploit integration