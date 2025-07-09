Modules
=======

DiscourseMap uses a modular architecture that allows you to run specific security tests based on your needs. Each module focuses on a particular aspect of Discourse security.

🎯 Available Modules
===================

Information Gathering
--------------------

**info**
  Basic information gathering about the target Discourse forum.
  
  * Discourse version detection
  * Server information
  * Basic configuration details
  * Public statistics

**users**
  User enumeration and analysis.
  
  * Public user discovery
  * User profile analysis
  * Admin/moderator identification
  * User activity patterns

**plugins**
  Plugin detection and analysis.
  
  * Installed plugin enumeration
  * Plugin version detection
  * Known plugin vulnerabilities
  * Custom plugin identification

Vulnerability Assessment
-----------------------

**vulnerability**
  General vulnerability scanning.
  
  * Common web vulnerabilities
  * Discourse-specific issues
  * Configuration weaknesses
  * Security misconfigurations

**cve**
  CVE-based exploit testing.
  
  * Known CVE exploitation
  * Version-specific vulnerabilities
  * Proof-of-concept exploits
  * Impact assessment

**auth**
  Authentication and authorization testing.
  
  * Login mechanism analysis
  * Session management testing
  * Password policy evaluation
  * Two-factor authentication bypass

API Testing
----------

**api**
  Discourse API security testing.
  
  * API endpoint discovery
  * Authentication bypass
  * Rate limiting analysis
  * Data exposure testing

**endpoints**
  Hidden endpoint discovery.
  
  * Admin panel discovery
  * Debug endpoints
  * Development interfaces
  * Backup file detection

Advanced Modules
---------------

**exploit**
  Advanced exploitation techniques.
  
  * Ruby-based exploits
  * Custom payload delivery
  * Post-exploitation modules
  * Privilege escalation

**compliance**
  Security compliance checking.
  
  * OWASP Top 10 assessment
  * Security headers analysis
  * SSL/TLS configuration
  * Privacy compliance

📋 Module Usage
===============

Running Single Modules
---------------------

.. code-block:: bash

   # Run information gathering only
   discoursemap -u https://forum.example.com --modules info

   # Run vulnerability assessment
   discoursemap -u https://forum.example.com --modules vulnerability

   # Run CVE testing
   discoursemap -u https://forum.example.com --modules cve

Running Multiple Modules
------------------------

.. code-block:: bash

   # Combine multiple modules
   discoursemap -u https://forum.example.com --modules info,users,plugins

   # Security-focused scan
   discoursemap -u https://forum.example.com --modules vulnerability,cve,auth

   # Comprehensive assessment
   discoursemap -u https://forum.example.com --modules all

Module Categories
----------------

.. code-block:: bash

   # Information gathering modules
   discoursemap -u https://forum.example.com --modules info,users,plugins

   # Vulnerability modules
   discoursemap -u https://forum.example.com --modules vulnerability,cve,auth

   # API testing modules
   discoursemap -u https://forum.example.com --modules api,endpoints

🔧 Module Configuration
=======================

Module-Specific Options
----------------------

Some modules accept additional configuration:

.. code-block:: bash

   # User enumeration with custom wordlist
   discoursemap -u https://forum.example.com \
     --modules users \
     --wordlist custom-users.txt

   # CVE testing with specific CVE
   discoursemap -u https://forum.example.com \
     --modules cve \
     --cve-filter CVE-2023-XXXX

   # API testing with authentication
   discoursemap -u https://forum.example.com \
     --modules api \
     --username admin \
     --password secretpass

Timing and Performance
---------------------

.. code-block:: bash

   # Add delays between requests
   discoursemap -u https://forum.example.com \
     --modules all \
     --delay 2

   # Limit concurrent requests
   discoursemap -u https://forum.example.com \
     --modules vulnerability \
     --threads 5

   # Set timeout for requests
   discoursemap -u https://forum.example.com \
     --modules api \
     --timeout 30

📊 Module Output
================

Each module provides structured output with:

* **Findings**: Security issues discovered
* **Information**: Gathered intelligence
* **Recommendations**: Suggested remediation
* **Evidence**: Proof of findings

Example Output
-------------

.. code-block:: text

   [INFO] Module: info
   [+] Discourse version: 3.1.0
   [+] Server: nginx/1.18.0
   [+] Users: 1,234 registered
   
   [INFO] Module: vulnerability
   [!] Potential XSS in search function
   [!] Weak password policy detected
   [+] HTTPS properly configured
   
   [INFO] Module: cve
   [CRITICAL] CVE-2023-XXXX: Remote code execution
   [HIGH] CVE-2023-YYYY: Information disclosure

🛡️ Ruby Exploit Modules
========================

Advanced exploitation using Ruby:

.. code-block:: bash

   # Run Ruby-based exploits
   discoursemap -u https://forum.example.com \
     --modules exploit \
     --ruby-exploits

   # Specific Ruby exploit
   discoursemap -u https://forum.example.com \
     --ruby-exploit discourse_rce.rb

Ruby Exploit Features:

* **Custom Payloads**: Tailored exploit code
* **Post-Exploitation**: Advanced techniques
* **Stealth Mode**: Evasion capabilities
* **Payload Generation**: Dynamic exploit creation

⚠️ Module Safety
=================

Safety Levels
------------

**Safe Modules** (Read-only):
  * info
  * users
  * plugins
  * api (GET requests only)

**Moderate Risk** (Limited testing):
  * vulnerability
  * auth
  * endpoints

**High Risk** (Active exploitation):
  * cve
  * exploit

Safe Mode
--------

.. code-block:: bash

   # Run only safe modules
   discoursemap -u https://forum.example.com --safe-mode

   # Exclude dangerous modules
   discoursemap -u https://forum.example.com \
     --modules all \
     --exclude cve,exploit

📚 Custom Modules
=================

Developing Custom Modules
------------------------

Create your own modules by extending the base module class:

.. code-block:: python

   from discoursemap.core.module import BaseModule
   
   class CustomModule(BaseModule):
       name = "custom"
       description = "Custom security test"
       
       def run(self):
           # Your custom logic here
           pass

Module Development Guidelines:

* Follow the established API
* Include proper error handling
* Provide clear output messages
* Document module functionality
* Test thoroughly before deployment

🔍 Module Troubleshooting
=========================

Common Issues
------------

**Module Not Found**

.. code-block:: bash

   # List available modules
   discoursemap --list-modules

**Permission Denied**

.. code-block:: bash

   # Some modules require authentication
   discoursemap -u https://forum.example.com \
     --modules admin \
     --username admin --password pass

**Timeout Issues**

.. code-block:: bash

   # Increase timeout for slow modules
   discoursemap -u https://forum.example.com \
     --modules cve \
     --timeout 60

Debugging
--------

.. code-block:: bash

   # Enable debug output
   discoursemap -u https://forum.example.com \
     --modules vulnerability \
     --debug

   # Verbose module output
   discoursemap -u https://forum.example.com \
     --modules all \
     --verbose