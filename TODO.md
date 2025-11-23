# Project Roadmap & Todo List

## 🚀 Upcoming Features

- [ ] **Web Interface and Dashboard (Web UI)** 📊
  - Implementation of a modern web interface using `FastAPI` or `Flask`.
  - Features:
    - Start scans via web UI.
    - Dashboard for visualizing past scans with charts.
    - Live progress tracking of ongoing scans.

- [ ] **Auto-Remediation Module** 🛠️
  - Development of a "Fixer" module.
  - Capability to automatically fix misconfigurations using the Discourse API.
  - Examples:
    - Correcting insecure Trust Level settings.
    - Closing exposed API endpoints.
  - Option to generate remediation scripts instead of auto-applying fixes.

- [ ] **Scan Comparison (Diffing)** 📈
  - Module to compare results between different scans (e.g., "Last Week" vs "Today").
  - clear visualization of:
    - Newly introduced vulnerabilities.
    - Remediated/Closed vulnerabilities.
