Cybersecurity Home Lab

A hands-on cybersecurity lab focused on SSH authentication log analysis, brute-force detection, suspicious IP identification, and security incident reporting.

Project Overview

This project demonstrates practical cybersecurity and IT skills through a Python-based SSH log analyzer and an interactive Streamlit dashboard. The lab uses sample authentication logs to identify suspicious login activity and highlight potential security incidents.

Key Features

SSH Log Analysis: Parses authentication logs to identify failed and successful login attempts.

Brute-Force Detection: Flags IP addresses that meet a configurable failed-login threshold.

Critical Alert Identification: Highlights suspicious IP addresses associated with both failed and successful logins.

Interactive Dashboard: Displays failed login attempts, suspicious IP addresses, critical alerts, and successful logins.

Incident Reporting: Documents detected activity and simulated security incidents.

Testing and Validation: Includes automated tests for the log analyzer.

Technologies Used

Python

Streamlit

Pandas

PowerShell

Git and GitHub

Regular expressions

Pytest / Python unittest (depending on the test framework used)

Dashboard

The Cybersecurity Operations Dashboard provides a visual overview of authentication activity and allows users to adjust the failed-login alert threshold.

Dashboard metrics include:

Total failed login attempts

Number of suspicious IP addresses

Number of critical alerts

Total successful logins

Detection Example

The sample authentication log includes repeated failed SSH login attempts from a single IP address, followed by a successful login from that same address.

The dashboard identifies this activity as a critical alert when the IP meets the configured failure threshold and has at least one successful login.

This is a controlled lab demonstration using sample log data. A successful login after repeated failures is suspicious and warrants investigation, but does not by itself prove an account compromise.

Project Structure

Cybersecurity-home-lab/

├── dashboard.py

├── logs/

│   └── Sample-auth.log

├── Scripts/

│   ├── log-analyzer.py

│   ├── run-simulation.ps1

│   ├── suspicious-ip.py

│   └── system-audit.py

├── Reports/

│   └── incident-02.md

├── tests/

│   └── test\_log\_analyzer.py

└── README.md

Note: The project structure above describes the intended layout. File names and locations may vary as the lab evolves.

Getting Started

Requirements

Python 3

pip

Git

A Windows environment with PowerShell is recommended for the supplied PowerShell scripts.

Installation

Clone the repository:

git clone https://github.com/JeronDavisSec/Cybersecurity-home-lab.git

cd Cybersecurity-home-lab

Install the dashboard dependencies:

python -m pip install streamlit pandas

Run the Dashboard

From the project root, run:

python -m streamlit run .\\dashboard.py

The dashboard will open in your browser. Use the sidebar to adjust the failed-login alert threshold or upload a supported .log or .txt authentication log.

Run the Log Analyzer

The analyzer supports command-line arguments. Check the available options in your local version with:

python .\\Scripts\\log-analyzer.py --help

Use the help output to select the appropriate log file and threshold arguments.

Security and Responsible Use

This project is intended for educational and defensive security purposes. It uses sample authentication logs to demonstrate detection and reporting. Only analyze systems and logs you are authorized to access.

Future Improvements

Expand IP parsing and authentication-log format coverage.

Add richer incident summaries and downloadable reports.

Improve automated testing for edge cases.

Add dashboard filtering and event timelines.

Document detection logic and investigation steps.

Author

Jeron Davis

&#x20;IT Support Specialist | Veteran

&#x20;Cybersecurity and IT home-lab portfolio

This project is part of my ongoing development in security monitoring, log analysis, troubleshooting, and defensive cybersecurity.



