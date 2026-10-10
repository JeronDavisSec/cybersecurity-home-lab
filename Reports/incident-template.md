\# Security Incident Report



\## Incident Details



\- Incident ID: INC-001

\- Date/Time: Simulated lab event

\- Severity: HIGH

\- Status: Open

\- Detection: SSH Brute Force



\## Evidence



\- Source IP: 203.0.113.50

\- Failed Authentication Attempts: 7

\- Targeted Accounts: admin, root

\- Successful Authentication: No



\## MITRE ATT\&CK Mapping



\- Technique: T1110 — Brute Force



\## Analyst Assessment



Repeated SSH authentication failures were detected from a

single source IP. This activity may indicate a brute-force

attempt against one or more accounts.



\## Recommended Response



1\. Review authentication logs and confirm the event.

2\. Investigate the source IP and targeted accounts.

3\. Check for successful authentication after the failed attempts.

4\. Review account and session activity if authentication succeeded.

5\. Apply containment measures according to organizational policy.

6\. Preserve evidence and document investigation findings.



\## Outcome



Pending investigation.



