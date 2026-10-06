# Incident 02 — Brute Force Followed by Successful Authentication

## Summary

A simulated SSH brute-force attack was detected from source IP
203.0.113.50.

The source generated multiple failed authentication attempts
against administrative accounts before successfully authenticating
as the `admin` user.

Because successful authentication followed repeated failures,
the event was escalated from HIGH to CRITICAL severity.

## Detection

- Detection: SSH Brute Force
- Source IP: 203.0.113.50
- Failed Attempts: 7
- Successful Authentication: Yes
- Account: admin
- Severity: CRITICAL
- MITRE ATT&CK: T1110 — Brute Force

## Investigation

The authentication logs were analyzed using the project's
Python-based SSH log analyzer.

The analyzer identified repeated failed authentication attempts
from the same source IP.

A subsequent successful authentication from the same IP triggered
the CRITICAL severity classification.

## Recommended Response

1. Disable or reset the affected account credentials.
2. Investigate the `admin` account for unauthorized activity.
3. Review authentication logs for additional activity from the source IP.
4. Review commands or sessions associated with the successful login.
5. Block the source IP if appropriate.
6. Preserve relevant logs for investigation.
7. Document the incident and recovery actions.

## MITRE ATT&CK Mapping

**T1110 — Brute Force**

The activity is consistent with repeated authentication attempts
designed to obtain access to an account.

## Lessons Learned

This scenario demonstrates why repeated authentication failures
should be correlated with subsequent successful authentication.

A successful login after a brute-force pattern may indicate
potential account compromise and warrants immediate investigation.
