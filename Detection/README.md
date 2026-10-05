# Detection Engineering

This directory contains detection logic and documentation for identifying suspicious authentication activity.

## Detection 001 — Repeated SSH Authentication Failures

### Objective

Identify potential brute-force authentication activity by detecting repeated failed SSH login attempts from the same source IP address.

### Detection Logic

The detection looks for multiple failed authentication attempts originating from the same IP address.

A source IP generating **5 or more failed authentication attempts** within the analyzed log set is flagged for investigation.

### Example Alert

```text
[ALERT] Possible brute-force activity detected
Source IP: 203.0.113.50
Failed attempts: 7
Target accounts: admin, root
Severity: HIGH
