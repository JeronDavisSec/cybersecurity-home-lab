# Incident 01 — Repeated SSH Authentication Failures

**Status:** Closed — simulated training incident  
**Severity:** Medium  
**Environment:** Synthetic Linux lab

## Detection

The authentication-log analyzer identified repeated failed SSH authentication attempts from `203.0.113.50`.

## Initial Findings

- Source: `203.0.113.50` (documentation/test IP range)
- Observed attempts: 7
- Targeted accounts: `admin`, `root`
- Pattern: repeated password failures over a short interval

## Triage

The behavior is consistent with automated password-guessing activity. Because the address is from a documentation range and the data is synthetic, no real-world attribution is made.

## Containment — Simulated

- Temporarily block the source at the lab firewall.
- Preserve the authentication log.
- Confirm that no unauthorized account was successfully authenticated.

## Eradication — Simulated

- Review SSH configuration.
- Disable unnecessary accounts.
- Enforce strong authentication and MFA where available.

## Recovery — Simulated

- Restore normal access after validation.
- Continue monitoring for repeated failures.

## Lessons Learned

Authentication logs are useful for detecting password-guessing patterns. Detection quality improves when log analysis is combined with asset, identity, and network context.
