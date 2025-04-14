# Sample Incident Response Playbook: Unauthorized Access Attempt

## 1. Overview
This playbook is intended to guide security analysts through the process of responding to unauthorized access attempts detected via our SIEM system.

## 2. Detection
- Review alerts from threat intelligence modules.
- Confirm unusual login activities using log analysis tools.

## 3. Containment
- Isolate affected systems from the network.
- Block the source IP address in your firewall.
- Disable compromised user accounts immediately.

## 4. Eradication
- Conduct a forensic investigation to determine the scope of the breach.
- Remove any malware or backdoors found.
- Patch vulnerabilities identified during the investigation.

## 5. Recovery
- Restore systems from secure backups.
- Monitor for any sign of re-infection.
- Reinstate network connectivity once the threat is neutralized.

## 6. Post-Incident Analysis
- Document the incident details and response actions.
- Identify improvements for future incident response.
- Schedule a security review meeting.
