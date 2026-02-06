Attack → Detection → Mitigation Mapping
  This document provides a structured mapping of attacks performed, tools used, security frameworks referenced, and mitigations implemented as part of the defense-in-depth security project.
  All attacks were executed in a controlled lab environment and validated before and after mitigation.

Attack Mapping Table:

| Attack Scenario                   | Layer       | Tool(s) Used        | OWASP Top 10                                  | MITRE ATT&CK           | What Happened (Before Fix)                     | Mitigation Implemented                                             | Result After Fix                     |
| --------------------------------- | ----------- | ------------------- | --------------------------------------------- | ---------------------- | ---------------------------------------------- | ------------------------------------------------------------------ | ------------------------------------ |
| Network Port Scan                 | Network     | Nmap                | A05: Security Misconfiguration                | Reconnaissance (T1046) | All open ports were visible, exposing services | Default-deny firewall rules, limited allowed ports, IDS monitoring | Scan detected, unused ports blocked  |
| Service Enumeration               | Network     | Nmap                | A05: Security Misconfiguration                | Reconnaissance (T1046) | Service banners exposed application details    | Firewall filtering and reduced exposed services                    | Reduced attack surface               |
| Stored XSS via File Upload        | Application | Burp Suite, Browser | A03: Injection                                | Initial Access         | Uploaded HTML executed JavaScript when opened  | File type validation, removal of direct file rendering             | Script execution blocked             |
| Direct File Access (/media)       | Application | Browser, cURL       | A01: Broken Access Control                    | Privilege Abuse        | Uploaded files accessible directly via URL     | Controlled download endpoint, access checks                        | Unauthorized access prevented        |
| Broken Access Control (IDOR-like) | Application | Browser, cURL       | A01: Broken Access Control                    | Privilege Abuse        | Users could access resources not owned by them | Authorization checks enforced at application layer                 | Access restricted                    |
| Authentication Abuse              | Application | Browser             | A07: Identification & Authentication Failures | Credential Access      | Multiple login attempts allowed                | Login protection and monitoring                                    | Abuse detected and limited           |
| Insecure File Storage             | Data        | OS Access           | A02: Cryptographic Failures                   | Impact                 | Uploaded sensitive files stored in plaintext   | Encryption at rest (filesystem-level)                              | Data protected if system compromised |
| Lateral Traffic Visibility        | Network     | Suricata            | A05: Security Misconfiguration                | Reconnaissance         | Network attacks passed without visibility      | IDS deployed on firewall                                           | Alerts generated and logged          |
| Undetected Attacks                | Monitoring  | —                   | —                                             | —                      | No centralized visibility                      | SIEM (Wazuh) integration                                           | Centralized alerts & timelines       |

After implementing mitigations:

    Network scans triggered IDS alerts and were logged centrally
    Stored XSS payloads no longer executed
    Unauthorized file access attempts failed
    Authentication abuse attempts were visible in logs
    Sensitive files remained unreadable even with filesystem access

Defense-in-Depth Validation

 | Security Layer | Control Implemented              |
| -------------- | -------------------------------- |
| Network        | Firewall (default-deny), IDS     |
| Application    | Input validation, access control |
| Authentication | Login monitoring                 |
| Data           | Encryption at rest               |
| Monitoring     | Centralized SIEM                 |

