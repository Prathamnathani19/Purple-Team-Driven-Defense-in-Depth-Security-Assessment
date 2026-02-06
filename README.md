# Purple-Team-Driven-Defense-in-Depth-Security-Assessment
This project demonstrates a practical defense-in-depth security assessment performed in a controlled lab environment. The objective was to simulate real attacker behavior, observe how attacks propagate across layers, and implement layered security controls to detect, mitigate, and reduce the impact of those attacks.
The project focuses on manual vulnerability assessment and penetration testing (VAPT) at the application and network layers, followed by defensive controls such as firewall enforcement, intrusion detection, centralized logging, and data protection.

Architecture Overview

The environment is designed using a segmented multi-VM architecture:

    Attacker VM (Kali Linux) – Simulates real-world attacker activity

    Firewall VM – Enforces traffic filtering and hosts IDS/IPS

    Web Server VM – Hosts a Django web application and encrypted data

    SIEM VM (Wazuh) – Centralized monitoring and log correlation

Traffic Flow:-

    Attacker (Kali) → Firewall (iptables + Suricata) → Web Server (Django)
                                      ↓
                                 Logs forwarded
                                      ↓
                                 Wazuh SIEM


All attacker traffic is forced through the firewall and IDS layer before reaching the application, ensuring inspection and logging at each stage.


🔴 Attacks Performed (Red Team)

The following attacks were manually performed and validated:

  Network Reconnaissance

      Port scanning and service discovery

  Stored Cross-Site Scripting (XSS)

      HTML file upload leading to JavaScript execution

  Broken Access Control (IDOR-like testing)

      Unauthorized access to protected resources

  Authentication Abuse

      Multiple login attempts and weak access controls

  Insecure File Handling

      Direct access to uploaded files via media paths

  All attacks were executed in a controlled environment and documented with evidence.


🔵 Detection & Monitoring (Blue Team)
Network-Level Detection

      Firewall rules implemented using a default-deny approach

      IDS/IPS deployed to detect:

          Network scans

          Suspicious traffic patterns

          Policy violations

Host & Application Monitoring

      Centralized logging using Wazuh SIEM

      Collection and analysis of:

          System logs

          Authentication logs

          Firewall logs

          IDS alerts

          Application events

This enabled end-to-end visibility from attack initiation to detection.

🛡️ Mitigations Implemented

    Firewall Hardening

        Explicit allow rules for required services

        Restricted administrative access at the network level

    Application Security Fixes

        Input validation and secure file upload handling

        Removal of direct file rendering paths

        Access control enforcement

    Data Protection

        Encryption of sensitive uploaded files at rest using filesystem-level encryption

    Re-testing

  All attacks were re-executed post-mitigation to validate effectiveness


  🧠 Framework Mapping
        
        OWASP Top 10

          A01 – Broken Access Control

          A03 – Injection (XSS)

          A05 – Security Misconfiguration

          A07 – Identification and Authentication Failures

          A02 – Cryptographic Failures

        MITRE ATT&CK

          Reconnaissance

          Initial Access

          Privilege Abuse

          Impact

      Each attack and mitigation was mapped to relevant techniques for structured analysis.
