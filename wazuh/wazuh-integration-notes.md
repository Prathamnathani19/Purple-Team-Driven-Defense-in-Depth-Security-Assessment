#Wazuh SIEM Integration Notes

Purpose
  Wazuh is deployed as a centralized SIEM and host-based intrusion detection system (HIDS) to collect, correlate, and analyze security-relevant logs from multiple components of the environment.
  While Suricata provides network-level detection, Wazuh provides host, authentication, and system-level visibility, enabling full attack timeline reconstruction.

Deployment Context:

| Component     | Details                                           |
| ------------- | ------------------------------------------------- |
| Wazuh Manager | Dedicated SIEM VM                                 |
| Wazuh Agents  | Web Server VM, Firewall VM                        |
| Log Sources   | System logs, auth logs, firewall logs, IDS alerts |
| Protocol      | TCP (1514, 1515)                                  |

Level 0 – Baseline (No Centralized Monitoring)
At the initial stage:
  Logs existed only locally on each machine
  Attacks could not be correlated across systems
  No centralized visibility or alerting
  This made investigation and incident analysis difficult.

Level 1 – Wazuh Installation
  Wazuh was installed on a dedicated SIEM VM to avoid performance and security overlap with other components

Level 2 – Agent Installation & Registration

  Wazuh agents were installed on monitored hosts:
      Web Server
      Firewall

  Agent registration enabled secure communication with the Wazuh Manager.

  This allowed host-level logs to be forwarded centrally.
Level 3 – Log Collection Configuration

  Wazuh was configured to collect:

  System & Authentication Logs:

      /var/log/syslog
      /var/log/auth.log

  Firewall Logs

  iptables dropped packet logs
  Kernel-level firewall events
  IDS Logs

Suricata alerts (eve.json, fast.log)

This provided multi-layer visibility.

Level 4 – Alert Generation & Correlation

  Wazuh generated alerts for:

    Successful and failed login attempts
    Privilege escalation via sudo
    Suspicious authentication behavior
    Firewall drop events
    IDS alerts forwarded from Suricata

  Alerts were visible via:
  
    Local alert logs
    Wazuh dashboard


  Level 5 – Attack Visibility & Timeline Creation

    Using Wazuh, attack behavior could be reconstructed:

        Firewall logs show blocked packets
        Authentication attempts logged
        All events correlated under a single timeline

This enabled incident-style analysis.

Final Outcome:

| Capability               | Status |
| ------------------------ | ------ |
| Centralized logging      | ✅      |
| Host-based detection     | ✅      |
| Firewall log correlation | ✅      |
| IDS alert visibility     | ✅      |
| SOC-style monitoring     | ✅      |


