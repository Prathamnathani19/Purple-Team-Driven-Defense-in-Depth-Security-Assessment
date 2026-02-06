Suricata IDS / IPS Configuration Notes

Purpose
Suricata is deployed on the Firewall VM to provide network-level intrusion detection and prevention.
It inspects traffic flowing between the attacker network and the internal web server and generates alerts for suspicious or malicious activity.
The goal is visibility first (IDS), with the ability to enforce prevention (IPS) if required.

Deployment Context:


| Component         | Details                                   |
| ----------------- | ----------------------------------------- |
| Firewall VM       | Hosts Suricata                            |
| Interfaces        | `ens33` (WAN), `ens36` (LAN)              |
| Traffic Inspected | Forwarded traffic (Attacker → Web Server) |
| Log Consumers     | Local logs + Wazuh SIEM                   |


Level 0 – Baseline (No IDS)

At the initial stage:

      No packet inspection
      Network attacks passed silently
      No alerting or visibility

Level 1 – Install Suricata
      
      sudo apt update
      sudo apt install suricata -y

  Verify installation:

      suricata --build-info

Level 2 – Configure Network Variables

  Edit Suricata configuration:

      sudo nano /etc/suricata/suricata.yaml


  Set protected network:

      HOME_NET: "[192.168.10.0/24]"
      EXTERNAL_NET: "!$HOME_NET"


Why:

      Ensures alerts are generated only for traffic targeting internal assets
      Reduces false positives

This baseline was used to compare behavior before IDS deployment.


Level 3 – Select Monitoring Interface

  Identify interfaces:

      ip a


  Suricata was configured to monitor forwarded traffic on the firewall interface.

Level 4 – Enable Rule Sets

  Rules are stored in:

      /var/lib/suricata/rules/


  Update rules:

      sudo suricata-update

  Verify rules loaded:

      sudo suricata -T -c /etc/suricata/suricata.yaml


  Expected output:

      Rules loaded successfully

Level 5 – IDS Mode (Detection)

    Suricata initially runs in IDS mode.

    Start service:

      sudo systemctl start suricata
      sudo systemctl enable suricata

  Alerts Generated For:

      Nmap scans
      Port scanning behavior
      Suspicious TCP patterns
      Web attack signatures

Log Locations:


    | Log Type        | Path                             |
    | --------------- | -------------------------------- |
    | Fast alerts     | `/var/log/suricata/fast.log`     |
    | Detailed events | `/var/log/suricata/eve.json`     |
    | Engine logs     | `/var/log/suricata/suricata.log` |


Level 6 – Attack Validation

  Example validation:

    nmap -sS -p- 192.168.10.100

  Observed behavior:

    Scan detected by Suricata
    Alerts generated
    Logged events forwarded to SIEM

  Final Outcome:

    | Capability                   | Status |
    | ---------------------------- | ------ |
    | Network attack detection     | ✅      |
    | Scan visibility              | ✅      |
    | Centralized logging          | ✅      |
    | False positive control       | ✅      |
    | Defense-in-depth integration | ✅      |




