Firewall Rules Implementation (iptables)

Purpose:
  The firewall acts as a security gateway between the attacker network and the internal network.
  All traffic is inspected, filtered, logged, and only explicitly allowed services are permitted.
  
The approach follows a default-deny policy, which is a core principle of defense in depth.

Network Context

  | Component       | IP Address       |
  | --------------- | ---------------- |
  | Firewall (LAN)  | `192.168.10.2`   |
  | Web Server      | `192.168.10.100` |
  | Wazuh SIEM      | `192.168.10.150` |
  | Attacker (Kali) | Untrusted        |
  | LAN Interface   | `ens36`          |
  | WAN Interface   | `ens33`          |


🔰 Level 0 – Baseline (No Security)

  At the initial stage:

    All traffic was allowed

    Web server services were exposed

    No filtering or logging was enforced

 This baseline was used to observe attack surface before defenses.

 Level 1 – Enable IP Forwarding

  The firewall must route traffic between networks.
  
        sudo sysctl -w net.ipv4.ip_forward=1
  Permanent configuration:
  
        sudo nano /etc/sysctl.conf
        
  Add:
  
        net.ipv4.ip_forward=1
 Level 2 – Flush Existing Rules
 
  Ensure no inherited or conflicting rules exist.
  
        sudo iptables -F
        sudo iptables -t nat -F
        sudo iptables -X
        
 Level 3 – Default-Deny Policy
 
  Block everything by default.
  
        sudo iptables -P INPUT DROP
        sudo iptables -P FORWARD DROP
        sudo iptables -P OUTPUT ACCEPT
        
  Rationale:
  
    Inbound and forwarded traffic must be explicitly allowed
    Outbound traffic allowed for updates and logging
  
  Level 4 – Allow Loopback & Established Connections
  
        sudo iptables -A INPUT -i lo -j ACCEPT
        sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        sudo iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        
    Why:
      Prevents breaking existing connections
      Required for normal system operation

  Level 5 – Allow Web Traffic to Web Server
    Allow only HTTP traffic to the web server.

        sudo iptables -A FORWARD -p tcp -d 192.168.10.100 --dport 80 -j ACCEPT
        
    (HTTPS can be added later if configured.)
  
  Level 6 – Restrict SSH at Network Level

    SSH access is not open globally.

    Only LAN-based administrative access is allowed (no key-based claim).

        sudo iptables -A FORWARD -p tcp -s 192.168.10.0/24 -d 192.168.10.100 --dport 22 -j ACCEPT

    Security Benefit:
    
      SSH is inaccessible from attacker network
      Administrative access restricted by network segmentation
      
  Level 7 – Allow Wazuh Log Communication
  
    Permit web server and firewall to communicate with SIEM.
    
        sudo iptables -A FORWARD -p tcp -d 192.168.10.150 --dport 1514 -j ACCEPT
        sudo iptables -A FORWARD -p tcp -d 192.168.10.150 --dport 1515 -j ACCEPT

  Level 8 – NAT Configuration (Outbound Access)
  
    Enable internet access for internal machines via firewall.

        sudo iptables -t nat -A POSTROUTING -o ens33 -j MASQUERADE

    Purpose:
      Allows updates (apt update)
      Prevents direct exposure of internal IPs

   Level 9 – ICMP Control (Ping)
    Allow controlled ICMP for diagnostics.

        sudo iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
        sudo iptables -A FORWARD -p icmp -j ACCEPT
        
   Level 10 – Logging Dropped Packets
    Log blocked traffic for monitoring and SIEM correlation.

        sudo iptables -A INPUT -j LOG --log-prefix "FW_DROP_INPUT: " --log-level 4
        sudo iptables -A FORWARD -j LOG --log-prefix "FW_DROP_FORWARD: " --log-level 4


    Logs appear in:
        /var/log/kern.log

   Level 11 - Save Firewall Rules

    Persist rules across reboot.

        sudo iptables-save > /etc/iptables.rules
    (Optional restore on boot using netfilter-persistent.)



