// Flash Cards Data Structure
const flashcardsData = {
    networking: [
        {
            id: "net_1",
            question: "Explain the OSI vs. TCP/IP model. Why does it matter in security?",
            answer: "The OSI model has 7 layers (Physical, Data Link, Network, Transport, Session, Presentation, Application) while TCP/IP has 4 layers (Network Access, Internet, Transport, Application). Understanding these models is crucial for security because attacks can occur at any layer, and security controls must be implemented at appropriate layers. For example, firewalls operate at Layer 3/4, encryption at Layer 6/7, and network segmentation at Layer 2."
        },
        {
            id: "net_2",
            question: "Walk me through the TCP 3-way handshake. Where can it be attacked?",
            answer: "The TCP handshake involves: 1) Client sends SYN, 2) Server responds with SYN-ACK, 3) Client sends ACK to establish connection. This process is vulnerable to SYN flood attacks where attackers send many SYN packets without completing the handshake, exhausting server resources. Additionally, the handshake can be intercepted for man-in-the-middle attacks or spoofed to hijack existing connections."
        },
        {
            id: "net_3",
            question: "What's the difference between TCP and UDP, and how does that impact security monitoring?",
            answer: "TCP is connection-oriented with error correction and flow control, while UDP is connectionless and faster but unreliable. For security monitoring, TCP connections provide more forensic data through sequence numbers and connection states, making anomalies easier to detect. UDP traffic is harder to track since there's no connection state, making it popular for covert channels and harder to monitor for data exfiltration."
        },
        {
            id: "net_4",
            question: "What's an ARP spoofing attack? How do you detect and prevent it?",
            answer: "ARP spoofing involves sending fake ARP replies to associate an attacker's MAC address with a legitimate IP address, enabling man-in-the-middle attacks. Detection methods include monitoring for duplicate MAC addresses, unusual ARP traffic patterns, and using tools like arpwatch. Prevention includes static ARP entries for critical systems, dynamic ARP inspection on switches, and network segmentation."
        },
        {
            id: "net_5",
            question: "Explain the difference between a switch, router, and firewall.",
            answer: "A switch operates at Layer 2, connecting devices within the same network segment using MAC addresses. A router operates at Layer 3, connecting different networks using IP addresses and making routing decisions. A firewall operates at multiple layers (3-7), filtering traffic based on security policies and can perform deep packet inspection, while switches and routers primarily focus on connectivity and routing."
        },
        {
            id: "net_6",
            question: "What's the difference between NAT and PAT? Why are they important for security?",
            answer: "NAT (Network Address Translation) maps one private IP to one public IP, while PAT (Port Address Translation) maps multiple private IPs to one public IP using different ports. Both provide security by hiding internal network topology and acting as a basic firewall since external hosts cannot initiate connections to internal systems. PAT is more common in home/small office environments due to limited public IP addresses."
        },
        {
            id: "net_7",
            question: "What's the purpose of a load balancer, and what security risks can it introduce?",
            answer: "Load balancers distribute traffic across multiple servers to improve performance and availability, while providing SSL termination and health checks. Security risks include becoming a single point of failure, potential SSL certificate management issues, and the risk of session hijacking if session persistence isn't properly configured. They can also introduce blind spots in security monitoring if not properly configured to forward logs and maintain client IP visibility."
        },
        {
            id: "net_8",
            question: "What's DNS poisoning / cache poisoning? How would you detect it?",
            answer: "DNS poisoning involves corrupting DNS cache entries to redirect users to malicious servers instead of legitimate ones. Detection methods include monitoring for DNS responses with unexpected TTL values, comparing DNS responses from multiple servers, and analyzing DNS query patterns for anomalies. Implementing DNSSEC, using secure DNS resolvers, and monitoring DNS traffic for unusual patterns are key prevention and detection strategies."
        },
        {
            id: "net_9",
            question: "Explain how DHCP works. How can attackers abuse it?",
            answer: "DHCP automatically assigns IP addresses through a 4-step process: Discover, Offer, Request, Acknowledge. Attackers can abuse DHCP through rogue DHCP servers that provide malicious configurations (like pointing to attacker-controlled DNS servers), DHCP starvation attacks that exhaust the IP pool, or DHCP spoofing to perform man-in-the-middle attacks. DHCP snooping on switches and monitoring for multiple DHCP servers can help detect these attacks."
        },
        {
            id: "net_10",
            question: "What's the difference between a VPN and a proxy?",
            answer: "A VPN creates an encrypted tunnel for all network traffic at the network layer, providing comprehensive protection and appearing as if you're on the remote network. A proxy only handles specific application traffic (like HTTP) at the application layer, acting as an intermediary without necessarily encrypting traffic. VPNs provide better security and privacy but may have more overhead, while proxies offer more granular control and can provide caching benefits."
        },
        {
            id: "net_11",
            question: "Describe a man-in-the-middle (MITM) attack. How would you detect it on a corporate network?",
            answer: "A MITM attack involves an attacker intercepting and potentially modifying communications between two parties who believe they're communicating directly. Detection methods include monitoring for certificate changes, unusual ARP traffic, duplicate MAC addresses, and analyzing SSL/TLS handshakes for anomalies. Network monitoring tools, certificate pinning, and analyzing network latency patterns can help identify when traffic is being redirected through an attacker's system."
        },
        {
            id: "net_12",
            question: "What's the difference between a DoS and a DDoS?",
            answer: "DoS (Denial of Service) attacks originate from a single source attempting to overwhelm a target system's resources. DDoS (Distributed Denial of Service) attacks use multiple compromised systems (botnets) to launch coordinated attacks, making them much harder to block and more devastating. DDoS attacks are more difficult to defend against because blocking individual IP addresses is ineffective when thousands of sources are involved, requiring more sophisticated mitigation strategies."
        },
        {
            id: "net_13",
            question: "How does a SYN flood attack work?",
            answer: "A SYN flood attack exploits the TCP three-way handshake by sending numerous SYN packets to a target without completing the handshake, leaving half-open connections that consume server resources. The server allocates memory for each connection attempt and waits for the final ACK that never comes, eventually exhausting available connection slots. Countermeasures include SYN cookies, reducing timeout values, rate limiting, and using firewalls to filter suspicious traffic patterns."
        },
        {
            id: "net_14",
            question: "What's a smurf attack?",
            answer: "A smurf attack is a type of DDoS that exploits ICMP echo requests (ping) by sending them to a network's broadcast address with a spoofed source IP of the victim. All hosts on the network respond to the victim's IP address, amplifying the attack traffic significantly. This attack leverages IP directed broadcasts and can be prevented by disabling broadcast forwarding on routers and configuring hosts not to respond to broadcast pings."
        },
        {
            id: "net_15",
            question: "What is IP spoofing, and how do you prevent it?",
            answer: "IP spoofing involves falsifying the source IP address in packet headers to impersonate another system or hide the attacker's identity. Prevention methods include implementing ingress and egress filtering at network boundaries, using anti-spoofing ACLs on routers, and deploying network authentication mechanisms. Source address validation and implementing reverse path forwarding (RPF) checks help ensure packets are coming from legitimate network paths."
        },
        {
            id: "net_16",
            question: "What's the difference between sniffing vs. spoofing?",
            answer: "Sniffing is the passive interception and monitoring of network traffic to capture data packets, typically using tools like Wireshark or tcpdump. Spoofing is the active falsification of data (like IP addresses, MAC addresses, or DNS responses) to impersonate legitimate entities. Sniffing is primarily for reconnaissance and data collection, while spoofing is used to actively deceive systems and redirect or manipulate communications."
        },
        {
            id: "net_17",
            question: "How would you detect data exfiltration over DNS?",
            answer: "DNS exfiltration can be detected by monitoring for unusual DNS query patterns such as excessive queries to uncommon domains, queries with suspiciously long subdomains, high-frequency queries to the same domain, and DNS queries containing encoded data. Baseline DNS behavior and look for statistical anomalies, analyze query lengths and character distributions, and monitor for DNS tunneling tools' signatures. DNS security solutions and machine learning can help identify these patterns."
        },
        {
            id: "net_18",
            question: "How does an attacker use ICMP tunneling?",
            answer: "ICMP tunneling embeds data within ICMP packets (typically ping requests/replies) to create covert communication channels that bypass firewall restrictions. Attackers can exfiltrate data or establish command and control channels since ICMP is often allowed through firewalls for network diagnostics. Detection involves analyzing ICMP packet sizes, frequency patterns, and payload content for anomalies, as legitimate ICMP traffic typically has predictable patterns and sizes."
        },
        {
            id: "net_19",
            question: "What's the difference between port scanning and banner grabbing?",
            answer: "Port scanning determines which ports are open on a target system by sending packets and analyzing responses, revealing potential attack surfaces. Banner grabbing is the next step that connects to open ports to retrieve service information like software versions and configurations. Port scanning is broader reconnaissance to map available services, while banner grabbing provides detailed information about specific services that can be used to identify vulnerabilities."
        },
        {
            id: "net_20",
            question: "If you see thousands of connections to port 22 in logs, what does that tell you?",
            answer: "Thousands of connections to port 22 (SSH) typically indicate a brute force attack attempting to guess login credentials through automated login attempts. This could be a distributed attack from multiple sources or a focused attack from fewer sources with high connection rates. Immediate response should include analyzing source IPs, implementing rate limiting, reviewing authentication logs for successful logins, and potentially blocking suspicious IP ranges while investigating the scope of the attack."
        },
        {
            id: "net_21",
            question: "Explain HTTPS vs. HTTP. How does TLS work at a high level?",
            answer: "HTTP transmits data in plaintext while HTTPS encrypts data using TLS/SSL, providing confidentiality, integrity, and authentication. TLS works through a handshake process where the client and server exchange certificates, agree on encryption algorithms, and establish shared encryption keys. The process includes certificate validation, key exchange, and symmetric encryption setup, ensuring that subsequent communication is encrypted and protected from eavesdropping and tampering."
        },
        {
            id: "net_22",
            question: "What's the role of SSL certificates in authentication?",
            answer: "SSL certificates provide server authentication by containing the server's public key and identity information, digitally signed by a trusted Certificate Authority (CA). Clients verify the certificate's validity, check if it matches the domain being accessed, and confirm it's signed by a trusted CA. This prevents man-in-the-middle attacks by ensuring clients connect to legitimate servers and establishes trust through the PKI (Public Key Infrastructure) chain of trust."
        },
        {
            id: "net_23",
            question: "What's Perfect Forward Secrecy (PFS)?",
            answer: "Perfect Forward Secrecy ensures that session keys are not compromised even if the server's private key is later compromised, by using ephemeral keys that are discarded after each session. PFS is implemented through key exchange algorithms like Diffie-Hellman Ephemeral (DHE) or Elliptic Curve Diffie-Hellman Ephemeral (ECDHE). This means that even if an attacker obtains the server's private key, they cannot decrypt previously recorded encrypted communications."
        },
        {
            id: "net_24",
            question: "How would you secure SMTP traffic?",
            answer: "SMTP can be secured using STARTTLS for opportunistic encryption, SMTPS (SMTP over SSL/TLS) for forced encryption, and implementing authentication mechanisms like SMTP AUTH. Additional security measures include configuring SPF, DKIM, and DMARC records for email authentication, using strong authentication credentials, and implementing rate limiting and anti-spam measures. Proper certificate management and disabling legacy insecure protocols are also essential."
        },
        {
            id: "net_25",
            question: "How would you secure DNS traffic? (e.g., DNSSEC, DoH, DoT).",
            answer: "DNS security involves multiple approaches: DNSSEC provides cryptographic signatures to verify DNS response authenticity and integrity, preventing DNS spoofing. DNS over HTTPS (DoH) and DNS over TLS (DoT) encrypt DNS queries to prevent eavesdropping and manipulation. Additional measures include using secure DNS resolvers, implementing DNS filtering for malicious domains, and monitoring DNS traffic for anomalies and data exfiltration attempts."
        },
        {
            id: "net_26",
            question: "What's the difference between IPSec transport vs. tunnel mode?",
            answer: "IPSec transport mode encrypts only the payload of IP packets, leaving the original IP headers intact, typically used for end-to-end communication between hosts. Tunnel mode encrypts the entire original IP packet and adds new IP headers, commonly used for VPN gateways and site-to-site connections. Transport mode provides less overhead but reveals routing information, while tunnel mode provides complete packet protection but adds additional overhead."
        },
        {
            id: "net_27",
            question: "What's the difference between TLS 1.2 and TLS 1.3?",
            answer: "TLS 1.3 provides improved security by removing vulnerable cryptographic algorithms, reducing handshake round trips from 2 to 1 for better performance, and enforcing Perfect Forward Secrecy. TLS 1.3 eliminates support for weak ciphers like RC4 and 3DES, implements more secure key derivation, and provides better privacy by encrypting more handshake data. The simplified protocol also reduces attack surface and potential implementation vulnerabilities."
        },
        {
            id: "net_28",
            question: "Why is FTP insecure? What's the secure alternative?",
            answer: "FTP transmits credentials and data in plaintext, making it vulnerable to eavesdropping and credential theft, and uses separate control and data channels that complicate firewall configuration. FTP also lacks integrity verification and modern authentication methods. Secure alternatives include SFTP (SSH File Transfer Protocol) which encrypts all traffic, FTPS (FTP over SSL/TLS) which adds encryption to FTP, and SCP for simple secure file copying over SSH."
        },
        {
            id: "net_29",
            question: "How would you secure remote admin protocols (SSH, RDP)?",
            answer: "Secure remote admin protocols by using strong authentication (key-based for SSH, strong passwords/certificates for RDP), changing default ports, implementing rate limiting and fail2ban for brute force protection, and restricting access to specific IP ranges. Additional measures include disabling unused features, using VPN for access, implementing multi-factor authentication, keeping protocols updated, and monitoring access logs for suspicious activities."
        },
        {
            id: "net_30",
            question: "What's the difference between Kerberos and NTLM?",
            answer: "Kerberos is a more secure authentication protocol that uses tickets and symmetric encryption, requiring a trusted third-party Key Distribution Center (KDC), and provides mutual authentication. NTLM is an older challenge-response protocol that's more vulnerable to attacks like pass-the-hash and doesn't provide mutual authentication. Kerberos is preferred for modern environments due to better security, scalability, and support for delegation, while NTLM is maintained for backward compatibility."
        },
        {
            id: "net_31",
            question: "You find open Telnet on a production server. What do you do?",
            answer: "Immediately disable the Telnet service as it transmits credentials and data in plaintext, creating a critical security vulnerability. Document the finding, identify who has access and why it was enabled, and implement SSH as a secure alternative for remote access. Review logs for any unauthorized access, assess potential data exposure, change any credentials that may have been transmitted over Telnet, and update security policies to prevent future insecure protocol deployments."
        },
        {
            id: "net_32",
            question: "Logs show failed logins to SSH from multiple countries. How do you respond?",
            answer: "This indicates a likely brute force attack requiring immediate action: implement rate limiting and fail2ban to block repeated failed attempts, analyze the scope and source IPs to determine if blocking entire countries is appropriate, and review authentication logs for any successful logins. Strengthen SSH security by disabling password authentication in favor of key-based auth, changing the default port, and implementing multi-factor authentication while monitoring for indicators of compromise."
        },
        {
            id: "net_33",
            question: "A user reports slow network traffic. How do you investigate if it's a DoS attack?",
            answer: "Begin by collecting baseline network metrics and comparing current traffic patterns to identify anomalies in bandwidth usage, connection counts, and response times. Analyze network logs for unusual traffic patterns, check for repeated connections from specific sources, and examine protocol distributions for potential flooding attacks. Use network monitoring tools to identify traffic sources and patterns, and correlate symptoms with security event logs to determine if the slowness is attack-related or operational."
        },
        {
            id: "net_34",
            question: "Your firewall shows outbound traffic on port 4444. What does this suggest?",
            answer: "Port 4444 is commonly used by malware and remote access tools for command and control communication, suggesting potential malware infection or unauthorized remote access. Immediately investigate the source system for malware, analyze the destination IP for reputation and geographical location, and capture traffic samples to understand the communication protocol. Block the traffic at the firewall, isolate the affected system, and perform incident response procedures including malware analysis and forensic investigation."
        },
        {
            id: "net_35",
            question: "Your IDS alerts on SMB traffic between two endpoints. Why could this be suspicious?",
            answer: "SMB traffic between endpoints could indicate lateral movement by an attacker, unauthorized file sharing, or potential malware propagation attempting to exploit SMB vulnerabilities. Modern networks should minimize peer-to-peer SMB traffic, with most file access going through dedicated file servers. Investigate whether this traffic is authorized, check for signs of credential dumping or pass-the-hash attacks, and analyze the systems involved for indicators of compromise."
        },
        {
            id: "net_36",
            question: "You see DNS requests to random domains every 5 seconds. What's happening?",
            answer: "This pattern strongly suggests DNS tunneling for command and control communication or data exfiltration, where data is encoded in DNS queries to bypass firewall restrictions. The regular 5-second interval indicates automated malware behavior with a programmed beacon interval. Investigate the source system for malware, analyze the domain names for patterns or encoding, block the domains at the DNS level, and examine the system for backdoors or persistent threats."
        },
        {
            id: "net_37",
            question: "During log review, you see repeated ICMP packets with odd payload sizes. What could this be?",
            answer: "Unusual ICMP packet sizes likely indicate ICMP tunneling, where data is being covertly transmitted within ICMP packets to establish command and control channels or exfiltrate data. Normal ICMP traffic has predictable payload sizes, so variations suggest embedded data. Analyze the payload contents for encoded information, investigate the source and destination systems, and implement network controls to monitor or restrict ICMP traffic based on size and frequency patterns."
        },
        {
            id: "net_38",
            question: "You're asked to explain the risk of an open Wi-Fi network.",
            answer: "Open Wi-Fi networks transmit all data unencrypted, allowing anyone within range to intercept traffic using packet sniffers, potentially capturing credentials, personal information, and sensitive communications. Additional risks include evil twin attacks where attackers create fake hotspots, man-in-the-middle attacks, and malware distribution through network shares. Users should avoid accessing sensitive information on open networks and use VPNs to encrypt their traffic."
        },
        {
            id: "net_39",
            question: "How would you configure a firewall to prevent data exfiltration?",
            answer: "Implement egress filtering to monitor and control outbound traffic, create whitelist-based rules for approved external destinations, and block or monitor suspicious ports commonly used for exfiltration. Configure deep packet inspection to analyze traffic content, implement data loss prevention (DLP) rules to detect sensitive data patterns, and establish logging for all outbound connections. Monitor for unusual protocols, large data transfers, and connections to suspicious domains or IP addresses."
        },
        {
            id: "net_40",
            question: "What network layer defenses would you use against MITM attacks?",
            answer: "Deploy network monitoring to detect ARP spoofing and unusual MAC address changes, implement certificate pinning to detect SSL certificate substitution, and use network access control (NAC) to verify device authenticity. Configure dynamic ARP inspection and DHCP snooping on switches, implement DNSSEC to prevent DNS manipulation, and deploy network segmentation to limit attack scope. Monitor for duplicate IP addresses and unusual network topology changes."
        },
        {
            id: "net_41",
            question: "What's the difference between a firewall vs. IDS vs. IPS?",
            answer: "A firewall controls traffic based on predetermined rules and can block connections, operating in-line and making real-time decisions about traffic flow. An IDS (Intrusion Detection System) passively monitors network traffic and alerts on suspicious activities but cannot block traffic. An IPS (Intrusion Prevention System) combines both functions, actively monitoring traffic like an IDS but also blocking threats in real-time like a firewall, operating in-line to provide active protection."
        },
        {
            id: "net_42",
            question: "How would you use Wireshark to analyze suspicious traffic?",
            answer: "Use Wireshark's filtering capabilities to isolate suspicious traffic by IP, port, or protocol, then analyze packet details for anomalies in protocols, unusual payload sizes, or unexpected communications. Examine connection patterns, look for protocol violations or malformed packets, and analyze timing patterns that might indicate automated behavior. Export objects and flows for further analysis, and use statistical tools to identify outliers in traffic patterns and communication behaviors."
        },
        {
            id: "net_43",
            question: "What's the role of NetFlow logs in security monitoring?",
            answer: "NetFlow logs provide metadata about network communications including source/destination IPs, ports, protocols, byte counts, and timing information without capturing actual packet content. This enables security teams to identify communication patterns, detect data exfiltration through volume analysis, track lateral movement, and perform network forensics. NetFlow is particularly valuable for detecting low-and-slow attacks, establishing baselines for normal network behavior, and investigating incidents across large network infrastructures."
        },
        {
            id: "net_44",
            question: "How would you use tcpdump in incident investigation?",
            answer: "Use tcpdump to capture live network traffic during active incidents or analyze specific network segments by filtering for relevant hosts, ports, or protocols. Apply filters to focus on suspicious activity (e.g., 'tcpdump host 192.168.1.100 and port 80'), capture traffic to files for later analysis with tools like Wireshark, and use it for real-time monitoring of specific network events. Tcpdump is particularly useful for command-line investigation and automated capture during incident response."
        },
        {
            id: "net_45",
            question: "What's the difference between stateful vs. stateless firewalls?",
            answer: "Stateful firewalls track the state of network connections and make decisions based on connection context, allowing return traffic for established connections and providing better security. Stateless firewalls examine each packet independently without connection context, requiring explicit rules for both inbound and outbound traffic. Stateful firewalls offer better security and easier management but require more resources, while stateless firewalls are faster and simpler but provide less sophisticated protection."
        },
        {
            id: "net_46",
            question: "How would you configure VLANs for security segmentation?",
            answer: "Create separate VLANs for different security zones (DMZ, internal, guest, management) and implement inter-VLAN routing controls through firewalls or Layer 3 switches with ACLs. Assign systems to appropriate VLANs based on their security requirements and trust levels, ensuring that critical systems are isolated from general user networks. Configure trunk ports securely, implement VLAN access control, and monitor for VLAN hopping attempts while maintaining proper VLAN documentation and change management."
        },
        {
            id: "net_47",
            question: "Explain zero trust networking in simple terms.",
            answer: "Zero trust networking operates on the principle of 'never trust, always verify,' requiring authentication and authorization for every network access attempt regardless of location or previous access. Unlike traditional perimeter-based security that trusts internal traffic, zero trust treats all traffic as potentially hostile and continuously validates every connection. This approach includes micro-segmentation, least privilege access, continuous monitoring, and identity-based access controls rather than relying on network location for security decisions."
        },
        {
            id: "net_48",
            question: "How do proxy servers improve security?",
            answer: "Proxy servers act as intermediaries that can filter malicious content, block access to dangerous websites, and hide internal network topology from external threats. They provide centralized logging for web activity monitoring, can perform SSL inspection to detect encrypted threats, and implement access controls based on user policies. Proxies also cache content to improve performance, provide anonymity for internal users, and can serve as a chokepoint for implementing data loss prevention and malware scanning."
        },
        {
            id: "net_49",
            question: "How does microsegmentation in the data center improve security?",
            answer: "Microsegmentation creates granular security zones around individual workloads or applications, limiting lateral movement when attackers breach the perimeter. By implementing fine-grained access controls between systems, microsegmentation reduces the blast radius of security incidents and ensures that compromise of one system doesn't automatically grant access to others. This approach enables zero-trust principles within the data center and provides better visibility and control over east-west traffic flows."
        },
        {
            id: "net_50",
            question: "What's the difference between north-south and east-west traffic, and why does it matter?",
            answer: "North-south traffic flows between the data center and external networks (users, internet, branch offices), typically passing through perimeter security controls like firewalls and DMZ zones. East-west traffic flows laterally between systems within the data center, often trusted by default in traditional security models. Understanding this distinction is crucial because most modern attacks involve lateral movement (east-west), requiring internal security controls like microsegmentation and zero trust rather than relying solely on perimeter defenses."
        }
    ],
    
    systems: [
        // 50 systems flashcards - currently empty placeholders
        ...Array.from({length: 50}, (_, i) => ({
            id: `sys_${i + 1}`,
            question: `Systems Question ${i + 1} - Placeholder`,
            answer: `This is a placeholder answer for systems question ${i + 1}. Content will be added soon.`
        }))
    ],
    
    cloud: [
        // 50 cloud flashcards - currently empty placeholders
        ...Array.from({length: 50}, (_, i) => ({
            id: `cloud_${i + 1}`,
            question: `Cloud Question ${i + 1} - Placeholder`,
            answer: `This is a placeholder answer for cloud question ${i + 1}. Content will be added soon.`
        }))
    ],
    
    applications: [
        // 50 applications flashcards - currently empty placeholders
        ...Array.from({length: 50}, (_, i) => ({
            id: `app_${i + 1}`,
            question: `Applications Question ${i + 1} - Placeholder`,
            answer: `This is a placeholder answer for applications question ${i + 1}. Content will be added soon.`
        }))
    ],
    
    'security-operations': [
        // 50 security operations flashcards - currently empty placeholders
        ...Array.from({length: 50}, (_, i) => ({
            id: `secops_${i + 1}`,
            question: `Security Operations Question ${i + 1} - Placeholder`,
            answer: `This is a placeholder answer for security operations question ${i + 1}. Content will be added soon.`
        }))
    ],
    
    automation: [
        // 50 automation flashcards - currently empty placeholders
        ...Array.from({length: 50}, (_, i) => ({
            id: `auto_${i + 1}`,
            question: `Automation Question ${i + 1} - Placeholder`,
            answer: `This is a placeholder answer for automation question ${i + 1}. Content will be added soon.`
        }))
    ]
};

// Export for use in main app
window.flashcardsData = flashcardsData;
