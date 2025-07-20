# CodeAlpha_Tasks
This Repository includes two CyberSecurity projects for CodeAlpha Basic Network Sniffer and Phishing Awareness Training.

## Task 1: Network Packet Sniffer

This Network Sniffer captures and analyzes live network packets with extra functionality like suspicious packet detection and GeoIP metadata lookup.

###  Features
- Live network traffic capture using `scapy`
- User-selectable payload view modes:
  - `short`, `full`, `hex`, `ascii`
- GeoIP metadata:
  - Country, ISP, organization, VPN/proxy status
- Colored terminal output for readability
- Logging:
  - All packets → `all_sniffed_packets.csv`
  - Suspicious packets → `suspicious_packets.txt`
- Suspicious activity detection (DoS-like behavior)

### 📁 Files
- `packet_sniffer.py` – main script
- `all_sniffed_packets.csv` – log of all captured packets
- `suspicious_packets.txt` – log of suspicious packets with payload

#  Requirements
bash
pip install scapy termcolor requests
 Note: Run with sudo for full packet sniffing access.

# ▶ **How to Run**
sudo python3 packet_sniffer.py

 Input Options
-	•	Select payload view mode (short/full/hex/ascii)
-	•	Choose a protocol filter (tcp/udp/icmp/all)

###**Task 2: Phishing Awareness Training**

**Objective**

-To create a phishing awareness presentation that:
-	•	Educates users about phishing and its types
-	•	Shares detection techniques
-	•	Provides safety best practices
-	•	Includes real-world examples

- Files Included
-	•	Phishing_Awareness_Slides.pdf: Main presentation
-	•	phishing_infographics/: Folder of all infographics and slide images
-	•	README.md: Documentation of both tasks
-
- Key Topics Covered
-	1.	What is Phishing?
-	2.	Types of Phishing Attacks
-	3.	How to Identify a Phishing Attempt
-	4.	Social Engineering Tactics
	5.	Prevention Best Practices
	6.	Real-World Example
	7.	Conclusion

