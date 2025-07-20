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

### Files
- `packet_sniffer.py` – main script
- `all_sniffed_packets.csv` – log of all captured packets
- `suspicious_packets.txt` – log of suspicious packets with payload


⸻

###Requirements

```pip install scapy termcolor requests```

Note: Run with sudo for full packet sniffing access.


### ▶ How to Run

sudo python3 packet_sniffer.py



# Task 2: Phishing Awareness Training

### Objective

To create a phishing awareness presentation that:
	```•	Educates users about phishing and its types
	•	Shares detection techniques
	•	Provides safety best practices
	•	Includes real-world examples```


### Key Topics Covered
	•	What is Phishing?
	•	Types of Phishing Attacks
	•	How to Identify a Phishing Attempt
	•	Social Engineering Tactics
	•	Prevention Best Practices
	•	Real-World Example
	•	Conclusion
