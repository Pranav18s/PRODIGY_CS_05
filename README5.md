# PRODIGY_CS_05 NetDetective

**NetDetective** is a Python-based packet sniffer and analyzer built using **Scapy**. It captures and displays network packets, providing insights into IP addresses, protocols, ports, and payload data. This tool is designed for educational purposes and to help users understand network traffic and basic packet analysis.

## Features

- Captures network packets in real-time.
- Displays detailed information about captured packets, including:
  - Source and Destination IP addresses
  - Protocol (TCP, UDP, etc.)
  - Source and Destination Ports
  - Raw Payload Data
- Logs captured packet details to a text file for later analysis.
- Easy-to-understand output for educational purposes.

## Requirements

- Python 3.x
- Scapy (for packet capturing and analysis)
- Npcap (Windows users) or libpcap (Linux/macOS users)

### Install Dependencies

To get started, you need to install the required Python libraries and packet capture drivers:

1. Install **Scapy**:
   ```bash
   pip install scapy
   ```
   
2. Install Npcap (for Windows users):
   - Download and install Npcap from the [Npcap Official Website](https://nmap.org/npcap/).

   - (Optional) Install libpcap if you're on Linux or macOS.

### Installation

Clone the repository:

```bash
git clone https://github.com/Pranav18s/PRODIGY_CS_05.git
```

Change to the project directory:

```bash
cd NetDetective
```

Install dependencies (as noted above).

Run the tool:

```bash
python netdetective.py
```

Captured packets will be displayed in the console with relevant details, such as IP addresses, ports, and the protocol used. The details will also be logged to `packet_log.txt` for further analysis.

## Author

Pranav S  
[LinkedIn Profile](https://www.linkedin.com/in/pranav-s-85b106269)

## Ethical Use Disclaimer

This tool is intended for educational purposes only. Make sure you have permission to capture and analyze network traffic before using this tool on any network.
