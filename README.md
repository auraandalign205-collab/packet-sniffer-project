markdown# Network Packet Sniffer

A lightweight Python network analysis tool designed to capture, decode, and analyze live network traffic packets flowing through a network interface card.

## Features
- **Live Traffic Capture:** Hooks into network layers using `Scapy` and `Npcap`.
- **Protocol Decoding:** Separates and identifies `TCP` and `UDP` connections.
- **Addressing Maps:** Extracts source/destination IP addresses alongside hardware port mapping.
- **Payload Extraction:** Sniffs out underlying payload layers, presenting plaintext streams or structured Hexadecimal representations.
- **Session Metrics:** Displays a traffic breakdown summary upon application exit.

## Core Learning Objectives Fulfilled
- Understood network structures by parsing Layer 3 (IP) and Layer 4 (TCP/UDP) protocols.
- Analyzed plaintext data distribution protocols like SSDP (`M-SEARCH`).
- Explored raw encrypted packet formats via Hex-conversions.

## Installation & Usage

1. Install packet dependencies:
   ```bash
   pip install scapy
   ```
2. **Important for Windows Users:** Install [Npcap](https://npcap.com) with "WinPcap API-compatible Mode" enabled.
3. Run the script with administrative privileges:
   ```bash
   python sniffer.py
   ```