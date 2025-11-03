# CodeAlpha_BasicNetworkSniffer

## Project Overview
This repository contains a **Basic Network Sniffer** implemented in Python. This utility is designed to capture, dissect, and analyze live network traffic packets, offering practical visibility into network security and protocol fundamentals. It serves as a foundational tool for understanding how data flows across a network.

---

## 🛠️ Tool Features and Capabilities

This Python-based utility, built using the powerful **Scapy** library, performs real-time packet analysis and provides the following core features:

### **1. Real-Time Packet Capture**
* **Live Traffic Monitoring:** Actively captures network packets transmitted over the local network interface.
* **Scapy-Powered Dissection:** Utilizes the Scapy library for robust and accurate parsing of packet structures.
* **Protocol Filtering:** Employs Berkeley Packet Filter (BPF) syntax to capture only targeted traffic (e.g., only IP packets), optimizing resource usage and output clarity.

### **2. Detailed Protocol Analysis**
The sniffer provides a structured breakdown of key information from the IP (Layer 3) and Transport (Layer 4) layers:

* **Endpoint Identification:** Extracts and displays the **Source IP Address** and **Destination IP Address** for every captured packet.
* **Transport Protocol Visibility:** Identifies the type of Layer 4 protocol used, specifically differentiating between **TCP**, **UDP**, and **ICMP**.
* **Port Information:** Extracts and presents the **Source Port** and **Destination Port** for TCP and UDP packets.
* **Data Payload Extraction:** Retrieves the raw data (payload) contained within the packet. It includes functionality to attempt decoding the payload (e.g., using UTF-8) for human-readable output.



## 🚀 Getting Started

### Prerequisites
1.  **Python:** Ensure Python 3.x is installed on your system.
2.  **Scapy:** Install the necessary library using pip:
    ```bash
    pip install scapy
    ```
3.  **Permissions:** **Crucially**, running a network sniffer requires elevated privileges (root on Linux/macOS or Administrator on Windows) to access the network interface card.

### Running the Sniffer
1.  Clone this repository:
    ```bash
    git clone https://github.com/jesudeyi/CodeAlpha_BasicNetworkSniffer.git
    cd CodeAlpha_BasicNetworkSniffer
    ```
2.  Execute the Python script with elevated permissions:
    ```bash
    sudo python3 network_sniffer.py
  
    ```
3.  The sniffer will begin printing structured details of incoming network traffic to the console. Press **Ctrl+C** to stop the monitoring session gracefully.

---

## 📜 License
This project is licensed under the **MIT License**. See the `LICENSE` file for details.
