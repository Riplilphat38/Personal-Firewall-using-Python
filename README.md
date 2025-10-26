# Personal-Firewall-using-Python
Developing a Lightweight Personal Firewall that filters traffic based on rules

# 🔥 Personal Firewall 

A custom-built personal firewall application using **Python** and **Scapy**.  
It captures, analyzes, and logs network traffic in real-time and allows dynamic IP/port blocking via a simple GUI.

---

## 📌 Features

- 🔍 Real-time **packet monitoring**
- 📁 Logs all traffic (source IP, destination IP, protocol, ports)
- 🛑 Block any IP or port dynamically via the GUI
- 🧠 Built using **Scapy + Tkinter**
- ⚙️ Fully functional on **Windows OS**

---

## 🛠️ Tools & Technologies

- Python 3
- Scapy (packet capture and parsing)
- NetfilterQueue
- Iptables (kernel-level packet filtering framework)
- Logging module
- Json

---

## ▶️ How to Run

### 🔧 Prerequisites

- Python 3.8 or later installed
- Install dependencies:
  ```bash
  pip install scapy
  ```

  ---

## 📖 How It Works

- Captures all IP packets using Scapy’s sniff() function.
- Each packet is parsed to extract:
  - Source/Destination IP
  - Protocol (TCP/UDP)
  - Source/Destination Port
- All traffic is logged to logs/traffic_log.txt.
- Blocked packets are marked as [BLOCKED] in logs.
- Use the GUI to add IPs or ports to the blocklist in real time.

---
