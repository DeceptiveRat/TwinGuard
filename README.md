# 🛡️ TwinGuard: Your Personal Wi-Fi Bodyguard

> **"Cafes, Airports, Schools... Is the Wi-Fi you are connected to right now actually safe?"**
>
> **TwinGuard** is a user-friendly, Windows-based security solution designed to detect **Evil Twin attacks** (fake Wi-Fi hotspots) and protect your personal data in real-time.

---

## 1. 💡 Motivation

**"Hacking tools are everywhere, but why are defense tools so difficult to use?"**

The **Evil Twin attack**—where a hacker creates a fake Wi-Fi access point to intercept data—is a well-known threat. However, detecting it has traditionally remained in the realm of experts. Average users cannot be expected to open a terminal and analyze network packets manually.

We aimed to bridge this gap by taking a **'User-Friendly'** approach. Our goal was to create a practical application that allows anyone, regardless of technical background, to verify the safety of their surrounding Wi-Fi networks with a single click.

---

## 2. 🏗️ Workflow & Architecture

TwinGuard visualizes invisible network threats through a **3-stage pipeline**. It captures packets, analyzes them for anomalies, and alerts the user.

```mermaid
graph TD
    User((User/Client)) -->|1. Start Scan| UI[Integrated Dashboard]
    
    subgraph "TwinGuard Core System"
        UI -->|2. Execute Process| Collector[Data Collector]
        UI -->|2. Execute Process| Analyzer[Analyzer & Detector]
        
        Collector -- "Real-time Packets & RSSI" --> Analyzer
        
        subgraph "Detection Algorithm"
            Analyzer --> Check1{Is signal suspiciously strong?}
            Analyzer --> Check2{Has the BSSID changed?}
            Analyzer --> Check3{Is there network latency (RTT)?}
        end
    end
    
    Analyzer -- "4. Result (Normal/Suspicious/High Risk)" --> UI
    UI -->|5. Display Alert| User
🔍 Anomaly Detection Logic
We analyze physical and communication characteristics that hackers cannot easily hide, rather than just looking at the SSID (Network Name).

📶 Physical Signal (RSSI): If the signal strength is abnormally high compared to the baseline, it is suspicious (Hackers often boost signals to lure victims).

🆔 Device Address (BSSID): If the Wi-Fi name is the same but the MAC Address (BSSID) has changed, it is a 100% indication of a different device.

🐢 Communication Latency (RTT): Since internet traffic is relayed through the hacker's device, inevitable speed delays (Latency) occur. We detect these micro-delays in TCP packets.

3. ⚙️ Getting Started
This program is designed for Windows 10/11 environments.

Prerequisites
The following tools are required for network packet analysis:

Python 3.x (⚠️ Ensure Add to PATH is checked during installation).

Wireshark

Crucial: You must select Install TShark and Install Npcap during the installation process.

Python Libraries Run the following command in your terminal:

Bash

pip install pyshark
Installation & Execution
Clone or download this repository.

Open Command Prompt (CMD), PowerShell, or VS Code as Administrator (Required for network access).

Run the main UI script:

Bash

python ui_windows.py
4. 🧪 Results & Current Status
Successful PoC (Proof of Concept): We constructed a fake Wi-Fi environment using an ESP32 hacking module. TwinGuard successfully distinguished between the legitimate Wi-Fi and the fake one, displaying appropriate warning alerts.

Optimization: While the real-time packet analysis structure is complete, resource optimization for low-spec PCs is currently in progress.

Limitations: The current version is specialized for Evil Twin attacks. Response capabilities for more advanced attacks, such as ARP Spoofing, require further research.

5. 🚀 Future Roadmap
We aim to evolve from a simple detection tool into an integrated security platform.

🧠 AI-Based Detection: Moving beyond rule-based detection, we plan to implement Machine Learning models that learn the user's normal network patterns to detect subtle anomalies.

☁️ Threat Intelligence Cloud: A feature for users to share detected fake Wi-Fi data to a central server, pre-warning other users that "This location is a hacking danger zone."

📱 Mobile App Expansion: Developing background apps for smartphones that automatically diagnose safety when connecting to public Wi-Fi.

🛡️ Automated Defense System: A feature that automatically disconnects Wi-Fi without user intervention when a 'High Risk' threat is detected, preventing data leakage at the source
