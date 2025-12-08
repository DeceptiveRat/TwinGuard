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
