# 🚗 AutoShield-CAN IDS
### Automotive CAN Bus Intrusion Detection System

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)
![Standard](https://img.shields.io/badge/Standard-ISO%2021434-1D9E75?style=flat)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat)

A Python-based automotive **Intrusion Detection and Prevention System (IDPS)** prototype that simulates a vehicle's CAN bus network, injects real-world cyber attacks, and detects them in real time using a two-layer detection engine — aligned with **ISO/SAE 21434** automotive cybersecurity requirements.

---

## 📸 Demo

```
🚗  CAN Bus Intrusion Detection System
Uptime: 14s  │  Frames: 4,894  │  Alerts: 1,733

ECU Traffic Monitor          Live Alert Feed
──────────────────────       ─────────────────────────────────────────────────
0x0C0  Engine ECU   ● ACTIVE  18:21:38  CRITICAL  FLOODING  0x000  Bus dominated (41%)
0x1A0  Brake ECU    ● ACTIVE  18:21:38  HIGH      FUZZING   0x2B0  byte[0]=255 Z=355.7
0x2B0  Steering ECU ● ACTIVE  18:21:38  HIGH      SPOOFING  0x0C0  Rate 284/s (×2.8)
0x1F0  Transmission ● ACTIVE  18:21:38  HIGH      REPLAY    0x4B0  Identical frame ×3
0x4B0  Body Control ● ACTIVE  18:21:38  HIGH      FUZZING   0x1A0  Z-score anomaly

Detection Summary
  FLOODING   196  ████████████
  SPOOFING     9  █████
  FUZZING   3374  ████████████████████
  REPLAY     221  ██████████
  Bus rate: 319 fps   Injected: 15.2%
```

---

## 🎯 What This Project Demonstrates

| Skill | How it's demonstrated |
|---|---|
| **CAN Bus protocol** | ISO 11898-compliant frame modelling, signal encoding, DLC, arbitration |
| **Automotive ECU simulation** | 5 ECUs with real cycle times, signal ranges, byte-level encoding |
| **Threat modelling** | ISO 21434 TARA with CVSS scoring across 4 threat scenarios |
| **Attack simulation** | Replay, Fuzzing, Spoofing, Flooding — each targeting a real CAN weakness |
| **Intrusion detection** | Rule-based (5 rules) + Statistical (Z-score) two-layer IDS |
| **AUTOSAR awareness** | Architecture mirrors AUTOSAR IdsM component separation |

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    ECU Layer                            │
│  [Engine 0x0C0] [Brake 0x1A0] [Steering 0x2B0]        │
│  [Transmission 0x1F0]  [Body Control 0x4B0]            │
└──────────────────────┬──────────────────────────────────┘
                       │ CAN frames (11-bit ID, 0–8 bytes)
┌──────────────────────▼──────────────────────────────────┐
│           Virtual CAN Bus (500 kbps)                    │
│        Thread-safe queue · Broadcast medium             │
└────────┬─────────────────────────┬───────────────────────┘
         │                         │
┌────────▼────────┐    ┌───────────▼──────────────────────┐
│  Attack Engine  │    │        IDS Engine                │
│  ─────────────  │    │  ──────────────────────────────  │
│  Replay         │    │  Layer 1: Rule-based detector    │
│  Fuzzing        │    │    R1 Frequency  R2 Duplicate    │
│  Spoofing       │    │    R3 Payload    R4 Unknown ID   │
│  Flooding       │    │    R5 Bus domination             │
└─────────────────┘    │  Layer 2: Statistical (Z-score)  │
                       │    Training → Baseline → Detect  │
                       └───────────────┬──────────────────┘
                                       │ Alerts
                       ┌───────────────▼──────────────────┐
                       │      Live Terminal Dashboard      │
                       │   Rich · Real-time · Color-coded │
                       └──────────────────────────────────┘
```

---

## ⚔️ Attack Scenarios Simulated

### 1. Replay Attack
**CAN weakness exploited:** No sequence numbers, no timestamps
**Scenario:** Capture a door-unlock frame (0x4B0), replay it remotely to unlock the vehicle
**Detection:** Rule R2 — identical frame fingerprint seen ≥ 3× in sliding window
**CVSS:** 7.1 (High)

### 2. Fuzzing Attack
**CAN weakness exploited:** No payload validation at protocol level
**Scenario:** Inject random/boundary-value payloads into Brake (0x1A0) and Steering (0x2B0) ECUs
**Detection:** Rule R3 (range check) + Statistical Z-score > 3.5 on payload bytes
**CVSS:** 9.1 (Critical)

### 3. ID Spoofing Attack
**CAN weakness exploited:** No sender authentication — any node can use any ID
**Scenario:** Impersonate Engine ECU (0x0C0), report RPM=0 (fake stall) at speed
**Detection:** Rule R1 (rate doubles) + timing anomaly detection
**CVSS:** 9.3 (Critical)
**Real incident:** 2015 Jeep Cherokee remote hack used this exact technique

### 4. Bus Flooding / DoS
**CAN weakness exploited:** Priority-based arbitration — ID 0x000 wins every contest
**Scenario:** Saturate bus with ID 0x000 frames, starving ABS and airbag messages
**Detection:** Rule R5 (bus domination >40%) + Rule R1 (rate threshold)
**CVSS:** 8.6 (High)

---

## 🛡️ IDS Detection Architecture

### Layer 1 — Rule-Based Detector
Deterministic rules with zero latency. 100% recall on known attack patterns.

| Rule | Logic | Attack Detected |
|---|---|---|
| R1 — Frequency | Rate > 2.5× baseline for any CAN ID | Flooding, Spoofing |
| R2 — Duplicate | Identical frame seen ≥ 3× in window | Replay |
| R3 — Payload Range | Signal value outside physical range | Fuzzing |
| R4 — Unknown ID | CAN ID not in known ECU whitelist | Rogue node |
| R5 — Bus Domination | Single ID > 40% of all traffic | Flooding |

### Layer 2 — Statistical Anomaly Detector
Learns normal behaviour during a 5-second training phase, then uses Z-score analysis to detect deviations.

```
Z = |observed - mean| / stddev

Z > 4.0  → Timing anomaly    (flooding, rate attack)
Z > 3.5  → Payload anomaly   (fuzzing, spoofing)
```

---

## 📁 Project Structure

```
can_ids_project/
├── run_dashboard.py          ← MAIN DEMO — run this
├── run_simulator.py          ← Test: ECU simulator only
├── run_attacks.py            ← Test: Attack engine only
├── run_ids.py                ← Test: IDS engine only
│
├── simulator/
│   ├── can_frame.py          ← ISO 11898 CAN frame dataclass
│   ├── ecu_nodes.py          ← 5 ECU implementations
│   └── virtual_can_bus.py    ← Shared bus medium (threaded)
│
├── attacker/
│   └── attack_engine.py      ← 4 attack classes + orchestrator
│
├── detector/
│   └── ids_detector.py       ← Rule-based + Statistical IDS
│
├── dashboard/
│   └── live_dashboard.py     ← Rich terminal UI
│
└── docs/
    └── AutoShield_CAN_IDS_TARA.docx  ← ISO 21434 TARA document
```

---

## 🚀 Quick Start

### Prerequisites
```bash
Python 3.10+
```

### Installation
```bash
git clone https://github.com/Janani2436/CAN-Bus-Intrusion-Detection-System.git
cd CAN-Bus-Intrusion-Detection-System
pip install python-can rich numpy
```

### Run the full demo
```bash
python run_dashboard.py
```

**What happens:**
1. Vehicle CAN network starts (5 ECUs, 500 kbps)
2. IDS trains on normal traffic for 5 seconds
3. All 4 attacks run automatically
4. Live dashboard shows detections in real time
5. Final detection report printed

### Run individual modules
```bash
python run_simulator.py   # ECU simulator only
python run_attacks.py     # Attack engine demo
python run_ids.py         # IDS without dashboard
```

---

## 📊 Sample Results

```
Frames analyzed : 6,350
Total alerts    : 3,800
Trained ECU IDs : 6
Uptime          : 18.1s

Alert breakdown:
  REPLAY      221
  FLOODING    196
  FUZZING    3374
  SPOOFING      9

Attack frames injected : 649  (15.2% of total traffic)
Normal frames          : 5701 (84.8% of total traffic)
```

---

## 📋 ISO 21434 Alignment

This project was developed following ISO/SAE 21434:2021 methodology:

- **TARA completed** before implementation (see `/docs`)
- **Asset identification** — 6 assets across 5 ECU nodes
- **Threat enumeration** — 4 threats from UNECE WP.29 catalogue
- **Risk scoring** — CVSS v3.1 for each threat (range: 7.1–9.3)
- **Detection controls** mapped to each identified threat
- **Mitigation recommendations** per ISO 21434 §15 and AUTOSAR SecOC

---

## 🔧 Tech Stack

| Component | Technology | Purpose |
|---|---|---|
| Language | Python 3.10+ | Core implementation |
| CAN interface | python-can | Virtual bus abstraction |
| Dashboard | Rich | Live terminal UI |
| Statistics | NumPy / statistics | Z-score anomaly detection |
| Threading | threading | Concurrent ECU simulation |
| Documentation | ISO 21434 TARA | Threat modelling |

---

## 🔮 Future Enhancements

- [ ] Machine learning detection (LSTM autoencoder for sequence anomalies)
- [ ] CAN-FD support (up to 64-byte payload, 8 Mbps)
- [ ] Real hardware integration (Peak PCAN, Kvaser)
- [ ] OBD-II attack surface simulation
- [ ] UDS (Unified Diagnostic Services) protocol layer
- [ ] SecOC (Secure Onboard Communication) demonstration

---

## 📚 References

- ISO/SAE 21434:2021 — Road Vehicles Cybersecurity Engineering
- UNECE WP.29 R155 — Cybersecurity Management System
- ISO 11898 — CAN Bus Standard
- AUTOSAR IdsM — Intrusion Detection System Manager
- Miller & Valasek (2015) — Remote Exploitation of an Unaltered Passenger Vehicle

---

## 👤 Author

**Janani**
Automotive Cybersecurity | Embedded Systems | Python

---

