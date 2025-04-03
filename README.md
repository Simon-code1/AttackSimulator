# AttackSimulator

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg)

Professional penetration testing toolkit for authorized security assessments with advanced reconnaissance and reporting features.

## 📌 Table of Contents
- [Features](#-features)
- [Installation](#-installation)
- [Usage](#-usage)
- [Attack Modules](#-attack-modules)
- [Reporting](#-reporting)
- [Contributing](#-contributing)

## 🧰 Features

### Core Components
- **Network Attacks**
  - SYN Flood
  - UDP Flood
  - ICMP Flood
  - Slowloris (HTTP DoS)
  - ARP Spoofing (MITM)

- **Web Application Testing**
  - SQL Injection detection
  - XSS scanning (Basic)

- **Reconnaissance**
  - Port scanning with Nmap
  - Subdomain enumeration
  - Automated PDF/HTML reporting

## 📥 Installation

### Prerequisites
- Python 3.8+
- Root/Admin privileges (for network attacks)

### Clone repository
```bash
git clone -b master https://github.com/Simon-code1/AttackSimulator.git
cd AttackSimulator
```

# Install dependencies
```bash
pip install -r requirements.txt
```

## 🕹️ Usage

### Interactive Mode

python3 Attack_Sim.py
Command-Line Mode
```bash
# SYN Flood attack
python3 Attack_Sim.py --syn-flood 192.168.1.100 -p 80 -c 1000

# Port scan with PDF report
python3 Attack_Sim.py --port-scan 192.168.1.100 --format pdf

# SQL Injection test
python3 Attack_Sim.py --sqli http://example.com/login.php
```
## ⚔️ Attack Modules
### Network Layer Attacks

| Command                       | Description                     |
|-------------------------------|---------------------------------|
| `--syn-flood <IP> -p <PORT>`  | TCP SYN flood attack            |
| `--udp-flood <IP> -p <PORT>`  | UDP packet flood                |
| `--slowloris <IP> -p <PORT>`  | HTTP Slowloris attack           |

## 📊 Reporting
Generate comprehensive reports:

```bash
# PDF Report
python3 Attack_Sim.py --generate-report pdf

# HTML Report
python3 Attack_Sim.py --generate-report html
```
## Report contents include:

#### Vulnerability findings

#### Attack statistics

#### Remediation suggestions

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/NewFeature`)
3. Commit your changes (`git commit -m 'Add some feature'`)
4. Push to the branch (`git push origin feature/NewFeature`)
5. Open a Pull Request
