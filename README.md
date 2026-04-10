<div align="center">

# 🛡️ NexusGuard

### Advanced Intrusion Prevention & Detection System

<img src="nexusguard/web/static/img/logo.svg" alt="NexusGuard Logo" width="200"/>

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

**Beautiful • Intelligent • Real-time • Beginner-Friendly**

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Screenshots](#screenshots)

</div>

---

## ✨ Features

### 🎨 **Stunning Interfaces**
- **Interactive TUI** with gradient banners, live updates, and autocomplete
- **Modern Web GUI** with real-time dashboards and beautiful visualizations
- Color-coded threat levels and responsive design

### 🧠 **Intelligent Detection**
- Machine Learning-based anomaly detection
- Signature-based threat identification
- Behavioral analysis of network traffic
- Zero-day attack detection

### 🚀 **Real-time Protection**
- Live packet inspection
- Automatic threat blocking
- Geo-IP tracking and blocking
- Port scan detection
- DDoS mitigation

### 🔧 **Beginner-Friendly**
- Command auto-suggestion and hints
- Interactive tutorials
- Pre-configured security rules
- One-click threat responses

---

## 🚀 Installation

### Prerequisites
```bash
# Debian/Ubuntu
sudo apt-get update
sudo apt-get install python3-pip libpcap-dev

# macOS
brew install libpcap

# Fedora/RHEL
sudo dnf install python3-pip libpcap-devel
```

### Quick Install
```bash
# Clone the repository
git clone https://github.com/yourusername/nexusguard.git
cd nexusguard

# Install dependencies
pip install -r requirements.txt

# Install NexusGuard
sudo python setup.py install
```

---

## 💻 Usage

### TUI Mode (Terminal User Interface)
```bash
sudo nexusguard tui
```

### Web GUI Mode
```bash
sudo nexusguard web --port 8080
# Open browser to http://localhost:8080
```

### CLI Mode
```bash
# Start monitoring
sudo nexusguard start --interface eth0

# View live threats
sudo nexusguard threats --live

# Block an IP
sudo nexusguard block 192.168.1.100

# View statistics
sudo nexusguard stats
```

---

## 📸 Screenshots

*Beautiful gradient TUI with live threat monitoring*

*Modern web dashboard with real-time analytics*

---

## 🎯 Quick Start Guide

1. **Launch TUI**: `sudo nexusguard tui`
2. **Select Network Interface**: Use arrow keys and press Enter
3. **Enable Protection**: Toggle protection with `P`
4. **View Threats**: Navigate to Threats tab with `→`
5. **Block Threats**: Select threat and press `B`

---

## 🛠️ Configuration

Edit `config/settings.yaml`:
```yaml
network:
  interface: auto  # or eth0, wlan0, etc.
  promiscuous_mode: true

detection:
  ml_enabled: true
  signature_check: true
  threshold: 0.75

response:
  auto_block: true
  notify: true
  log_level: INFO
```

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

This tool is for educational and authorized testing purposes only. Always ensure you have permission before monitoring network traffic.

---

<div align="center">

**Made with ❤️ by the Security Community**

⭐ Star us on GitHub if you find this useful!

</div>
