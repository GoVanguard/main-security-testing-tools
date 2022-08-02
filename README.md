## Contents

* [Penetration Testing OS Distributions](#penetration-testing-os-distributions)
* [Multi-paradigm Frameworks](#multi-paradigm-frameworks)
* [Network Vulnerability scanners](#network-vulnerability-scanners)
  * [Static Analyzers](#static-analyzers)
  * [Web Vulnerability Scanners](#web-vulnerability-scanners)
* [Network Tools](#network-tools)
  * [Network Reconnaissance Tools](#network-reconnaissance-tools)
  * [Protocol Analyzers and Sniffers](#protocol-analyzers-and-sniffers)
  * [Proxies and MITM Tools](#proxies-and-mitm-tools)
* [Wireless Network Tools](#wireless-network-tools)
* [Transport Layer Security Tools](#transport-layer-security-tools)
* [Web Exploitation](#web-exploitation)
* [Hex Editors](#hex-editors)
* [Hash Cracking Tools](#hash-cracking-tools)
* [Windows Utilities](#windows-utilities)
* [GNU/Linux Utilities](#gnulinux-utilities)
* [macOS Utilities](#macos-utilities)
* [Social Engineering Tools](#social-engineering-tools)
* [OSINT Tools](#osint-tools)
* [Anonymity Tools](#anonymity-tools)
* [Reverse Engineering Tools](#reverse-engineering-tools)
* [Side-channel Tools](#side-channel-tools)

## Tools

### Penetration Testing OS Distributions

* [Parrot Security OS](https://www.parrotsec.org/) - Distribution similar to Kali using the same repositories, but with additional features such as Tor and I2P integration.
* [Kali](https://www.kali.org/) - GNU/Linux distribution designed for digital forensics and penetration testing.

### Multi-paradigm Frameworks

* [Metasploit](https://www.metasploit.com/) - Software for offensive security teams to help verify vulnerabilities and manage security assessments.
* [Pentest-tools](https://pentest-tools.com/) - Web based platform for several open source reconnaissance and exploitation tools. 

### Network Vulnerability Scanners

* [OpenVAS](http://www.openvas.org/) - Open source implementation of the popular Nessus vulnerability assessment system.
* [Nexpose](https://www.rapid7.com/products/nexpose/) - Commercial vulnerability and risk management assessment engine that integrates with Metasploit, sold by Rapid7.
* [Nessus](https://www.tenable.com/lp/campaigns/19/try-nessus/) - Commercial vulnerability assessment tool, sold by Tenable. 

### Static Analyzers

* [OWASP Dependency Check](https://www.owasp.org/index.php/OWASP_Dependency_Check) - Open source static analysis tool that enumerates dependencies used by Java and .NET software code (with experimental support for Python, Ruby, Node.js, C, and C++) and lists security vulnerabilities associated with the dependencies. 
* [VisualCodeGrepper](https://github.com/nccgroup/VCG) - Open source static code analysis tool with support for Java, C, C++, C#, PL/SQL, VB, and PHP. VisualCodeGrepper also conforms to OWASP best practices.
* [Brakeman](https://github.com/presidentbeef/brakeman) - Static analysis security vulnerability scanner for Ruby on Rails applications.
* [sobelow](https://github.com/nccgroup/sobelow) - Security-focused static analysis for the Phoenix Framework.
* [Progpilot](https://github.com/designsecurity/progpilot) - Static security analysis tool for PHP code.
* [ShellCheck](https://github.com/koalaman/shellcheck) - Static code analysis tool for shell script.
* [Codebeat (open source)](https://codebeat.co/open-source/) - Open source implementation of commercial static code analysis tool with GitHub integration.
* [truffleHog](https://github.com/dxa4481/truffleHog) - Git repo scanner.
* [SecretScanner](https://github.com/GoVanguard/SecretScanner) - Scans application code for hard coded secrets.

### Web Vulnerability Scanners

* [Netsparker Web Application Security Scanner](https://www.netsparker.com/) - Commercial web application security scanner to automatically find many different types of security flaws.
* [OWASP Zed Attack Proxy (ZAP)](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project) - Feature-rich, scriptable HTTP intercepting proxy and fuzzer for penetration testing web applications.
* [Nikto](https://cirt.net/nikto2) - Noisy but fast black box web server and web application vulnerability scanner.
* [WPScan](https://wpscan.org/) - Black box WordPress vulnerability scanner.
* [Log4jCenter](https://github.com/puzzlepeaches/Log4jCenter) - VMWare vCenter Log4Shell exploitation tool.

### Network Tools

* [Spyse](https://spyse.com) - Web research services that scans the entire internet using OSINT.  to simplify the investigation of infrastructure and attack surfaces.
 - [Spyse.py](https://github.com/zeropwn/spyse.py) - Python wrapper for interacting with Spyse API 
* [pig](https://github.com/rafael-santiago/pig) - GNU/Linux packet crafting tool.
* [Network-Tools.com](http://network-tools.com/) - Website offering an interface to numerous basic network utilities like `ping`, `traceroute`, `whois`, and more.
* [Intercepter-NG](http://sniff.su/) - Multifunctional network toolkit.
* [Legion](https://github.com/GoVanguard/legion) - Graphical interface offering scriptable, configurable access to existing network infrastructure scanning and enumeration tools.
* [dsniff](https://www.monkey.org/~dugsong/dsniff/) - Collection of tools for network auditing and pentesting.
* [Printer Exploitation Toolkit (PRET)](https://github.com/RUB-NDS/PRET) - Tool for printer security testing capable of IP and USB connectivity, fuzzing, and exploitation of PostScript, PJL, and PCL printer language features.
* [impacket](https://github.com/CoreSecurity/impacket) - Collection of Python classes for working with network protocols.
* [THC Hydra](https://github.com/vanhauser-thc/thc-hydra) - Online password cracking tool with built-in support for many network protocols, including HTTP, SMB, FTP, telnet, ICQ, MySQL, LDAP, IMAP, VNC, and more.
* [Ncat](https://nmap.org/ncat/) - TCP/IP command line utility supporting multiple protocols, included with Nmap.
* [Network Detective] ( https://www.rapidfiretools.com/products/network-detective/) - White Box tool used for network analysis, enumeration of users, permission, shares, and assets, sold by Rapidfiretools. 

### Cloud Vulnerability Analysis Tools
* [ScoutSuite](https://github.com/nccgroup/ScoutSuite) - Open source multi-cloud security-auditing tool, which enables security posture assessment of cloud environments.
* [Prowler](https://github.com/prowler-cloud/prowler) - Open Source security tool to perform AWS security best practices assessments, audits, incident response, continuous monitoring, hardening and forensics readiness.
* [PrincipleMapper](https://github.com/nccgroup/PMapper) - Open source AWS IAM vulnerability analysis tool.
* [Pacu](https://github.com/RhinoSecurityLabs/pacu) - AWS exploitation framework.
* [CloudSploit](https://github.com/aquasecurity/cloudsploit) - CloudSploit by Aqua is an open-source project designed to allow detection of security risks in cloud infrastructure accounts, including: Amazon Web Services (AWS), Microsoft Azure, Google Cloud Platform (GCP), Oracle Cloud Infrastructure (OCI), and GitHub.

### Network Reconnaissance Tools

* [Shodan](https://shodan.io/) - Database containing information on all accessible domains on the internet obtained from passive scanning.
  - [pyShodan](https://github.com/GoVanguard/pyShodan) - Python 3 script for interacting with Shodan API (requires valid API key).
* [zmap](https://zmap.io/) - Open source network scanner that enables researchers to easily perform Internet-wide network studies.
* [Amass](https://github.com/OWASP/Amass) - network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques, maintained by OWASP. 
* [nmap](https://nmap.org/) - Free security scanner for network exploration & security audits.
* [Netdiscover](https://github.com/alexxy/netdiscover) - Simple and quick network scanning tool.
* [Mass Scan](https://github.com/robertdavidgraham/masscan) - TCP port scanner, spews SYN packets asynchronously, scanning entire Internet in under 5 minutes.
* [smbmap](https://github.com/ShawnDEvans/smbmap) - Handy SMB enumeration tool.
* [LdapMiner](https://sourceforge.net/projects/ldapminer/) - Multiplatform LDAP enumeration utility.
* [ldapsearch](https://linux.die.net/man/1/ldapsearch) - Linux command line utility for querying LDAP servers.
* [ACLight](https://github.com/cyberark/ACLight) - Script for advanced discovery of sensitive Privileged Accounts - includes Shadow Admins.
* [Pentest-Tools](https://pentest-tools.com/home) - Online suite of various different pentest related tools.
* [BuiltWith](https://builtwith.com/) - Technology lookup tool for websites.

### Protocol Analyzers and Sniffers

* [tcpdump/libpcap](http://www.tcpdump.org/) - Common packet analyzer that runs under the command line.
* [Wireshark](https://www.wireshark.org/) - Widely-used graphical, cross-platform network protocol analyzer.
* [Yersinia](https://tools.kali.org/vulnerability-analysis/yersinia) - Packet and protocol analyzer with MITM capability.
* [netsniff-ng](https://github.com/netsniff-ng/netsniff-ng) - Swiss army knife for for network sniffing.

### Proxies and MITM Tools

* [Responder](https://github.com/SpiderLabs/Responder) - Open source NBT-NS, LLMNR, and MDNS poisoner.
* [Responder-Windows](https://github.com/lgandx/Responder-Windows) - Windows version of the above NBT-NS/LLMNR/MDNS poisoner.
* [dnschef](https://github.com/iphelix/dnschef) - Highly configurable DNS proxy for pentesters.
* [mitmproxy](https://github.com/mitmproxy/mitmproxy) - Interactive TLS-capable intercepting HTTP proxy for penetration testers and software developers.
* [SSH MITM](https://github.com/jtesta/ssh-mitm) - Intercept SSH connections with a proxy; all plaintext passwords and sessions are logged to disk.
* [evilgrade](https://github.com/infobyte/evilgrade) - Modular framework to take advantage of poor upgrade implementations by injecting fake updates.
* [Ettercap](http://www.ettercap-project.org) - Comprehensive, mature suite for machine-in-the-middle attacks.
* [BetterCAP](https://www.bettercap.org/) - Modular, portable and easily extensible MITM framework.

### Wireless Network Tools

* [Aircrack-ng](http://www.aircrack-ng.org/) - Set of tools for auditing wireless networks.
* [BetterCAP](https://www.bettercap.org/) - Wifi, Bluetooth LE, and HID reconnaissance and MITM attack framework, written in Go.
* [Wifite](https://github.com/derv82/wifite) - Automated wireless attack tool.
* [wifi-pickle](https://github.com/GoVanguard/wifi-pickle) - Fake access point attacks.

### Transport Layer Security Tools

* [SSLyze](https://github.com/nabla-c0d3/sslyze) - Fast and comprehensive TLS/SSL configuration analyzer to help identify security mis-configurations.
* [crackpkcs12](https://github.com/crackpkcs12/crackpkcs12) - Multithreaded program to crack PKCS#12 files (`.p12` and `.pfx` extensions), such as TLS/SSL certificates.
* [SSLScan](https://github.com/rbsec/sslscan) - Quick command line tool for checking TLS/SSL configuration.

### Web Exploitation

* [WPSploit](https://github.com/espreto/wpsploit) - Exploit WordPress-powered websites with Metasploit.
* [SQLmap](http://sqlmap.org/) - Automated SQL injection and database takeover tool.
* [tplmap](https://github.com/epinna/tplmap) - Automatic server-side template injection and Web server takeover tool.
* [wafw00f](https://github.com/EnableSecurity/wafw00f) - Identifies and fingerprints Web Application Firewall (WAF) products.
* [IIS-Shortname-Scanner](https://github.com/irsdl/IIS-ShortName-Scanner) - Command line tool to exploit the Windows IIS tilde information disclosure vulnerability.

### Hex Editors

* [HexEdit.js](https://hexed.it) - Browser-based hex editing.
* [Hexinator](https://hexinator.com/) - World's finest (proprietary, commercial) Hex Editor.
* [Frhed](http://frhed.sourceforge.net/) - Binary file editor for Windows.
* [Cheat Engine](https://www.cheatengine.org/) - Memory debugger and hex editor for running applications.

### Hash Cracking Tools

* [Hashcat](http://hashcat.net/hashcat/) - Fast hash cracking utility with support for most known hashes as well as OpenCL and CUDA acceleration.
* [John the Ripper](http://www.openwall.com/john/) - Fast password cracker.
* [CeWL](https://digi.ninja/projects/cewl.php) - Generates custom wordlists by spidering a target's website and collecting unique words.
* [JWT Cracker](https://github.com/lmammino/jwt-cracker) - Simple HS256 JWT token brute force cracker.
* [Rar Crack](http://rarcrack.sourceforge.net) - RAR bruteforce cracker.
* [Mentalist](https://github.com/sc0tfree/mentalist) - Graphical tool for custom wordlist generation 

### Windows Utilities

* [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) - PowerShell Post-Exploitation Framework.
* [Headstart](https://github.com/GoVanguard/script-win-privescalate-headstart) - Lazy man's Windows privilege escalation tool utilizing PowerSploit.
* [mimikatz](http://blog.gentilkiwi.com/mimikatz) - Credentials extraction tool for Windows operating system.
* [Bloodhound](https://github.com/adaptivethreat/Bloodhound/wiki) - Graphical Active Directory trust relationship explorer.
* [Fibratus](https://github.com/rabbitstack/fibratus) - Tool for exploration and tracing of the Windows kernel.
* [redsnarf](https://github.com/nccgroup/redsnarf) - Post-exploitation tool for retrieving password hashes and credentials from Windows workstations, servers, and domain controllers.
* [Magic Unicorn](https://github.com/trustedsec/unicorn) - Shellcode generator for numerous attack vectors, including Microsoft Office macros, PowerShell, HTML applications (HTA), or `certutil` (using fake certificates).
* [WinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS) - A series of scripts for Windows Priviledge escalation. 
* [ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump) - Active directory domain information dumper

### GNU/Linux Utilities

* [Linux Exploit Suggester](https://github.com/PenturaLabs/Linux_Exploit_Suggester) - Heuristic reporting on potentially viable exploits for a given GNU/Linux system.
* [Linus](https://cisofy.com/lynis/) - Security auditing tool for Linux and macOS.
* [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) - A series of scripts for Linux priviledge escalation. 
* [LinEnum](https://github.com/rebootuser/LinEnum) - Linex enumeration tool for priviledge escalation. 

### macOS Utilities

* [Bella](https://github.com/Trietptm-on-Security/Bella) - Pure Python post-exploitation data mining and remote administration tool for macOS.
* [Linus](https://cisofy.com/lynis/) - Security auditing tool for Linux and macOS.

### Social Engineering Tools

* [GoPhish](https://github.com/gophish/gophish) - Open source phishing toolkit
* [Linkedin2username](https://github.com/initstring/linkedin2username) - OSINT Tool: Generate username lists from companies on LinkedIn.
* [Modlishka](https://github.com/x7x3x2x/Modlishka-Phishing-NG) - Flexible reverse proxy tool for phishing engagements. 

### OSINT Tools

* [Shodan](https://www.shodan.io/) - World's first search engine for Internet-connected devices.
  - - [pyShodan](https://github.com/GoVanguard/pyShodan) - Python 3 script for interacting with Shodan API (requires valid API key).
* [Maltego](http://www.paterva.com/web7/) - Proprietary software for open source intelligence and forensics, from Paterva.
* [Mxtoolbox](https://mxtoolbox.com/) - Email domain and DNS lookup.
* [recon-ng](https://bitbucket.org/LaNMaSteR53/recon-ng) - Full-featured Web Reconnaissance framework written in Python..
* [Virus Total](https://www.virustotal.com/) - Free service that analyzes suspicious files and URLs and facilitates the quick detection of viruses, worms, trojans, and all kinds of malware.
* [PacketTotal](https://packettotal.com/) - Simple, free, high-quality packet capture file analysis facilitating the quick detection of network-borne malware (using Bro and Suricata IDS signatures under the hood).
* [Amass](https://github.com/OWASP/Amass) - Subdomain enumeration via scraping, web archives, brute forcing, permutations, reverse DNS sweeping, TLS certificates, passive DNS data sources, etc.
* [TruePeopleSearch](https://www.truepeoplesearch.com/) - OSINT tool for individual research. 
* [DNSTwist](https://dnstwist.it/) - Open source phishing domain scanner to identify potentially malicious typosquatted domains. 

### Reverse Engineering Tools
* [VirusTotal](https://www.virustotal.com/#/home/upload) - Online malware scanner.
* [Hybrid Analysis](https://www.hybrid-analysis.com/) - Online malware scanner.
* [WDK/WinDbg](https://msdn.microsoft.com/en-us/windows/hardware/hh852365.aspx) - Windows Driver Kit and WinDbg.
* [Radare2](http://rada.re/r/index.html) - Open source, crossplatform reverse engineering framework.
* [plasma](https://github.com/joelpx/plasma) - Interactive disassembler for x86/ARM/MIPS. Generates indented pseudo-code with colored syntax code.
* [peda](https://github.com/longld/peda) - Python Exploit Development Assistance for GDB.
* [dnSpy](https://github.com/0xd4d/dnSpy) - Tool to reverse engineer .NET assemblies.
* [binwalk](https://github.com/devttys0/binwalk) - Fast, easy to use tool for analyzing, reverse engineering, and extracting firmware images.
* [rVMI](https://github.com/fireeye/rVMI) - Debugger on steroids; inspect userspace processes, kernel drivers, and preboot environments in a single tool.

# License

[![CC-BY](https://mirrors.creativecommons.org/presskit/buttons/88x31/svg/by.svg)](https://creativecommons.org/licenses/by/4.0/)

This work is licensed under a [Creative Commons Attribution 4.0 International License](https://creativecommons.org/licenses/by/4.0/).
