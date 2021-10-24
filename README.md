# Red Teaming/Adversary Simulation Toolkit

A collection of open source and commercial penetration testing tools. 
This repository will help you during your red team engagement.

Use toolkit.py script to maintain your collection.
_________________________________________________________________________________________________________

## Contents
* [Active Intelligence Gathering](#active-intelligence-gathering)
* [Passive Intelligence Gathering](#passive-intelligence-gathering)
* [Weaponization](#weaponization)
* [Delivery](#delivery)
* [Phishing](#phishing)
* [Social Engineering](#social-engineering)
* [Remote Access Tools](#remote-access-tools)
* [Staging](#staging)
* [Man In the Middle](#man-in-the-middle)
* [Establish Foothold](#establish-foothold)
* [Pivoting and Tunneling](#pivoting-and-tunneling)
* [Lateral Movement](#lateral-movement)
* [Local Privileges Escalation](#local-privileges-escalation)
* [Domain Privileges Escalation](#domain-privileges-escalation)
* [Data Exfiltration](#data-exfiltration)
* [Anonymization](#anonymization)
* [Malware Analysis](#malware-analysis)
* [Adversary Simulation](#adversary-simulation)
* [Wireless Networks](#wireless-networks)
* [Embedded & Peripheral Devices Hacking](#embedded-peripheral-devices-hacking)
* [Software For Team Communication](#software-for-team-communication)
* [Log Aggregation](#log-aggregation)
* [Cloud Computing](#cloud-computing)
* [Labs](#labs)
* [Binaries](#binaries)
* [References](#references)
* [Scripts](#scripts)
* [Wordlists](#wordlists)



### Active Intelligence Gathering
* **FinalRecon** All-in-one information gathering tool https://github.com/thewhiteh4t/FinalRecon
* **Vanquish**  Vanquish is Kali Linux based Enumeration Orchestrator. Vanquish leverages the opensource enumeration tools on Kali to perform multiple active information gathering phases.  https://github.com/frizb/Vanquish
* **nullinux** Nullinux is an internal penetration testing tool for Linux that can be used to enumerate OS information, domain information, shares, directories, and users through SMB https://github.com/m8r0wn/nullinux
* **hakrevdns** Small, fast, simple tool for performing reverse DNS lookups en masse. https://github.com/hakluke/hakrevdns
* **AutoRecon** AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of the network https://github.com/Tib3rius/AutoRecon
* **enumapis** Enumerate javascript endpoints on a web-page from the given URL https://github.com/infosec-au/enumapis
* **async-intrusion** Asynchronic python scripts for network reconnaissance https://github.com/cyberhexe/async-intrusion
* **XSStrike** XSStrike is a Cross Site Scripting detection suite equipped with four hand written parsers, an intelligent payload generator, a powerful fuzzing engine and an incredibly fast crawler. https://github.com/s0md3v/XSStrike
* **Osmedeus** Fully automated offensive security framework for reconnaissance and vulnerability scanning https://github.com/j3ssie/Osmedeus
* **cve-2019-1040-scanner** Checks for CVE-2019-1040 vulnerability over SMB. https://github.com/fox-it/cve-2019-1040-scanner
* **bfac** BFAC (Backup File Artifacts Checker): An automated tool that checks for backup artifacts that may disclose the web-application's source code. https://github.com/mazen160/bfac
* **Reconnoitre** A reconnaissance tool made for the OSCP labs to automate information gathering and service enumeration whilst creating a directory structure to store  results, findings and exploits used for each host, recommended commands to execute and directory structures for storing loot and flags. https://github.com/codingo/Reconnoitre
* **nullinux** Nullinux is an internal penetration testing tool for Linux that can be used to enumerate OS information, domain information, shares, directories, and users through SMB. https://github.com/m8r0wn/nullinux
* **sharesearch** ShareSearch tool goes through hosts with SMB, NFS, checking credentials, looking for interesting stuff and greping sensitive data in it. WARNING! Alfa version, a lot of bugs and spaghetti code. https://github.com/nikallass/sharesearch
* **smbclient_cheatsheet** This is a list of useful commands/tricks using smbclient and nmap smb scripts - very useful on a pentesting https://sharingsec.blogspot.com https://github.com/irgoncalves/smbclient_cheatsheet
* **enumapis** Discovery of hidden API's through traversing web applications https://github.com/infosec-au/enumapis
* **jsearch** Jsearch a simple script that grep infos from javascript files https://github.com/incogbyte/jsearch
* **altdns** Altdns is a DNS recon tool that allows for the discovery of subdomains that conform to patterns. Altdns takes in words that could be present in subdomains under a domain (such as test, dev, staging) as well as takes in a list of subdomains that you know of.https://github.com/urbanadventurer/altdns
* **unhidens** Small DNS Recon utility, allows you to obtain some useful info about NS-servers placed behind relays, firewalls, etc. Requires 'dig' utility! https://github.com/german-namestnikov/unhidens
* **knock** is a python tool designed to enumerate subdomains on a target domain through a wordlist. It is designed to scan for **DNS zone transfer** and to try to bypass the **wildcard DNS record** automatically if it is enabled. Now knockpy supports queries to VirusTotal subdomains, you can setting the API_KEY within the config.json file. https://github.com/guelfoweb/knock.git
* **subbrute** SubBrute is a community driven project with the goal of creating the fastest, and most accurate subdomain enumeration tool.  Some of the magic behind SubBrute is that it uses open resolvers as a kind of proxy to circumvent DNS rate-limiting.  This design also provides a layer of anonymity, as SubBrute does not send traffic directly to the target's name servers. https://github.com/infosec-au/subbrute
* **subscraper** SubScraper uses DNS brute force, Google & Bing scraping, and Virus Total to enumerate subdomains. Written in Python3, SubScraper performs HTTP(S) requests and DNS "A" record lookups during the enumeration process to validate discovered subdomains. This provides further information to help prioritize targets and aid in potential next steps. Post-Enumeration, "CNAME" lookups are displayed to identify subdomain takeover opportunities. https://github.com/m8r0wn/subscraper
* **EyeWitness** is designed to take screenshots of websites, provide some server header info, and identify default credentials if possible. https://github.com/ChrisTruncer/EyeWitness
* **AWSBucketDump** is a tool to quickly enumerate AWS S3 buckets to look for loot. https://github.com/jordanpotti/AWSBucketDump
* **AQUATONE** is a set of tools for performing reconnaissance on domain names. https://github.com/michenriksen/aquatone
* **spoofcheck** a program that checks if a domain can be spoofed from. The program checks SPF and DMARC records for weak configurations that allow spoofing. https://github.com/BishopFox/spoofcheck
* **dnsrecon** a tool DNS Enumeration Script. https://github.com/darkoperator/dnsrecon
* **dirsearch** is a simple command line tool designed to brute force directories and files in websites. https://github.com/maurosoria/dirsearch
* **masscan-web-ui** MASSCAN Web UI from Offensive Security https://github.com/offensive-security/masscan-web-ui
* **jwt-hack** JWT cracking tool https://github.com/hahwul/jwt-hack

### Passive Intelligence Gathering
* **awesome-osint** A curated list of amazingly awesome open source intelligence tools and resources. https://github.com/jivoi/awesome-osint
* **Maryam** OWASP Maryam is an Open-source intelligence(OSINT) and Web-based Footprinting optional/modular framework based on the Recon-ng core and written in Python. https://github.com/saeeddhqan/Maryam
* **darkshot** Darkshot is a scraper tool on steroids, to analyze all of the +2 Billions pictures publicly available on Lightshot. It uses OCR to analyze pictures and auto-categorize them thanks to keywords and detection functions. https://github.com/mxrch/darkshot
* **fav-up** Lookups for real IP starting from the favicon icon and using Shodan. https://github.com/pielco11/fav-up
* **lenz** Geolocate all active TCP/ UDP socket conn peer(s) on console map. https://github.com/itzmeanjan/lenz
* **threat-actor-intelligence-server** A simple ReST server to lookup threat actors (by name, synonym or UUID) and returning the corresponding MISP galaxy information about the known threat actors. https://github.com/MISP/threat-actor-intelligence-server
* **Photon** The extensive range of options provided by Photon lets you crawl the web exactly the way you want. https://github.com/s0md3v/Photon
* **git-vuln-finder** Finding potential software vulnerabilities from git commit messages https://github.com/cve-search/git-vuln-finder
* **Ultimate-Dork** Dork Web Crawler https://github.com/jaxBCD/Ultimate-Dork
* **Amass** In-depth Attack Surface Mapping and Asset Discovery https://github.com/OWASP/Amass
* **ODIN** Automated network asset, email, and social media profile discovery and cataloguing https://github.com/chrismaddalena/ODIN
* **Awesome-Asset-Discovery** List of Awesome Open Source Intelligence Resources https://github.com/redhuntlabs/Awesome-Asset-Discovery
* **gitrob** Gitrob is a tool to help find potentially sensitive files pushed to public repositories on Github. Gitrob will clone repositories belonging to a user or organization down to a configurable depth and iterate through the commit history and flag files that match signatures for potentially sensitive files. https://github.com/michenriksen/gitrob
* **security-focus-dataset** A tool to scrape the security-focus, a public exploits database. https://github.com/cyberhexe/security-focus-dataset
* **shodan-eye** Shodan Eye This tool collects all the information about all devices directly connected to the internet using the specified keywords that you enter. https://github.com/BullsEye0/shodan-eye
* **userrecon-py** Find usernames in **187** social networks. https://github.com/decoxviii/userrecon-py
* **sherlock-js** Node-JS enumeration tool to find accounts in social networks by a given username. https://github.com/GitSquared/sherlock-js
* **pymeta** Pymeta uses specially crafted search queries to identify and download the following file types (pdf, xls, xlsx, doc, docx, ppt, pptx) from a given domain using Google and Bing. https://github.com/m8r0wn/pymeta
* **GoogleScraper** Scraping search engines professionally https://github.com/NikolaiT/GoogleScraper
* **cloud_enum** Multi-cloud OSINT tool. Enumerate public resources in AWS, Azure, and Google Cloud. https://github.com/initstring/cloud_enum
* **SiteBroker** A cross-platform python based utility for information gathering and penetration automation! https://github.com/Anon-Exploiter/SiteBroker
* **Social Mapper** OSINT Social Media RMapping Tool, takes a list of names & images (or LinkedIn company name) and performs automated target searching on a huge scale across multiple social media sites. Not restricted by APIs as it instruments a browser using Selenium. Outputs reports to aid in correlating targets across sites. https://github.com/SpiderLabs/social_mapper
* **skiptracer** OSINT scraping framework, utilizes some basic python webscraping (BeautifulSoup) of PII paywall sites to compile passive information on a target on a ramen noodle budget. https://github.com/xillwillx/skiptracer
* **FOCA** (Fingerprinting Organizations with Collected Archives) is a tool used mainly to find metadata and hidden information in the documents its scans. https://github.com/ElevenPaths/FOCA
* **Metagoofil** is a tool for extracting metadata of public documents (pdf,doc,xls,ppt,etc) availables in the target websites. https://github.com/laramies/metagoofil
* **SimplyEmail** Email recon made fast and easy, with a framework to build on. https://github.com/killswitch-GUI/SimplyEmail
* **truffleHog** searches through git repositories for secrets, digging deep into commit history and branches.  https://github.com/dxa4481/truffleHog
* **Just-Metadata** is a tool that gathers and analyzes metadata about IP addresses. It attempts to find relationships between systems within a large dataset. https://github.com/ChrisTruncer/Just-Metadata
* **typofinder** a finder of domain typos showing country of IP address. https://github.com/nccgroup/typofinder
* **pwnedOrNot** is a python script which checks if the email account has been compromised in a data breach, if the email account is compromised it proceeds to find passwords for the compromised account. https://github.com/thewhiteh4t/pwnedOrNot
* **GitHarvester** This tool is used for harvesting information from GitHub like google dork. https://github.com/metac0rtex/GitHarvester
* **pwndb** is a python command-line tool for searching leaked credentials using the Onion service with the same name. https://github.com/davidtavarez/pwndb/
* **CrossLinked** LinkedIn enumeration tool to extract valid employee names from an organization through search engine scraping. https://github.com/m8r0wn/CrossLinked
* **SpiderFoot** the open source footprinting and intelligence-gathering tool. https://github.com/smicallef/spiderfoot
* **datasploit** is an OSINT Framework to perform various recon techniques on Companies, People, Phone Number, Bitcoin Addresses, etc., aggregate all the raw data, and give data in multiple formats. https://github.com/DataSploit/datasploit

## Weaponization
* **android-malware** A collection of android malware samples. https://github.com/ashishb/android-malware
* **OffensiveCSharp** This is a collection of C# tooling and POCs I've created for use on operations. Each project is designed to use no external libraries. Open each project's .SLN in Visual Studio and compile as "Release". https://github.com/matterpreter/OffensiveCSharp
* **SharpSploit** is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers. https://github.com/cobbr/SharpSploit
* **SharpWeb** .NET 2.0 CLR project to retrieve saved browser credentials from Google Chrome, Mozilla Firefox and Microsoft Internet Explorer/Edge. https://github.com/djhohnstein/SharpWeb
* **reconerator** C# Targeted Attack Reconnissance Tools. https://github.com/stufus/reconerator
* **SharpView** C# implementation of harmj0y's PowerView. https://github.com/tevora-threat/SharpView
* **spotter** potter is a tool to wrap payloads in environmentally-keyed, AES256-encrypted launchers. These keyed launchers provide a way to ensure your payload is running on its intended target, as well as provide a level of protection for the launcher itself. https://github.com/matterpreter/spotter
* **misc** Collection of things I've written on pentests to make life easier. https://github.com/matterpreter/misc
* **getDA.sh** This script checks for a few common, easy to leverage vulnerabilites I find testers using to get Domain Administrator access when stealth doesn't matter. https://github.com/matterpreter/getDA.sh
* **ReverseTCPShell** A reverse shell with bbfuscation, AV evasion, FW and EDR bypassing. https://github.com/ZHacker13/ReverseTCPShell
* **PayloadsAllTheThings**  A list of useful payloads and bypass for Web Application Security and Pentest/CTF  https://github.com/swisskyrepo/PayloadsAllTheThings
* **TIDoS-Framework** The Offensive Manual Web Application Penetration Testing Framework. https://github.com/0xInfection/TIDoS-Framework
* **webshells** A collection of web shells https://github.com/tennc/webshell
* **Perfect-Malware-Samples** Fresh malware samples caught in the wild daily from random places https://github.com/Perfectdotexe/Perfect-Malware-Samples
* **DLLREVERSESHELL** A CUSTOM CODED FUD DLL, CODED IN C , WHEN LOADED , VIA A DECOY WEB-DELIVERY MODULE( FIRING A DECOY PROGRAM), WILL GIVE A REVERSE SHELL (POWERSHELL) FROM THE VICTIM MACHINE TO THE ATTACKER CONSOLE , OVER LAN AND WAN.  https://github.com/1captainnemo1/DLLREVERSESHELL
* **tactical-exploitation** Modern tactical exploitation toolkit. https://github.com/0xdea/tactical-exploitation
* **PayloadsAllTheThings** A list of useful payloads and bypass for Web Application Security and Pentest/CTF  https://github.com/swisskyrepo/PayloadsAllTheThings
* **Sickle** Sickle is a shellcode development tool created to speed up the various steps needed to create functioning shellcode. https://github.com/wetw0rk/Sickle
* **Cheatsheets** Helped during my OSCP lab days. (REALLY GOOD STUFF) https://github.com/slyth11907/Cheatsheets
* **Pandoras-Box** (OSCP) This repo will contain random scripts that I used/use during my offensive testing. It can contain scripts ranging from extremely stupid and basic stuf to some extremely awesome and elite stuff.... Stay tuned :) https://github.com/paranoidninja/Pandoras-Box.git
* **Evil-Droid** Evil-Droid is a framework that create & generate & embed apk payload to penetrate android platforms. https://github.com/M4sc3r4n0/Evil-Droid
* **PhoneSploit** Using open ADB ports we can exploit an android device  https://github.com/metachar/PhoneSploit
* **massadb**  A python script to probe a number of android devices for an open ADB port https://github.com/cyberhexe/massadb
* **TheFatRat** An Easy tool to Generate Backdoor for bypass AV and Easy Tool For Post exploitation attack like browser attack,dll . This tool compiles a malware with popular payload  and then the compiled malware can be execute on windows, android, mac . . https://github.com/Screetsec/TheFatRat
* **NetWorm** Python network worm that spreads on the local network and gives the attacker control of these machines. https://github.com/pylyf/NetWorm
* **cryptondie** CryptonDie is a ransomware developed for study purposes.  https://github.com/zer0dx/cryptondie
* **Microsploit** a Simple tool and not very special but this tool fast and easy create backdoor office exploitation using module metasploit packet. Like Microsoft Office in windows or mac , Open Office in linux  , Macro attack , Buffer Overflow in word . Work in kali rolling , Parrot , Backbox .. https://github.com/Screetsec/Microsploit
* **IPObfuscator** A simple tool to convert the IP to different obfuscated forms https://github.com/OsandaMalith/IPObfuscator
* **WinRAR Remote Code Execution** Proof of Concept exploit for CVE-2018-20250. https://github.com/WyAtu/CVE-2018-20250
* **Composite Moniker** Proof of Concept exploit for CVE-2017-8570. https://github.com/rxwx/CVE-2017-8570
* **Exploit toolkit CVE-2017-8759** is a handy python script which provides pentesters and security researchers a quick and effective way to test Microsoft .NET Framework RCE. https://github.com/bhdresh/CVE-2017-8759
* **CVE-2017-11882 Exploit** accepts over 17k bytes long command/code in maximum. https://github.com/unamer/CVE-2017-11882
* **Adobe Flash Exploit** CVE-2018-4878. https://github.com/anbai-inc/CVE-2018-4878
* **Exploit toolkit CVE-2017-0199** is a handy python script which provides pentesters and security researchers a quick and effective way to test Microsoft Office RCE. https://github.com/bhdresh/CVE-2017-0199
* **ExtensionSpoofer** Simple program to spoof file extensions and icons in Windows https://github.com/henriksb/ExtensionSpoofer
* **demiguise** is a HTA encryption tool for RedTeams. https://github.com/nccgroup/demiguise
* **Office-DDE-Payloads** collection of scripts and templates to generate Office documents embedded with the DDE, macro-less command execution technique. https://github.com/0xdeadbeefJERKY/Office-DDE-Payloads
* **lnkexploit** Spoofing an executable payload as a LNK file https://github.com/mortychannel/lnkexploit
* **CACTUSTORCH** Payload Generation for Adversary Simulations. https://github.com/mdsecactivebreach/CACTUSTORCH
* **SharpShooter** is a payload creation framework for the retrieval and execution of arbitrary CSharp source code. https://github.com/mdsecactivebreach/SharpShooter
* **Don't kill my cat** is a tool that generates obfuscated shellcode that is stored inside of polyglot images. The image is 100% valid and also 100% valid shellcode. https://github.com/Mr-Un1k0d3r/DKMC
* **Malicious Macro Generator Utility** Simple utility design to generate obfuscated macro that also include a AV / Sandboxes escape mechanism. https://github.com/Mr-Un1k0d3r/MaliciousMacroGenerator
* **Invoke-Obfuscation** PowerShell Obfuscator. https://github.com/danielbohannon/Invoke-Obfuscation
* **Invoke-CradleCrafter** PowerShell remote download cradle generator and obfuscator. https://github.com/danielbohannon/Invoke-CradleCrafter
* **eternalblue** EternalBlue MS17-010 scanner / sendNexecute exploit https://github.com/cyberhexe/eternalblue.git
* **Invoke-DOSfuscation** cmd.exe Command Obfuscation Generator & Detection Test Harness. https://github.com/danielbohannon/Invoke-DOSfuscation
* **Unicorn** is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory. https://github.com/trustedsec/unicorn
* **PyFuscation** Obfuscate powershell scripts by replacing Function names, Variables and Parameters. https://github.com/CBHue/PyFuscation
* **EmbedInHTML** Embed and hide any file in an HTML file. https://github.com/Arno0x/EmbedInHTML
* **SigThief** Stealing Signatures and Making One Invalid Signature at a Time. https://github.com/secretsquirrel/SigThief
* **Veil** is a tool designed to generate metasploit payloads that bypass common anti-virus solutions. https://github.com/Veil-Framework/Veil
* **CheckPlease** Sandbox evasion modules written in PowerShell, Python, Go, Ruby, C, C#, Perl, and Rust. https://github.com/Arvanaghi/CheckPlease
* **Invoke-PSImage** is a tool to embeded a PowerShell script in the pixels of a PNG file and generates a oneliner to execute. https://github.com/peewpw/Invoke-PSImage
* **LuckyStrike** a PowerShell based utility for the creation of malicious Office macro documents. To be used for pentesting or educational purposes only. https://github.com/curi0usJack/luckystrike
* **ClickOnceGenerator** Quick Malicious ClickOnceGenerator for Red Team. The default application a simple WebBrowser widget that point to a website of your choice. https://github.com/Mr-Un1k0d3r/ClickOnceGenerator
* **macro_pack** is a tool by @EmericNasi used to automatize obfuscation and generation of MS Office documents, VB scripts, and other formats for pentest, demo, and social engineering assessments. https://github.com/sevagas/macro_pack
* **StarFighters** a JavaScript and VBScript Based Empire Launcher. https://github.com/Cn33liz/StarFighters
* **bsr** A trojan with features: 1 - Kills explorer.exe so the user cant shutdown or open anything on desktop; 2- Constantly kills taskmgr.exe so the user cant end the process; 3 - At the end it kills critical processes so it causes a blue screen https://github.com/Artucuno/bsr
* **nps_payload** this script will generate payloads for basic intrusion detection avoidance. It utilizes publicly demonstrated techniques from several different sources. https://github.com/trustedsec/nps_payload
* **SocialEngineeringPayloads** a collection of social engineering tricks and payloads being used for credential theft and spear phishing attacks. https://github.com/bhdresh/SocialEngineeringPayloads
* **The Social-Engineer Toolkit** is an open-source penetration testing framework designed for social engineering. https://github.com/trustedsec/social-engineer-toolkit
* **PowerShdll** run PowerShell with rundll32. Bypass software restrictions. https://github.com/p3nt4/PowerShdll
* **Ultimate AppLocker ByPass List** The goal of this repository is to document the most common techniques to bypass AppLocker. https://github.com/api0cradle/UltimateAppLockerByPassList
* **Ruler** is a tool that allows you to interact with Exchange servers remotely, through either the MAPI/HTTP or RPC/HTTP protocol. https://github.com/sensepost/ruler
* **Generate-Macro** is a standalone PowerShell script that will generate a malicious Microsoft Office document with a specified payload and persistence method. https://github.com/enigma0x3/Generate-Macro
* **Malicious Macro MSBuild Generator** Generates Malicious Macro and Execute Powershell or Shellcode via MSBuild Application Whitelisting Bypass. https://github.com/infosecn1nja/MaliciousMacroMSBuild
* **Meta Twin** is designed as a file resource cloner. Metadata, including digital signature, is extracted from one file and injected into another. https://github.com/threatexpress/metatwin
* **WePWNise** generates architecture independent VBA code to be used in Office documents or templates and automates bypassing application control and exploit mitigation software. https://github.com/mwrlabs/wePWNise
* **DotNetToJScript** a tool to create a JScript file which loads a .NET v2 assembly from memory. https://github.com/tyranid/DotNetToJScript
* **PSAmsi** is a tool for auditing and defeating AMSI signatures. https://github.com/cobbr/PSAmsi
* **Reflective DLL injection** is a library injection technique in which the concept of reflective programming is employed to perform the loading of a library from memory into a host process. https://github.com/stephenfewer/ReflectiveDLLInjection
* **ps1encode** use to generate and encode a powershell based metasploit payloads. https://github.com/CroweCybersecurity/ps1encode
* **Worse PDF** turn a normal PDF file into malicious. Use to steal Net-NTLM Hashes from windows machines. https://github.com/3gstudent/Worse-PDF
* **SpookFlare** has a different perspective to bypass security measures and it gives you the opportunity to bypass the endpoint countermeasures at the client-side detection and network-side detection. https://github.com/hlldz/SpookFlare
* **GreatSCT** is an open source project to generate application white list bypasses. This tool is intended for BOTH red and blue team. https://github.com/GreatSCT/GreatSCT
* **nps** running powershell without powershell. https://github.com/Ben0xA/nps
* **Meterpreter_Paranoid_Mode.sh** allows users to secure your staged/stageless connection for Meterpreter by having it check the certificate of the handler it is connecting to. https://github.com/r00t-3xp10it/Meterpreter_Paranoid_Mode-SSL
* **MacroShop** a collection of scripts to aid in delivering payloads via Office Macros. https://github.com/khr0x40sh/MacroShop
* **UnmanagedPowerShell** Executes PowerShell from an unmanaged process. https://github.com/leechristensen/UnmanagedPowerShell
* **evil-ssdp** Spoof SSDP replies to phish for NTLM hashes on a network. Creates a fake UPNP device, tricking users into visiting a malicious phishing page. https://gitlab.com/initstring/evil-ssdp
* **Ebowla** Framework for Making Environmental Keyed Payloads. https://github.com/Genetic-Malware/Ebowla
* **avet** (AntiVirusEvasionTool) is targeting windows machines with executable files using different evasion techniques. https://github.com/govolution/avet
* **EvilClippy** A cross-platform assistant for creating malicious MS Office documents. Can hide VBA macros, stomp VBA code (via P-Code) and confuse macro analysis tools. Runs on Linux, OSX and Windows. https://github.com/outflanknl/EvilClippy
* **CallObfuscator** Obfuscate windows apis from static analysis tools and debuggers. https://github.com/d35ha/CallObfuscator
* **CScriptShell** CScriptShell, a Powershell Host running within cscript.exe. This code let's you Bypass Application Whitelisting and Powershell.exe restrictions and gives you a shell that almost looks and feels like a normal Powershell session (Get-Credential, PSSessions -> Works). https://github.com/Cn33liz/CScriptShell
* **Donut** is a shellcode generation tool that creates position-independant shellcode payloads from .NET Assemblies. This shellcode may be used to inject the Assembly into arbitrary Windows processes. https://github.com/TheWover/donut

### Delivery
* **red-transfers** A script to quickly generate a lot of echo uninteractive commands to be executed on the compromised system. Both downloading and uplocading are supported. https://github.com/cyberhexe/red-transfers
* **flask-filebox** Basic file upload Web UI. Make sure to update config.py according to your needs. https://github.com/mtalimanchuk/flask-filebox

### Phishing
* **HiddenEye** All-in-one tool to generate a phishing page https://github.com/DarkSecDevelopers/HiddenEye
* **Phishery** is a Simple SSL Enabled HTTP server with the primary purpose of phishing credentials via Basic Authentication.  https://github.com/ryhanson/phishery
* **King Phisher** is a tool for testing and promoting user awareness by simulating real world phishing attacks. https://github.com/securestate/king-phisher
* **FiercePhish** is a full-fledged phishing framework to manage all phishing engagements. It allows you to track separate phishing campaigns, schedule sending of emails, and much more. https://github.com/Raikia/FiercePhish
* **ReelPhish** is a Real-Time Two-Factor Phishing Tool. https://github.com/fireeye/ReelPhish/
* **Gophish** is an open-source phishing toolkit designed for businesses and penetration testers. It provides the ability to quickly and easily setup and execute phishing engagements and security awareness training. https://github.com/gophish/gophish
* **CredSniper** is a phishing framework written with the Python micro-framework Flask and Jinja2 templating which supports capturing 2FA tokens. https://github.com/ustayready/CredSniper
* **PwnAuth** a web application framework for launching and managing OAuth abuse campaigns. https://github.com/fireeye/PwnAuth
* **Phishing Frenzy** Ruby on Rails Phishing Framework. https://github.com/pentestgeek/phishing-frenzy
* **Phishing Pretexts** a library of pretexts to use on offensive phishing engagements. https://github.com/L4bF0x/PhishingPretexts
* **Modlishka** is a flexible and powerful reverse proxy, that will take your ethical phishing campaigns to the next level. https://github.com/drk1wi/Modlishka
* **Evilginx** is a man-in-the-middle attack framework used for phishing credentials and session cookies of any web service. https://github.com/kgretzky/evilginx2

### Social Engineering
* **FakeID** Fake identity generator https://github.com/Manisso/FakeID

### Remote Access Tools
* **L3MON** Remote Android Management Suite https://github.com/etechd/L3MON
* **android-backdoor-dashboard** Android Meterpreter Backdoor Command & Control https://github.com/cyberhexe/android-backdoor-dashboard
* **flask-reverse-shell** Python HTTPS reverse shell with Flask https://github.com/cyberhexe/flask-reverse-shell
* **tsh** Tiny SHell - An open-source UNIX backdoor https://github.com/creaktive/tsh
* **KeyPlexer** Keyplexer is a Remote Access Trojan (RAT) written in Python. It combines the functionalities of Keylogger with remote access abilities. Meaning, that not only the program records all movements of the user, but also has access to the machine live through the created backdoor or Trojan. https://github.com/nairuzabulhul/KeyPlexer
* **Empire** is a post-exploitation framework that includes a pure-PowerShell2.0 Windows agent, and a pure Python 2.6/2.7 Linux/OS X agent. https://github.com/EmpireProject/Empire
* **Spidernet** SSH Botnet C&C Using Python https://github.com/Und3rf10w/Spidernet
* **SILENTTRINITY** A post-exploitation agent powered by Python, IronPython, C#/.NET. https://github.com/byt3bl33d3r/SILENTTRINITY
* **Pupy** is an opensource, cross-platform (Windows, Linux, OSX, Android) remote administration and post-exploitation tool mainly written in python. https://github.com/n1nj4sec/pupy
* **Koadic** or COM Command & Control, is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. https://github.com/zerosum0x0/koadic
* **PoshC2** is a proxy aware C2 framework written completely in PowerShell to aid penetration testers with red teaming, post-exploitation and lateral movement. https://github.com/nettitude/PoshC2_Python
* **Gcat** a stealthy Python based backdoor that uses Gmail as a command and control server. https://github.com/byt3bl33d3r/gcat
* **TrevorC2** is a legitimate website (browsable) that tunnels client/server communications for covert command execution. https://github.com/trustedsec/trevorc2
* **Merlin** is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in golang. https://github.com/Ne0nd0g/merlin
* **Quasar** is a fast and light-weight remote administration tool coded in C#. Providing high stability and an easy-to-use user interface, Quasar is the perfect remote administration solution for you. https://github.com/quasar/QuasarRAT
* **Covenant** is a .NET command and control framework that aims to highlight the attack surface of .NET, make the use of offensive .NET tradecraft easier, and serve as a collaborative command and control platform for red teamers. https://github.com/cobbr/Covenant
* **DNScat2** is a tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol. https://github.com/iagox86/dnscat2
* **Sliver** is a general purpose cross-platform implant framework that supports C2 over Mutual-TLS, HTTP(S), and DNS. https://github.com/BishopFox/sliver
* **EvilOSX** An evil RAT (Remote Administration Tool) for macOS / OS X. https://github.com/Marten4n6/EvilOSX
* **EggShell** is a post exploitation surveillance tool written in Python. It gives you a command line session with extra functionality between you and a target machine. https://github.com/neoneggplant/EggShell

### Staging
* **Vegile** This tool will set up your backdoor/rootkits when backdoor is already setup it will be hidden, unlimited. Even when it is killed, it will re-run again. There will always be a procces which will run another process, so we can assume that this procces is unstopable like a Ghost in The Shell. https://github.com/Screetsec/Vegile
* **Rapid Attack Infrastructure (RAI)** Red Team Infrastructure... Quick... Fast... Simplified <br/> One of the most tedious phases of a Red Team Operation is usually the infrastructure setup. This usually entails <br/>a teamserver or controller, domains, redirectors, and a Phishing server. https://github.com/obscuritylabs/RAI
* **Red Baron** is a set of modules and custom/third-party providers for Terraform which tries to automate creating resilient, disposable, secure and agile infrastructure for Red Teams. https://github.com/byt3bl33d3r/Red-Baron
* **EvilURL** generate unicode evil domains for IDN Homograph Attack and detect them. https://github.com/UndeadSec/EvilURL
* **Domain Hunter** checks expired domains, bluecoat categorization, and Archive.org history to determine good candidates for phishing and C2 domain names. https://github.com/threatexpress/domainhunter
* **PowerDNS** is a simple proof of concept to demonstrate the execution of PowerShell script using DNS only. https://github.com/mdsecactivebreach/PowerDNS
* **Chameleon** a tool for evading Proxy categorisation. https://github.com/mdsecactivebreach/Chameleon
* **Malleable C2** is a domain specific language to redefine indicators in Beacon's communication. https://github.com/rsmudge/Malleable-C2-Profiles
* **FindFrontableDomains** search for potential frontable domains. https://github.com/rvrsh3ll/FindFrontableDomains
* **Postfix-Server-Setup** Setting up a phishing server is a very long and tedious process. It can take hours to setup, and can be compromised in minutes. https://github.com/n0pe-sled/Postfix-Server-Setup
* **DomainFrontingLists** a list of Domain Frontable Domains by CDN. https://github.com/vysec/DomainFrontingLists
* **Apache2-Mod-Rewrite-Setup** Quickly Implement Mod-Rewrite in your infastructure. https://github.com/n0pe-sled/Apache2-Mod-Rewrite-Setup
* **mod_rewrite rule** to evade vendor sandboxes. https://gist.github.com/curi0usJack/971385e8334e189d93a6cb4671238b10
* **e2modrewrite** a tools for convert Empire profiles to Apache modrewrite scripts. https://github.com/infosecn1nja/e2modrewrite
* **cat-sites** Library of sites for categorization. https://github.com/audrummer15/cat-sites
* **ycsm** is a quick script installation for resilient redirector using nginx reverse proxy and letsencrypt compatible with some popular Post-Ex Tools (Cobalt Strike, Empire, Metasploit, PoshC2). https://github.com/infosecn1nja/ycsm
* **Domain Fronting Google App Engine**. https://github.com/redteam-cyberark/Google-Domain-fronting
* **DomainFrontDiscover** Scripts and results for finding domain frontable CloudFront domains. https://github.com/peewpw/DomainFrontDiscover
* **Automated Empire Infrastructure** https://github.com/bneg/RedTeam-Automation
* **Serving Random Payloads** with NGINX. https://gist.github.com/jivoi/a33ace2e25515a31aa2ffbae246d98c9
* **meek** is a blocking-resistant pluggable transport for Tor. It encodes a data stream as a sequence of HTTPS requests and responses. https://github.com/arlolra/meek
* **mkhtaccess_red** Auto-generate an HTaccess for payload delivery -- automatically pulls ips/nets/etc from known sandbox companies/sources that have been seen before, and redirects them to a benign payload. https://github.com/violentlydave/mkhtaccess_red
* **RedFile** a flask wsgi application that serves files with intelligence, good for serving conditional RedTeam payloads. https://github.com/outflanknl/RedFile
* **keyserver** Easily serve HTTP and DNS keys for proper payload protection. https://github.com/leoloobeek/keyserver
* **HTran** is a connection bouncer, a kind of proxy server. A “listener” program is hacked stealthily onto an unsuspecting host anywhere on the Internet. https://github.com/HiwinCN/HTran


### Man In the Middle
* **js-mitm-proxy** https://github.com/ondrakrat/js-mitm-proxy

### Establish Foothold
* **TinyShell** Web Shell Framework. https://github.com/threatexpress/tinyshell
* **reGeorg** the successor to reDuh, pwn a bastion webserver and create SOCKS proxies through the DMZ. Pivot and pwn. https://github.com/sensepost/reGeorg
* **atbomb** A script to quickly generate a lot of AT statements to be executed on the compromised Windows machine https://github.com/cyberhexe/atbomb
* **Blade** is a webshell connection tool based on console, currently under development and aims to be a choice of replacement of Chooper. https://github.com/wonderqs/Blade
* **PowerLurk** is a PowerShell toolset for building malicious WMI Event Subsriptions. https://github.com/Sw4mpf0x/PowerLurk
* **DAMP** The Discretionary ACL Modification Project: Persistence Through Host-based Security Descriptor Modification. https://github.com/HarmJ0y/DAMP

### Pivoting and Tunneling
* **dns-tcp-proxy** A python script to tunnel the DNS queries through a TCP proxy https://github.com/cyberhexe/dns-tcp-proxy
* **rpivot** This is a method of traversing NAT connections. Rpivot is a reverse socks proxy tool that allows you to tunnel traffic via socks proxy. It connects back to your machine and binds a socks proxy on it. It works just like `ssh -D` but in opposite direction https://github.com/artkond/rpivot
* **redsocks** Redsocks is the tool that allows you to proxify(redirect) network traffic through a SOCKS4, SOCKS5 or HTTPs proxy server. It works on the lowest level, the kernel level (iptables). The other possible way is to use application level proxy, when the proxy client is implemented in the same language as an application is written in. Redsocks operates on the lowest system level, that’s why all running application don’t even have an idea that network traffic is sent through a proxy server, as a result it is called a transparent proxy redirector. https://github.com/darkk/redsocks
* **Tunna** is a set of tools which will wrap and tunnel any TCP communication over HTTP. It can be used to bypass network restrictions in fully firewalled environments. https://github.com/SECFORCE/Tunna
* **http-tunnel** A program to tunnel TCP connection through HTTP connection. https://github.com/khuevu/http-tunnel
* **microsocks** a SOCKS5 service that you can run on your remote boxes to tunnel connections through them, if for some reason SSH doesn't cut it for you. https://github.com/cyberhexe/microsocks
* **pyrexecd** PyRexecd is a standalone SSH server for Windows. https://github.com/euske/pyrexecd.git
* **3proxy** is a tiny free proxy server https://github.com/z3APA3A/3proxy
* **win-sshd** A native windows ssh2 server https://github.com/saju/win-sshd
* **sshuttle** Transparent proxy server that works as a poor man's VPN. Forwards over ssh. Doesn't require admin. Works with Linux and MacOS. Supports DNS tunneling. https://github.com/sshuttle/sshuttle

### Lateral Movement
* **TREVORspray** A featureful Python O365 sprayer based on MSOLSpray which uses the Microsoft Graph API https://github.com/blacklanternsecurity/TREVORspray
* **rshijack** tcp connection hijacker. The way this works is by sniffing for a packet of a specific connection, then read the SEQ and ACK fields. Using that information, it's possible to send a packet on a raw socket that is accepted by the remote server as valid. https://github.com/kpcyrd/rshijack
* **DumpsterDiver** DumpsterDiver is a tool, which can analyze big volumes of data in search of hardcoded secrets like keys (e.g. AWS Access Key, Azure Share Key or SSH keys) or passwords. https://github.com/securing/DumpsterDiver
* **aes-finder** Utility to find AES keys in running process memory. Works for 128, 192 and 256-bit keys. https://github.com/mmozeiko/aes-finder
* **evil-winrm** This program can be used on any Microsoft Windows Servers with this feature enabled (usually at port 5985), of course only if you have credentials and permissions to use it. https://github.com/Hackplayers/evil-winrm
* **CrackMapExec** is a swiss army knife for pentesting networks. https://github.com/byt3bl33d3r/CrackMapExec
* **Invoke-Phant0m** This script walks thread stacks of Event Log Service process (spesific svchost.exe) and identify Event Log Threads to kill Event Log Service Threads. So the system will not be able to collect logs and at the same time the Event Log Service will appear to be running. https://github.com/Und3rf10w/Invoke-Phant0m
* **PowerLessShell** rely on MSBuild.exe to remotely execute PowerShell scripts and commands without spawning powershell.exe. https://github.com/Mr-Un1k0d3r/PowerLessShell
* **GoFetch** is a tool to automatically exercise an attack plan generated by the BloodHound application. https://github.com/GoFetchAD/GoFetch
* **DeathStar** is a Python script that uses Empire's RESTful API to automate gaining Domain Admin rights in Active Directory environments using a variety of techinques. https://github.com/byt3bl33d3r/DeathStar
* **SharpHound** C# Rewrite of the BloodHound Ingestor. https://github.com/BloodHoundAD/SharpHound
* **BloodHound.py** is a Python based ingestor for BloodHound, based on Impacket. https://github.com/fox-it/BloodHound.py
* **SessionGopher** is a PowerShell tool that uses WMI to extract saved session information for remote access tools such as WinSCP, PuTTY, SuperPuTTY, FileZilla, and Microsoft Remote Desktop. It can be run remotely or locally. https://github.com/fireeye/SessionGopher
* **PowerSploit** is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. https://github.com/PowerShellMafia/PowerSploit
* **Nishang** is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security, penetration testing and red teaming. Nishang is useful during all phases of penetration testing. https://github.com/samratashok/nishang
* **Inveigh** is a Windows PowerShell LLMNR/mDNS/NBNS spoofer/man-in-the-middle tool. https://github.com/Kevin-Robertson/Inveigh
* **PowerUpSQL** a PowerShell Toolkit for Attacking SQL Server. https://github.com/NetSPI/PowerUpSQL
* **MailSniper** is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords, insider intel, network architecture information, etc.). https://github.com/dafthack/MailSniper
* **WMIOps** is a powershell script that uses WMI to perform a variety of actions on hosts, local or remote, within a Windows environment. It's designed primarily for use on penetration tests or red team engagements. https://github.com/ChrisTruncer/WMIOps
* **Mimikatz** is an open-source utility that enables the viewing of credential information from the Windows lsass. https://github.com/gentilkiwi/mimikatz
* **LaZagne** project is an open source application used to retrieve lots of passwords stored on a local computer. https://github.com/AlessandroZ/LaZagne
* **mimipenguin** a tool to dump the login password from the current linux desktop user. Adapted from the idea behind the popular Windows tool mimikatz. https://github.com/huntergregal/mimipenguin
* **PsExec** is a light-weight telnet-replacement that lets you execute processes on other systems, complete with full interactivity for console applications, without having to manually install client software. https://docs.microsoft.com/en-us/sysinternals/downloads/psexec
* **KeeThief** allows for the extraction of KeePass 2.X key material from memory, as well as the backdooring and enumeration of the KeePass trigger system. https://github.com/HarmJ0y/KeeThief
* **PSAttack** combines some of the best projects in the infosec powershell community into a self contained custom PowerShell console. https://github.com/jaredhaight/PSAttack
* **Internal Monologue Attack** Retrieving NTLM Hashes without Touching LSASS. https://github.com/eladshamir/Internal-Monologue
* **Impacket** is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (for instance NMB, SMB1-3 and MS-DCERPC) the protocol implementation itself. https://github.com/CoreSecurity/impacket
* **icebreaker** gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment. https://github.com/DanMcInerney/icebreaker
* **Living Off The Land Binaries and Scripts (and now also Libraries)** The goal of these lists are to document every binary, script and library that can be used for other purposes than they are designed to. https://github.com/api0cradle/LOLBAS
* **WSUSpendu** for compromised WSUS server to extend the compromise to clients. https://github.com/AlsidOfficial/WSUSpendu
* **Evilgrade** is a modular framework that allows the user to take advantage of poor upgrade implementations by injecting fake updates. https://github.com/infobyte/evilgrade
* **NetRipper** is a post exploitation tool targeting Windows systems which uses API hooking in order to intercept network traffic and encryption related functions from a low privileged user, being able to capture both plain-text traffic and encrypted traffic before encryption/after decryption. https://github.com/NytroRST/NetRipper
* **LethalHTA** Lateral Movement technique using DCOM and HTA. https://github.com/codewhitesec/LethalHTA
* **Invoke-PowerThIEf** an Internet Explorer Post Exploitation library. https://github.com/nettitude/Invoke-PowerThIEf
* **RedSnarf** is a pen-testing / red-teaming tool for Windows environments. https://github.com/nccgroup/redsnarf
* **HoneypotBuster** Microsoft PowerShell module designed for red teams that can be used to find honeypots and honeytokens in the network or at the host. https://github.com/JavelinNetworks/HoneypotBuster
* **PAExec** lets you launch Windows programs on remote Windows computers without needing to install software on the remote computer first. https://www.poweradmin.com/paexec/
* **nishang** Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security, penetration testing and red teaming. Nishang is useful during all phases of penetration testing. https://github.com/samratashok/nishang

### Local Privileges Escalation
* **JAWS** JAWS is PowerShell script designed to help penetration testers (and CTFers) quickly identify potential privilege escalation vectors on Windows systems. It is written using PowerShell 2.0 so 'should' run on every Windows version since Windows 7. https://github.com/411Hall/JAWS
* **AutoLocalPrivilegeEscalation** An automated script that download potential exploit for linux kernel from exploitdb, and compile them automatically https://github.com/ngalongc/AutoLocalPrivilegeEscalation
* **linux-smart-enumeration** Linux Privilege Escalation Enumeration Script (with colored output) https://github.com/diego-treitos/linux-smart-enumeration
* **Powerless** Windows Privilege Escalation Enumeration Script (only cmd, no powershell) https://github.com/M4ximuss/Powerless
* **Privesc** Windows batch script that finds misconfiguration issues which can lead to privilege escalation.  https://github.com/enjoiz/Privesc
* **windows-privesc-check** Windows-privesc-check is standalone executable that runs on Windows systems. It tries to find misconfigurations that could allow local unprivileged users to escalate privileges to other users or to access local apps (e.g. databases)  https://github.com/pentestmonkey/windows-privesc-check
* **Linux_Exploit_Suggester** Linux exploit suggester for Privilege Escalation && Local Enumeration  https://github.com/InteliSecureLabs/Linux_Exploit_Suggester
* **linux-kernel-exploits** A number of Linux kernel exploits for Privilege Escalation && Local Enumeration https://github.com/SecWiki/linux-kernel-exploits
* **LinEnum** Scripted Local Linux Enumeration & Privilege Escalation Checks https://github.com/rebootuser/LinEnum
* **wesng** WES-NG is a tool based on the output of Windows' `systeminfo` utility which provides the list of vulnerabilities the OS is vulnerable to, including any exploits for these vulnerabilities. Every Windows OS between Windows XP and Windows 10, including their Windows Server counterparts, is supported. https://github.com/bitsadmin/wesng
* **Windows-Exploit-Suggester** This tool compares a targets patch levels against the Microsoft vulnerability database in order to detect potential missing patches on the target. It also notifies the user if there are public exploits and Metasploit modules available for the missing bulletins. https://github.com/GDSSecurity/Windows-Exploit-Suggester
* **UACMe** is an open source assessment tool that contains many methods for bypassing Windows User Account Control on multiple versions of the operating system. https://github.com/hfiref0x/UACME
* **windows-kernel-exploits** a collection windows kernel exploit. https://github.com/SecWiki/windows-kernel-exploits
* **Sherlock** a powerShell script to quickly find missing software patches for local privilege escalation vulnerabilities. https://github.com/rasta-mouse/Sherlock
* **Watson** is a (.NET 2.0 compliant) C# implementation of Sherlock. https://github.com/rasta-mouse/Watson
* **Tokenvator** a tool to elevate privilege with Windows Tokens. https://github.com/0xbadjuju/Tokenvator

### Domain Privileges Escalation
* **linikatz** linikatz is a tool to attack AD on UNIX https://github.com/portcullislabs/linikatz
* **Invoke-ACLpwn** is a tool that automates the discovery and pwnage of ACLs in Active Directory that are unsafe configured. https://github.com/fox-it/Invoke-ACLPwn
* **BloodHound** uses graph theory to reveal the hidden and often unintended relationships within an Active Directory environment. https://github.com/BloodHoundAD/BloodHound
* **Grouper** a PowerShell script for helping to find vulnerable settings in AD Group Policy. https://github.com/l0ss/Grouper
* **ADRecon** is a tool which extracts various artifacts (as highlighted below) out of an AD environment in a specially formatted Microsoft Excel report that includes summary views with metrics to facilitate analysis. https://github.com/sense-of-security/ADRecon
* **ADACLScanner** one script for ACL's in Active Directory. https://github.com/canix1/ADACLScanner
* **ACLight** a useful script for advanced discovery of Domain Privileged Accounts that could be targeted - including Shadow Admins. https://github.com/cyberark/ACLight
* **LAPSToolkit** a tool to audit and attack LAPS environments. https://github.com/leoloobeek/LAPSToolkit
* **PingCastle** is a free, Windows-based utility to audit the risk level of your AD infrastructure and check for vulnerable practices. https://www.pingcastle.com/download
* **RiskySPNs** is a collection of PowerShell scripts focused on detecting and abusing accounts associated with SPNs (Service Principal Name). https://github.com/cyberark/RiskySPN
* **Mystique** is a PowerShell tool to play with Kerberos S4U extensions, this module can assist blue teams to identify risky Kerberos delegation configurations as well as red teams to impersonate arbitrary users by leveraging KCD with Protocol Transition. https://github.com/machosec/Mystique
* **Rubeus** is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpy's Kekeo project. https://github.com/GhostPack/Rubeus
* **kekeo** is a little toolbox I have started to manipulate Microsoft Kerberos in C (and for fun). https://github.com/gentilkiwi/kekeo

### Data Exfiltration
* **CloakifyFactory** & the Cloakify Toolset - Data Exfiltration & Infiltration In Plain Sight; Evade DLP/MLS Devices; Social Engineering of Analysts; Defeat Data Whitelisting Controls; Evade AV Detection. https://github.com/TryCatchHCF/Cloakify
* **DET** (is provided AS IS), is a proof of concept to perform Data Exfiltration using either single or multiple channel(s) at the same time. https://github.com/sensepost/DET
* **DNSExfiltrator** allows for transfering (exfiltrate) a file over a DNS request covert channel. This is basically a data leak testing tool allowing to exfiltrate data over a covert channel. https://github.com/Arno0x/DNSExfiltrator
* **PyExfil** a Python Package for Data Exfiltration. https://github.com/ytisf/PyExfil
* **Egress-Assess** is a tool used to test egress data detection capabilities. https://github.com/ChrisTruncer/Egress-Assess
* **LNKUp** This tool will allow you to generate LNK payloads. Upon rendering or being run, they will exfiltrate data. https://github.com/Plazmaz/LNKUp
* **Powershell RAT** python based backdoor that uses Gmail to exfiltrate data as an e-mail attachment. https://github.com/Viralmaniar/Powershell-RAT

### Anonymization
* **torghost** Tor anonymizer https://github.com/susmithHCK/torghost
* **docker-onion-nmap** Scan .onion hidden services with nmap using Tor, proxychains and dnsmasq in a minimal alpine Docker container. https://github.com/milesrichardson/docker-onion-nmap
* **kali-anonsurf** Anonsurf will anonymize the entire system under TOR using IPTables. It will also allow you to start and stop i2p as well. https://github.com/Und3rf10w/kali-anonsurf

### Malware Analysis
* **capa** capa detects capabilities in executable files. You run it against a PE file or shellcode and it tells you what it thinks the program can do. For example, it might suggest that the file is a backdoor, is capable of installing services, or relies on HTTP to communicate. https://github.com/fireeye/capa

### Adversary Simulation
* **MITRE CALDERA** - An automated adversary emulation system that performs post-compromise adversarial behavior within Windows Enterprise networks. https://github.com/mitre/caldera
* **APTSimulator** - A Windows Batch script that uses a set of tools and output files to make a system look as if it was compromised. https://github.com/NextronSystems/APTSimulator
* **Atomic Red Team** - Small and highly portable detection tests mapped to the Mitre ATT&CK Framework. https://github.com/redcanaryco/atomic-red-team
* **Network Flight Simulator** - flightsim is a lightweight utility used to generate malicious network traffic and help security teams to evaluate security controls and network visibility. https://github.com/alphasoc/flightsim
* **Metta** - A security preparedness tool to do adversarial simulation. https://github.com/uber-common/metta
* **Red Team Automation (RTA)** - RTA provides a framework of scripts designed to allow blue teams to test their detection capabilities against malicious tradecraft, modeled after MITRE ATT&CK. https://github.com/endgameinc/RTA

### Wireless Networks
* **opendrop** An open AirDrop Apple implementation written on Python https://github.com/seemoo-lab/opendrop
* **bluescan** A powerful Bluetooth scanner. https://github.com/fO-000/bluescan
* **WiFiBroot** A WiFi Pentest Cracking tool for WPA/WPA2 (Handshake, PMKID, Cracking, EAPOL, Deauthentication) https://github.com/hash3liZer/WiFiBroot
* **apple_bleee** These scripts are experimental PoCs that show what an attacker get from Apple devices if they sniff Bluetooth traffic. https://github.com/hexway/apple_bleee
* **IMSI-catcher** This program shows you IMSI numbers, country, brand and operator of cellphones around you. https://github.com/marcinguy/IMSI-catcher
* **Awesome-Cellular-Hacking** A list of resources about cellular hacking https://github.com/W00t3k/Awesome-Cellular-Hacking
* **Wifiphisher** is a security tool that performs Wi-Fi automatic association attacks to force wireless clients to unknowingly connect to an attacker-controlled Access Point. https://github.com/wifiphisher/wifiphisher
* **mana** toolkit for wifi rogue AP attacks and MitM. https://github.com/sensepost/mana
* **wifite** An automated wireless attack tool https://github.com/Und3rf10w/wifite

### Embedded & Peripheral Devices Hacking
* **USBTrojan** Super simple loader that spreads over removable drives (USB flash drives, portable and network drives, SD cards). Features: You can add the HWID of your PC to the whitelist and trojan will ignore it; You can add any payload (executable file); Slient work. Ideal for school, university or office. https://github.com/mashed-potatoes/USBTrojan
* **USB-Rubber-Ducky** The USB Rubber Ducky is a Human Interface Device programmable with a simple scripting language allowing penetration testers to quickly and easily craft and deploy security auditing payloads that mimic human keyboard input. https://github.com/hak5darren/USB-Rubber-Ducky
* **magspoof** a portable device that can spoof/emulate any magnetic stripe, credit card or hotel card "wirelessly", even on standard magstripe (non-NFC/RFID) readers. https://github.com/samyk/magspoof
* **WarBerryPi** was built to be used as a hardware implant during red teaming scenarios where we want to obtain as much information as possible in a short period of time with being as stealth as possible. https://github.com/secgroundzero/warberry
* **P4wnP1** is a highly customizable USB attack platform, based on a low cost Raspberry Pi Zero or Raspberry Pi Zero W (required for HID backdoor). https://github.com/mame82/P4wnP1
* **malusb** HID spoofing multi-OS payload for Teensy. https://github.com/ebursztein/malusb
* **Fenrir** is a tool designed to be used "out-of-the-box" for penetration tests and offensive engagements. Its main feature and purpose is to bypass wired 802.1x protection and to give you an access to the target network. https://github.com/Orange-Cyberdefense/fenrir-ocd
* **poisontap** exploits locked/password protected computers over USB, drops persistent WebSocket-based backdoor, exposes internal router, and siphons cookies using Raspberry Pi Zero & Node.js. https://github.com/samyk/poisontap
* **WHID** WiFi HID Injector - An USB Rubberducky / BadUSB On Steroids. https://github.com/whid-injector/WHID
* **PhanTap** is an ‘invisible’ network tap aimed at red teams. With limited physical access to a target building, this tap can be installed inline between a network device and the corporate network. https://github.com/nccgroup/phantap

### Software For Team Communication
* **shhh**  Flask app to share encrypted secrets with people using custom links, passphrases and expiration dates.  https://github.com/smallwat3r/shhh
* **RocketChat** is free, unlimited and open source. Replace email & Slack with the ultimate team chat software solution. https://rocket.chat
* **Etherpad** is an open source, web-based collaborative real-time editor, allowing authors to simultaneously edit a text document https://etherpad.net

### Log Aggregation
* **RedELK** Red Team's SIEM - easy deployable tool for Red Teams used for tracking and alarming about Blue Team activities as well as better usability in long term operations. https://github.com/outflanknl/RedELK/
* **Red Team Telemetry** A collection of scripts and configurations to enable centralized logging of red team infrastructure. https://github.com/ztgrace/red_team_telemetry
* **Elastic for Red Teaming** Repository of resources for configuring a Red Team SIEM using Elastic. https://github.com/SecurityRiskAdvisors/RedTeamSIEM
* **Ghostwriter** is a Django project written in Python 3.7 and is designed to be used by a team of operators. https://github.com/GhostManager/Ghostwriter

### Cloud Computing
* **kali-cloud-build** This script bootstraps a barebones Kali installation to create either an Amazon machine image or a Google Compute Engine image. The image contains no latent logfiles no .bash_history or even the apt package cache. https://github.com/Und3rf10w/kali-cloud-build

### Labs
* **Detection Lab** This lab has been designed with defenders in mind. Its primary purpose is to allow the user to quickly build a Windows domain that comes pre-loaded with security tooling and some best practices when it comes to system logging configurations. https://github.com/clong/DetectionLab
* **Modern Windows Attacks and Defense Lab** This is the lab configuration for the Modern Windows Attacks and Defense class that Sean Metcalf (@pyrotek3) and I teach. https://github.com/jaredhaight/WindowsAttackAndDefenseLab
* **Invoke-UserSimulator** Simulates common user behaviour on local and remote Windows hosts. https://github.com/ubeeri/Invoke-UserSimulator
* **Invoke-ADLabDeployer** Automated deployment of Windows and Active Directory test lab networks. Useful for red and blue teams. https://github.com/outflanknl/Invoke-ADLabDeployer
* **Sheepl** Creating realistic user behaviour for supporting tradecraft development within lab environments. https://github.com/SpiderLabs/sheepl

### Binaries
 * **accesschk.exe**  accesschk.exe is a Microsoft Sysinternals tool that is great for auditing privileges on your systems https://web.archive.org/web/20080530012252/http://live.sysinternals.com/accesschk.exe

## References
* **the-hacking-trove** This website can definitely help you during your penetration test, technical security audit, PWK/OSCP Lab or exam, CTF, challenge, training, etc. by providing cheat sheets, tools, examples, references, etc. https://noraj.gitlab.io/the-hacking-trove/
* **Cheatsheet-God** Penetration Testing Biggest Reference Bank - OSCP / PTP & PTX Cheatsheet https://github.com/OlivierLaflamme/Cheatsheet-God
* **RedTeam-Tactics-and-Techniques** This is publicly accessible personal notes at https://ired.team about my pentesting / red teaming experiments in a controlled environment that involve playing with various tools and techniques used by penetration testers, red teams and advanced adversaries. https://github.com/mantvydasb/RedTeam-Tactics-and-Techniques
* **Awesome-WAF** Everything awesome about web application firewalls (WAFs). https://github.com/0xInfection/Awesome-WAF
* **PENTESTING-BIBLE** hundreds of ethical hacking & penetration testing & red team & cyber security & computer science resources. https://github.com/blaCCkHatHacEEkr/PENTESTING-BIBLE/
* **awesome-python** A curated list of awesome Python frameworks, libraries, software and resources. https://github.com/vinta/awesome-python
* **awesome-reversing** A curated list of awesome reversing resources https://github.com/tylerha97/awesome-reversing 
* **Cheatsheets** Penetration Testing/Security Cheatsheets that I have collated over the years. https://github.com/rmusser01/Cheatsheets
* **awesome-nginx-security** A curated list of awesome links related to application/API security in NGINX environment.  https://github.com/wallarm/awesome-nginx-security
* **MITRE’s ATT&CK™** is a curated knowledge base and model for cyber adversary behavior, reflecting the various phases of an adversary’s lifecycle and the platforms they are known to target. https://attack.mitre.org/wiki/Main_Page
* **Cheat Sheets** for various projects (Beacon/Cobalt Strike,PowerView, PowerUp, Empire, and PowerSploit). https://github.com/HarmJ0y/CheatSheets
* **PRE-ATT&CK** Adversarial Tactics, Techniques & Common Knowledge for Left-of-Exploit. https://attack.mitre.org/pre-attack/index.php/Main_Page
* **Adversary OPSEC** consists of the use of various technologies or 3rd party services to obfuscate, hide, or blend in with accepted network traffic or system behavior. https://attack.mitre.org/pre-attack/index.php/Adversary_OPSEC
* **Adversary Emulation Plans** To showcase the practical use of ATT&CK for offensive operators and defenders, MITRE created Adversary Emulation Plans. https://attack.mitre.org/wiki/Adversary_Emulation_Plans
* **Red-Team-Infrastructure-Wiki** Wiki to collect Red Team infrastructure hardening resources. https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki
* **Advanced Threat Tactics – Course and Notes** This is a course on red team operations and adversary simulations. https://blog.cobaltstrike.com/2015/09/30/advanced-threat-tactics-course-and-notes
* **Red Team Tips** as posted by @vysecurity on Twitter. https://vincentyiu.co.uk/red-team-tips
* **Awesome Red Teaming** List of Awesome Red Team / Red Teaming Resources. https://github.com/yeyintminthuhtut/Awesome-Red-Teaming
* **ATT&CK for Enterprise Software** is a generic term for custom or commercial code, operating system utilities, open-source software, or other tools used to conduct behavior modeled in ATT&CK. https://attack.mitre.org/wiki/Software
* **Planning a Red Team exercise** This document helps inform red team planning by contrasting against the very specific red team style described in Red Teams. https://github.com/magoo/redteam-plan
* **Awesome Lockpicking** a curated list of awesome guides, tools, and other resources related to the security and compromise of locks, safes, and keys. https://github.com/meitar/awesome-lockpicking
* **Awesome Threat Intelligence** a curated list of awesome Threat Intelligence resources. https://github.com/hslatman/awesome-threat-intelligence
* **APT Notes** Need some scenario? APTnotes is a repository of publicly-available papers and blogs (sorted by year) related to malicious campaigns/activity/software that have been associated with vendor-defined APT (Advanced Persistent Threat) groups and/or tool-sets. https://github.com/aptnotes/data
* **TIBER-EU FRAMEWORK** The European Framework for Threat Intelligence-based Ethical Red Teaming (TIBER-EU), which is the first Europe-wide framework for controlled and bespoke tests against cyber attacks in the financial market. http://www.ecb.europa.eu/pub/pdf/other/ecb.tiber_eu_framework.en.pdf
* **CBEST Implementation Guide** CBEST is a framework to deliver controlled, bespoke, intelligence-led cyber security tests. The tests replicate behaviours of threat actors, assessed by the UK Government and commercial intelligence providers as posing a genuine threat to systemically important financial institutions. https://www.crest-approved.org/wp-content/uploads/2014/07/CBEST-Implementation-Guide.pdf
* **Red Team: Adversarial Attack Simulation Exercise Guidelines for the Financial Industry in Singapore** The Association of Banks in Singapore (ABS), with support from the Monetary Authority of Singapore (MAS), has developed a set of cybersecurity assessment guidelines today to strengthen the cyber resilience of the financial sector in Singapore. Known as the Adversarial Attack Simulation Exercises (AASE) Guidelines or “Red Teaming” Guidelines, the Guidelines provide financial institutions (FIs) with best practices and guidance on planning and conducting Red Teaming exercises to enhance their security testing. https://abs.org.sg/docs/library/abs-red-team-adversarial-attack-simulation-exercises-guidelines-v1-06766a69f299c69658b7dff00006ed795.pdf

### Scripts
  * https://github.com/Und3rf10w
  * https://github.com/invokethreatguy/CSASC
  * https://github.com/secgroundzero/CS-Aggressor-Scripts
  * https://github.com/Und3rf10w/Aggressor-scripts
  * https://github.com/harleyQu1nn/AggressorScripts
  * https://github.com/rasta-mouse/Aggressor-Script
  * https://github.com/RhinoSecurityLabs/Aggressor-Scripts
  * https://github.com/bluscreenofjeff/AggressorScripts
  * https://github.com/001SPARTaN/aggressor_scripts
  * https://github.com/FortyNorthSecurity/AggressorAssessor
  * https://github.com/ramen0x3f/AggressorScripts
  * https://github.com/FuzzySecurity/PowerShell-Suite
  * https://github.com/nettitude/Powershell
  * https://github.com/Mr-Un1k0d3r/RedTeamPowershellScripts
  * https://github.com/threatexpress/red-team-scripts
  * https://github.com/SadProcessor/SomeStuff
  * https://github.com/rvrsh3ll/Misc-Powershell-Scripts
  * https://github.com/enigma0x3/Misc-PowerShell-Stuff
  * https://github.com/ChrisTruncer/PenTestScripts
  * https://github.com/bluscreenofjeff/Scripts
  * https://github.com/xorrior/RandomPS-Scripts
  * https://github.com/xorrior/Random-CSharpTools
  * https://github.com/leechristensen/Random
  * https://github.com/mgeeky/Penetration-Testing-Tools/tree/master/social-engineering
  * https://github.com/kevthehermit/pentest/blob/master/linux-enum-mod.sh

### Wordlists
* **SecLists** It's a collection of multiple types of lists used during security assessments, collected in one place. List types include usernames, passwords, URLs, sensitive data patterns, fuzzing payloads, web shells, and many more. https://github.com/danielmiessler/SecLists
* **fuzzdb** Dictionary of attack patterns and primitives for black-box application fault injection and resource discovery. https://github.com/fuzzdb-project/fuzzdb
  
