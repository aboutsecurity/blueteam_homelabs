# Great List of Resources and Training to Build an Enterprise Grade Home Lab

Based on the Blue Team series of webinars: ['Becoming an All-Around Defender'](https://www.sans.org/blog/becoming-an-all-around-defender/) by [Security 530](https://www.sans.org/course/defensible-security-architecture-and-engineering) co-authors Ismael Valenzuela [@aboutsecurity](https://twitter.com/aboutsecurity) & Justin Henderson [@securitymapper](https://twitter.com/securitymapper?lang=en)

## Keep Learning

* [Ismael Valenzuela](https://ismaelvalenzuela.com/) - Articles, research, training, and speaking resources.
* [Think Red. Act Blue.](https://thinkredactblue.com/) - A framework for turning an understanding of adversary behavior into operational defense.
* [ATT&CK Lens](https://lens.thinkredactblue.com/) - Explore MITRE ATT&CK adversaries, techniques, detection strategies, and analytics to guide lab exercises and coverage reviews.
* [The Monday Brief](https://www.themondaybrief.com/) - A weekly briefing by Ismael Valenzuela and Douglas McKee, translating cybersecurity, AI, and technology signals into decisions.

Resource refresh last reviewed: **2026-11-19**. Free editions, evaluation periods, and license terms can change; check upstream requirements before deploying. "OpenSource / Free" groups open-source tools and products with free offerings, not identical licensing terms.

## Network
### OpenSource / Free

* [Zeek](https://zeek.org/) - A powerful framework for network traffic analysis and security monitoring.
* [Suricata](https://suricata.io/) - Suricata is a free and open source, mature, fast and robust network threat detection engine.The Suricata engine is capable of real time intrusion detection (IDS), inline intrusion prevention (IPS), network security monitoring (NSM) and offline pcap processing.
    - [EveBox](https://evebox.org/) - Web GUI for analyzing Suricata EVE logs. Removes need for SIEM or other interface although a SIEM still allows for more granular control and augmentation
    - [Scirius](https://github.com/StamusNetworks/scirius) - GUI for managing Suricata rules
* [Security Onion](https://securityonion.net/) - A free and open platform for network and host visibility, threat hunting, and case management. It integrates Suricata detection, Zeek metadata, full packet capture, Strelka file analysis, and Elasticsearch. Elastic Agent provides endpoint telemetry managed through Elastic Fleet; the Detections interface manages Suricata, Sigma, and YARA rules. See the [current architecture and components](https://docs.securityonion.net/en/2.4/introduction.html) before sizing a deployment.
* [Arkime](https://arkime.com/) - Formerly Moloch, Arkime stores and indexes network traffic in standard PCAP format, with a web interface for browsing, searching, and exporting captured sessions.
* [Pi-hole](https://pi-hole.net/) - The Pi-hole® is a DNS sinkhole that protects your devices from unwanted content, without installing any client-side software.
* [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome) - A network-wide DNS server for filtering ads and trackers, with a web interface for configuration and query analysis.
* [pfSense](https://github.com/pfsense/pfsense) - Firewall and Router FreeBSD distribution. pfSense started in 2004 as a fork of the m0n0wall Project (which ended 2015/02/15), though has diverged significantly since.
    - Supports SSL/TLS Inspection via Squid SslBump
    - Supports network antivirus
    - Supports VPN
    - Supports IDS/IPS
* [Opnsense](https://opnsense.org/) - OPNsense is an open source, easy-to-use and easy-to-build HardenedBSD based firewall and routing platform. OPNsense includes most of the features available in expensive commercial firewalls, and more in many cases. It brings the rich feature set of commercial offerings with the benefits of open and verifiable sources.OPNsense started as a fork of pfSense® and m0n0wall in 2014, with its first official release in January 2015. The project has evolved very quickly while still retaining  familiar aspects of both m0n0wall and pfSense. A strong focus on security and code quality drives the development of the project.
* [WireGuard](https://www.wireguard.com/) - WireGuard® is an extremely simple yet fast and modern VPN that utilizes state-of-the-art cryptography. It aims to be faster, simpler, leaner, and more useful than IPsec, while avoiding the massive headache. It intends to be considerably more performant than OpenVPN.
* [PacketFence](https://packetfence.org/) - PacketFence is a fully supported, trusted, Free and Open Source network access control (NAC) solution. Boasting an impressive feature set including a captive-portal for registration and remediation, centralized wired, wireless and VPN management, industry-leading BYOD capabilities, 802.1X and RBAC support, integrated network anomaly detection with layer-2 isolation of problematic devices; PacketFence can be used to effectively secure small to very large heterogeneous networks.

### Commercial

* [Unifi SDN, Ubiquiti](https://www.ui.com/software/) - The UniFi® Software-Defined Networking (SDN) platform is an end-to-end system of network devices across different locations — all controlled from a single interface.

## Endpoint
### OpenSource / Free

* [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) - System Monitor (Sysmon) is a Windows system service and device driver that, once installed on a system, remains resident across system reboots to monitor and log system activity to the Windows event log. It provides detailed information about process creations, network connections, and changes to file creation time. By collecting the events it generates using Windows Event Collection or SIEM agents and subsequently analyzing them, you can identify malicious or anomalous activity and understand how intruders and malware operate on your network.
    - Guide 1 - Olaf Hartong has a project called Sysmon Modular. It breaks out each Sysmon event ID and adds MITRE technique IDs to the logs. https://github.com/olafhartong/sysmon-modular
    - Guide 2 - Swift on Security has a Sysmon configuration file that is documented and works as a great start. https://github.com/SwiftOnSecurity/sysmon-config
* [Auditd](https://linux.die.net/man/8/auditd) - The auditd subsystem is an access monitoring and accounting for Linux developed and maintained by RedHat. It was designed to integrate pretty tightly with the kernel and watch for interesting system calls. Additionally, likely because of this level of integration and detailed logging, it is used as the logger for SELinux.
* [OSQuery](https://osquery.io/) - osquery exposes an operating system as a high-performance relational database. This allows you to write SQL-based queries to explore operating system data. With osquery, SQL tables represent abstract concepts such as running processes, loaded kernel modules, open network connections, browser plugins, hardware events or file hashes.
* [Velociraptor](https://github.com/Velocidex/velociraptor) - Velociraptor is a tool for collecting host based state information using Velocidex Query Language (VQL) queries.
* [Wazuh](https://github.com/wazuh/wazuh) - Wazuh helps you to gain deeper security visibility into your infrastructure by monitoring hosts at an operating system and application level. 
* [Elastic Defend](https://www.elastic.co/docs/solutions/security/configure-elastic-defend/install-elastic-defend) - Endpoint protection and telemetry through an Elastic Agent integration managed by Fleet. Free and paid capabilities vary by [subscription](https://www.elastic.co/subscriptions). For Security Onion labs, follow its [Elastic Agent deployment guidance](https://docs.securityonion.net/en/2.4/elastic-agent.html) and check supported integrations for your version rather than assuming every response feature is included.
* [Windows Defender Exploit Guard](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/enable-exploit-protection) - Windows Defender Exploit Guard is built-in to professional edition and higher Windows machines. It includes process and memory level protection mechanisms with a suite of auditing capabilities. Exploit guard is not to be confused with Windows Defender Antivirus. It allows overriding security controls per process or folder and is controlled via an XML configuration file. The XML file is pushed via group policy or an asset management tool such as SCCM or Intunes.
* [Windows Ransomware Protection](https://support.microsoft.com/en-us/help/4013550/windows-protect-your-pc-from-ransomware) - Windows 10 includes a built-in ransomware protection that is off by default. It allows you to deploy it in monitor only mode as well as in blocking mode. It adds protection mechanisms around what user and process is accessing files on a system.
* [AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview) - Windows 10 Enterprise and Server Standard and above include AppLocker. AppLocker is Microsoft application whitelisting product. Other Windows versions do not have AppLocker but do have Software Restriction Policies.

## Windows Services
### Most require a Windows Standard Server License
* [PKI](https://timothygruber.com/pki/deploy-a-pki-on-windows-server-2016-part-1/) - Public Key Infrastructure is hard to deploy. Yet there are multiple guides online on how to deploy a Windows PKI. Also, you can configure it to automatically enroll user and device certificates for things like Smart Cards, Code Signing, and 802.11x port authentication (NAC stuff)
* [File Classification Infrastructure](https://docs.microsoft.com/en-us/windows-server/identity/solution-guides/deploy-automatic-file-classification--demonstration-steps-) - Windows servers support file classification. This can be manual or set up to automatically tag files so that access rules can be applied to them.
* [Dynamic Access Control](https://docs.microsoft.com/en-us/windows-server/identity/solution-guides/dynamic-access-control-overview) - DAC allows organizations to dynamically calculate access controls at the time of object access. This allows rules to include more conditions than just users and groups.
* [Active Directory Federation Services](https://docs.microsoft.com/en-us/windows-server/identity/active-directory-federation-services) - Windows Servers can be deployed as an ADFS server. ADFS allows for enterprise federation of user accounts to external applications and partners.
* [Windows Server Update Services](https://docs.microsoft.com/en-us/windows-server/administration/windows-server-update-services/get-started/windows-server-update-services-wsus) - WSUS is a service that allows you to control patching for Windows workstations and servers. It can be modified to include third party programs as well.
* [Remote Desktop](https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/welcome-to-rds) - Installing the remote desktop service within a Windows server allows for remote connectivity of one or more users. It can also be modified to work via a web browser or with application streaming.
* [Domain Controller](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview) - Active Directory is a key component of on-premise enterprise environments. Deploying one and understanding the multipe facets is extremely beneficial to cyber defenders. Areas to understand (group policy, users vs. computers vs. service accounts, single-sign on, DNS integration, replication, sites and services, forests, trusts, and domains)

## Log Management & Analytics
### OpenSource / Free

* [Elastic Stack](https://www.elastic.co/elastic-stack) - That's Elasticsearch, Kibana, Beats, and Logstash (also known as the ELK Stack). Reliably and securely take data from any source, in any format, then search, analyze, and visualize it in real time.
* [ElastAlert 2](https://github.com/jertel/elastalert2) - A maintained fork of Yelp's ElastAlert for alerting on anomalies, spikes, and other patterns in Elasticsearch and OpenSearch data. Security Onion uses ElastAlert 2 for Sigma-based alerting.
* [GrayLog](https://graylog.org/) - Graylog is a leading centralized log management solution built to open standards for capturing, storing, and enabling real-time analysis of terabytes of machine data.Purpose-built for modern log analytics, Graylog removes complexity from data exploration, compliance audits, and threat hunting so you can quickly and easily find meaning in data and take action faster.
* [Fleet](https://github.com/fleetdm/fleet) - FleetDM's platform for managing osquery and querying endpoint state across hosts. Use the current project rather than the archived Kolide Fleet repository; some management capabilities require a paid edition.
* [Windows Event Collector](https://docs.microsoft.com/en-us/windows/security/threat-protection/use-windows-event-forwarding-to-assist-in-intrusion-detection) - Windows servers can be configured as a Windows Event Collector. This allows it to receive Windows logs from other Windows devices without installing a third party agent. Group policy + Windows Event Collector = WIN!

## Detection Engineering
### OpenSource / Free

* [Sigma](https://github.com/SigmaHQ/sigma) - Shareable detection rules for log events. Use [sigma-cli](https://github.com/SigmaHQ/sigma-cli) and [pySigma](https://github.com/SigmaHQ/pySigma) with the appropriate backend and processing pipeline to convert rules for your SIEM.

## Windows Event Log Triage
### OpenSource / Free

* [Hayabusa](https://github.com/Yamato-Security/hayabusa) - Windows event log threat hunting and timeline generation using Sigma-based detection rules.
* [Chainsaw](https://github.com/WithSecureOpenSource/chainsaw) - Search and analyze Windows event logs using Sigma rules and built-in hunting capabilities.

## Deception & Honeypots
### OpenSource / Free

* [DShield Honeypot](https://github.com/DShield-ISC/dshield) - A sensor for collecting attack telemetry and contributing to the SANS Internet Storm Center's DShield project.
* [T-Pot](https://github.com/telekom-security/tpotce) - A multi-honeypot platform with integrated collection and visualization.
* [Cowrie](https://github.com/cowrie/cowrie) - An SSH and Telnet honeypot for observing login attempts and attacker interactions.
* [Canarytokens](https://canarytokens.org/) - Deception tokens that alert when monitored resources are accessed.

Keep honeypots and malware-analysis guests isolated from trusted networks. Restrict management access and outbound connectivity, and follow each project's deployment guidance before exposing services to the Internet.

## Email
### OpenSource / Free

* [Proxmox Mail Gateway](https://proxmox.com/en/proxmox-mail-gateway) - Proxmox Mail Gateway is the leading open-source email security solution helping you to protect your mail server against all email threats the moment they emerge. The flexible architecture combined with the userfriendly, web-based management interface allows IT professionals and businesses to control all incoming and outgoing emails with ease and to protect their users from spam, viruses, phishing and trojans.

## Proxy
### OpenSource / Free

* [Squid](http://www.squid-cache.org/) - Squid is a caching proxy for the Web supporting HTTP, HTTPS, FTP, and more. It reduces bandwidth and improves response times by caching and reusing frequently-requested web pages. Squid has extensive access controls and makes a great server accelerator. It runs on most available operating systems, including Windows and is licensed under the GNU GPL.
    - SSL Inspection - Squid is capable of doing SSL Inspection using a feature called SslBump Peek and Splice. This is supported in open source firewalls like pfSense.
* [BurpSuite](https://portswigger.net/burp) - BurpSuite has a free community edition and a professional edition. It is commonly known for web application penetration testing. However, it is great for blue teamers to test applications and understand how they work. This is especially helpful for putting in rules for web application firewalls or application load balancers.
* [OWASP ZAP Zed Attack Proxy](https://owasp.org/www-project-zap/) - OWASP ZAP is a free man-in-the-middle proxy. It is commonly known for web application penetration testing. However, it is great for blue teamers to test applications and understand how they work. This is especially helpful for putting in rules for web application firewalls or application load balancers.

## WAF
### OpenSource / Free

* [Modsecurity](https://modsecurity.org/) - ModSecurity is an open source, cross-platform web application firewall (WAF) module. Known as the "Swiss Army Knife" of WAFs, it enables web application defenders to gain visibility into HTTP(S) traffic and provides a power rules language and API to implement advanced protections.

## Load Balancing
### OpenSource / Free

* [HAProxy](http://www.haproxy.org/) - HAProxy is a free, very fast and reliable solution offering high availability, load balancing, and proxying for TCP and HTTP-based applications. It is particularly suited for very high traffic web sites and powers quite a number of the world's most visited ones. Over the years it has become the de-facto standard opensource load balancer, is now shipped with most mainstream Linux distributions, and is often deployed by default in cloud platforms.

## Sandbox
### OpenSource / Free

* [CAPEv2](https://github.com/kevoreilly/CAPEv2) - An automated malware-analysis sandbox derived from Cuckoo, with behavioral analysis and payload/configuration extraction. Prefer this maintained alternative to the archived `cuckoosandbox/cuckoo` repository for a new lab, and follow its isolation guidance.

## Threat Intelligence
### OpenSource / Free

* [MISP](https://github.com/MISP/MISP) - MISP is an open source software solution for collecting, storing, distributing and sharing cyber security indicators and threats about cyber security incidents analysis and malware analysis. MISP is designed by and for incident analysts, security and ICT professionals or malware reversers to support their day-to-day operations to share structured information efficiently.
* [YETI](https://github.com/yeti-platform/yeti) - Yeti is a platform meant to organize observables, indicators of compromise, TTPs, and knowledge on threats in a single, unified repository. Yeti will also automatically enrich observables (e.g. resolve domains, geolocate IPs) so that you don't have to. Yeti provides an interface for humans (shiny Bootstrap-based UI) and one for machines (web API) so that your other tools can talk nicely to it.Yeti was born out of frustration of having to answer the question "where have I seen this artifact before?" or Googling shady domains to tie them to a malware family.
* [AIL framework](https://github.com/CIRCL/AIL-framework) - AIL is a modular framework to analyse potential information leaks from unstructured data sources like pastes from Pastebin or similar services or unstructured data streams. AIL framework is flexible and can be extended to support other functionalities to mine or process sensitive information (e.g. data leak prevention).

## IR Case Management & Orchestration
### OpenSource / Free

* [TheHive](https://docs.strangebee.com/thehive/overview/) - StrangeBee's incident response and case-management platform. The old `TheHive-Project/TheHive` repository is archived. The current free Community Edition is intended for non-commercial use, including personal home labs, and requires requesting and activating a license; paid plans add capabilities. Review [current plans, quotas, and licensing](https://docs.strangebee.com/thehive/installation/licenses/about-licenses/) rather than assuming the old open-source licensing still applies.
* [Cortex](https://github.com/TheHive-Project/Cortex) - Cortex tries to solve a common problem frequently encountered by SOCs, CSIRTs and security researchers in the course of threat intelligence, digital forensics and incident response: how to analyze observables they have collected, at scale, by querying a single tool instead of several? Cortex, an open source and free software, has been created by TheHive Project for this very purpose. Observables, such as IP and email addresses, URLs, domain names, files or hashes, can be analyzed one by one or in bulk mode using a Web interface. Analysts can also automate these operations thanks to the Cortex REST API.

## Network Discovery & Vulnerability Management
* [runZero](https://www.runzero.com/) - Formerly Rumble, an asset-discovery and inventory platform. Check the current Community Edition limits and licensing for your lab.
* [Greenbone Community Edition / OpenVAS](https://greenbone.github.io/docs/latest/) - An open-source vulnerability-management stack incorporating the OpenVAS scanner. Follow the Community Edition documentation for supported deployment options and feed setup; OpenVAS is the scanner component, not the entire management platform.

## Hardware
* [ASUS NUC](https://www.asus.com/displays-desktops/nucs/nuc-mini-pcs/) - Small-form-factor PCs for compact home labs, continuing the NUC product line originally developed by Intel. Check memory capacity, network interfaces, and hypervisor compatibility before buying.
* [Mikrotik](https://mikrotik.com/products) - MikroTik  provides hardware and software for Internet connectivity in most of the countries around the world. MikroTik maintani the RouterOS software system that provides extensive stability, controls, and flexibility for all kinds of data interfaces and routing.
* [Raspberry Pi](https://www.raspberrypi.org/) - The Raspberry Pi (/paɪ/) is a series of small single-board computers developed in the United Kingdom by the Raspberry Pi Foundation to promote teaching of basic computer science in schools and in developing countries.
* [Supermicro Edge & IoT](https://www.supermicro.com/en/products/edge/servers) - Compact and rackmount systems for edge deployments. Check each model's cooling, noise, and power requirements for home-lab use.
* [Ebay](https://www.ebay.com/) - Ebay is a common place to buy used equipment. For example, you can usually find an HP Z620 for around $500 with 16 CPU cores and between 64 and 96 GB of RAM.

## Virtualization & Containers
### OpenSource / Free
* [VMWare ESXi](https://www.vmware.com/products/esxi-and-esx.html) - A robust, bare-metal hypervisor that installs directly onto your physical server. With direct access to and control of underlying resources, VMware ESXi effectively partitions hardware to consolidate applications and cut costs.
* [Docker](https://www.docker.com/) - A container is a standard unit of software that packages up code and all its dependencies so the application runs quickly and reliably from one computing environment to another. A Docker container image is a lightweight, standalone, executable package of software that includes everything needed to run an application: code, runtime, system tools, system libraries and settings. The official Docker install guide is found here: https://docs.docker.com/get-docker. Docker swarm is built-in to Docker and allows multi-host docker networks. Kubernetes is a more advanced implementation that is also free.
* [Proxmox VE](https://proxmox.com/en/proxmox-ve) - Proxmox VE is a complete open-source platform for all-inclusive enterprise virtualization that tightly integrates KVM hypervisor and LXC containers, software-defined storage and networking functionality on a single platform, and easily manages high availability clusters and disaster recovery tools with the built-in web management interface. The enterprise-class features and the 100% software-based focus make Proxmox VE the perfect choice to virtualize your IT infrastructure, optimize existing resources, and increase efficiencies with minimal expense.
* [Hyper-V](https://docs.microsoft.com/en-us/windows-server/virtualization/hyper-v/hyper-v-technology-overview) - Microsoft Hyper-V is not exactly free. If you own a Windows Pro, Enterprise, or Education license then Hyper-V is included. If you using a Windows Server standard or enterprise license then you have access to enterprise features within Hyper-V. Hyper-V is a solid hypervisor. It also provides special endpoint security features via Device Guard and Credential Guard.

## DevSecOps

* [Terraform](https://github.com/hashicorp/terraform) - Terraform enables you to safely and predictably create, change, and improve infrastructure. It is an open source tool that codifies APIs into declarative configuration files that can be shared amongst team members, treated as code, edited, reviewed, and versioned.
* [Ansible](https://github.com/ansible/ansible) - Ansible is a radically simple IT automation platform that makes your applications and systems easier to deploy. Avoid writing scripts or custom code to deploy and update your applications — automate in a language that approaches plain English, using SSH, with no agents to install on remote systems.
* [Packer](https://github.com/hashicorp/packer) - Packer is a tool for creating identical machine images for multiple platforms from a single source configuration

## AV

* [ClamAV](https://www.clamav.net/) - ClamAV® is an open source antivirus engine for detecting trojans, viruses, malware & other malicious threats.

## OS & Linux Distros

* [Windows 11 Enterprise Evaluation](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise) - A time-limited desktop evaluation for endpoint telemetry, policy, and detection labs. Check hardware requirements and evaluation terms before installing.
* [Windows Server 2025 Evaluation](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2025) - A time-limited server evaluation for Active Directory and other Windows service labs. Standard Windows 10 Enterprise 22H2 support ended on October 14, 2025; LTSC and Extended Security Updates have separate terms and lifecycles.
* [Visual Studio Professional Subscription](https://visualstudio.microsoft.com/vs/pricing/) - Monthly subscription that provides Windows licenses for lab use.
* [Kali](https://www.kali.org/) - Kali Linux is an open source project that is maintained and funded by Offensive Security. Kali Linux has over 600 preinstalled penetration-testing programs, including Armitage (a graphical cyber attack management tool), Nmap (a port scanner), Wireshark (a packet analyzer), John the Ripper (a password cracker), Aircrack-ng (a software suite for penetration-testing wireless LANs), Burp suite and OWASP ZAP web application security scanners.
* [Alpine](https://alpinelinux.org/) - Small. Simple. Secure. Alpine Linux is a security-oriented, lightweight Linux distribution based on musl libc and busybox.
* [Ubuntu](https://ubuntu.com/) - Ubuntu is a free and open-source Linux distribution based on Debian. Ubuntu is officially released in three editions: Desktop, Server, and Core for the internet of things devices and robots. All the editions can run on the computer alone, or in a virtual machine.

## Adversary Emulation

* [MITRE CALDERA](https://github.com/mitre/caldera) - CALDERA is a cyber security framework designed to easily run autonomous breach-and-simulation exercises. It can also be used to run manual red-team engagements or automated incident response.
* [Atomic Red Teaming](https://atomicredteam.io/) - Atomic Red Team is a library of simple tests that every security team can execute to test their defenses. Tests are focused, have few dependencies, and are defined in a structured format that can be used by automation frameworks.
* [Infection Monkey](https://github.com/guardicore/monkey) - The Infection Monkey is an open source Breach and Attack Simulation (BAS) tool that assesses the resiliency of private and public cloud environments to post-breach attacks and lateral movement.

## Lab Gotchas

* **SPAN capacity and capture loss:** Mirroring both directions of a fully utilized 1 GbE link can send up to 2 Gb/s toward a 1 GbE monitoring port. Monitor switch drops, sensor capture statistics, and Zeek notices such as `CaptureLoss::Too_Much_Loss`. Reduce mirrored traffic or provision sufficient capture bandwidth and processing capacity. A TAP can improve visibility, but an aggregated TAP output can still oversubscribe the capture interface.
* **Validate Sigma rules end to end:** Security Onion's [Sigma integration](https://docs.securityonion.net/en/2.4/sigma.html) converts rules to backend queries and uses ElastAlert 2 for alerting. Use the backend and processing pipelines matching your installed version, inspect the converted query, and execute it against representative events. Test field types, supported modifiers, missing fields, and negation explicitly, then confirm the expected alert arrives and review errors. Successful YAML validation or query conversion alone does not establish detection correctness; record affected versions and reproductions before treating a limitation as universal.

## Legacy & Archived Resources

These are retained for historical research, not recommended as default choices for new deployments. A long period without repository activity does not by itself prove a project is abandoned; verify compatibility and maintenance before use.

* [RockNSM](https://github.com/rocknsm/rock) - Legacy network-security monitoring platform; repository last pushed in July 2023 when checked for this refresh.
* [The Hunting ELK, HELK](https://github.com/Cyb3rWard0g/HELK) - Research-oriented hunting platform; repository last pushed in June 2024 when checked for this refresh.
* [Metta](https://github.com/uber-common/metta) - Adversary-simulation framework; repository last pushed in April 2019 when checked for this refresh.
* [Viper](https://github.com/viper-framework/viper) - Archived binary-analysis and sample-management framework.

## Related Resource Collections

* [BlueTeam-Tools](https://github.com/A-poc/BlueTeam-Tools) - A broader collection of blue-team and incident-response tools and techniques. Evaluate individual entries for maintenance, licensing, and suitability for an isolated home lab.

## Other

* [Apache NiFi](https://nifi.apache.org/) - An easy to use, powerful, and reliable system to process and distribute data.

## Contributing & Maintenance

Suggest a resource or correction through an issue or pull request. Include its canonical upstream URL, a short description of the lab use case, maintenance status, and any free-edition limits, licensing requirements, or hardware prerequisites. Prefer maintained projects; clearly label archived or legacy entries rather than presenting them as current defaults.

For version-specific problems, include the product version, expected and actual behavior, and a minimal reproduction without credentials or personal data. Check for an existing entry or issue before proposing an addition.

The [link-check workflow](.github/workflows/links.yml) runs on pull requests, pushes, a weekly schedule, and manual dispatch. Maintainers should review its failures and periodically recheck project activity, licensing, and descriptions: a working URL does not establish that a project is maintained. Bot-blocked sites must be checked manually; document any narrowly scoped exclusions rather than ignoring all HTTP errors.

To reproduce the check locally with [lychee](https://github.com/lycheeverse/lychee), run `lychee --config lychee.toml "**/*.md"` from the repository root.
