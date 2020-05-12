# Great List of Resources to Build an Enterprise Grade Home Lab

Based on the Blue Team series of webinars: ['Becoming an All-Around Defender'](https://www.sans.org/blog/becoming-an-all-around-defender/) by [Security 530](https://www.sans.org/course/defensible-security-architecture-and-engineering) co-authors Ismael Valenzuela [@aboutsecurity](https://twitter.com/aboutsecurity) & Justin Henderson [@securitymapper](https://twitter.com/securitymapper?lang=en)

## Network
### OpenSource / Free

* [Zeek](https://zeek.org/) - A powerful framework for network traffic analysis and security monitoring.
* [Suricata](https://suricata-ids.org/) - Suricata is a free and open source, mature, fast and robust network threat detection engine.The Suricata engine is capable of real time intrusion detection (IDS), inline intrusion prevention (IPS), network security monitoring (NSM) and offline pcap processing.
    - [EveBox](https://evebox.org/) - Web GUI for analyzing Suricata EVE logs. Removes need for SIEM or other interface although a SIEM still allows for more granular control and augmentation
    - [Scirius](https://github.com/StamusNetworks/scirius) - GUI for managing Suricata rules
* [SecurityOnion](https://securityonion.net/) - Security Onion is a free and open source Linux distribution for threat hunting, enterprise security monitoring, and log management. It includes Elasticsearch, Logstash, Kibana, Snort, Suricata, Zeek (formerly known as Bro), Wazuh, Sguil, Squert, CyberChef, NetworkMiner, and many other security tools. The easy-to-use Setup wizard allows you to build an army of distributed sensors for your enterprise in minutes!
* [Moloch](https://molo.ch/) - Moloch augments your current security infrastructure to store and index network traffic in standard PCAP format, providing fast, indexed access. An intuitive and simple web interface is provided for PCAP browsing, searching, and exporting. Moloch is built to be deployed across many systems and can scale to handle tens of gigabits/sec of traffic.
* [Pi-hole](https://pi-hole.net/) - The Pi-hole® is a DNS sinkhole that protects your devices from unwanted content, without installing any client-side software.
* [pfSense](https://github.com/pfsense/pfsense) - Firewall and Router FreeBSD distribution. pfSense started in 2004 as a fork of the m0n0wall Project (which ended 2015/02/15), though has diverged significantly since.
    - Supports SSL/TLS Inspection via Squid SslBump
    - Supports network antivirus
    - Supports VPN
    - Supports IDS/IPS
* [Opnsense](https://opnsense.org/) - OPNsense is an open source, easy-to-use and easy-to-build HardenedBSD based firewall and routing platform. OPNsense includes most of the features available in expensive commercial firewalls, and more in many cases. It brings the rich feature set of commercial offerings with the benefits of open and verifiable sources.OPNsense started as a fork of pfSense® and m0n0wall in 2014, with its first official release in January 2015. The project has evolved very quickly while still retaining  familiar aspects of both m0n0wall and pfSense. A strong focus on security and code quality drives the development of the project.
* [WireGuard](https://www.wireguard.com/) - WireGuard® is an extremely simple yet fast and modern VPN that utilizes state-of-the-art cryptography. It aims to be faster, simpler, leaner, and more useful than IPsec, while avoiding the massive headache. It intends to be considerably more performant than OpenVPN.
* [PacketFence](https://packetfence.org/) - PacketFence is a fully supported, trusted, Free and Open Source network access control (NAC) solution. Boasting an impressive feature set including a captive-portal for registration and remediation, centralized wired, wireless and VPN management, industry-leading BYOD capabilities, 802.1X and RBAC support, integrated network anomaly detection with layer-2 isolation of problematic devices; PacketFence can be used to effectively secure small to very large heterogeneous networks.
* [RockNSM](https://rocknsm.io/) - ROCK is a collections platform, in the spirit of Network Security Monitoring by contributors from all over industry and the public sector. It's primary focus is to provide a robust, scalable sensor platform for both enduring security monitoring and incident response missions. The platform consists of 3 core capabilities, (1) passive data acquisition via AF_PACKET, feeding systems for metadata (Zeek), signature detection (Suricata), and full packet capture (Stenographer), (2) a messaging layer (Kafka and Logstash) that provides flexibility in scaling the platform to meet operational needs, as well as providing some degree of data reliability in transit, and (3) reliable data storage and indexing (Elasticsearch) to support rapid retrieval and analysis (Kibana) of the data.

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

## Log Management & Analytics
### OpenSource / Free

* [Elastic Stack](https://www.elastic.co/elastic-stack) - That's Elasticsearch, Kibana, Beats, and Logstash (also known as the ELK Stack). Reliably and securely take data from any source, in any format, then search, analyze, and visualize it in real time.
* [The Hunting ELK, HELK](https://github.com/Cyb3rWard0g/HELK) - The Hunting ELK or simply the HELK is one of the first open source hunt platforms with advanced analytics capabilities such as SQL declarative language, graphing, structured streaming, and even machine learning via Jupyter notebooks and Apache Spark over an ELK stack. This project was developed primarily for research, but due to its flexible design and core components, it can be deployed in larger environments with the right configurations and scalable infrastructure.
* [Elastalert](https://github.com/Yelp/elastalert) - ElastAlert is a simple framework for alerting on anomalies, spikes, or other patterns of interest from data in Elasticsearch.
* [GrayLog](https://www.graylog.org/) - Graylog is a leading centralized log management solution built to open standards for capturing, storing, and enabling real-time analysis of terabytes of machine data.Purpose-built for modern log analytics, Graylog removes complexity from data exploration, compliance audits, and threat hunting so you can quickly and easily find meaning in data and take action faster.
* [Kolidee Fleet](https://www.kolide.com/fleet/) - Open Source Osquery Manager. Expand osquery capabilities from a single machine to your entire fleet. Query dynamic sets of hosts, and watch the data stream in for immediate analysis and investigation. Export results for a closer look in your favorite tools.

## Email
### OpenSource / Free

* [Proxmox Mail Gateway](https://proxmox.com/en/proxmox-mail-gateway) - Proxmox Mail Gateway is the leading open-source email security solution helping you to protect your mail server against all email threats the moment they emerge. The flexible architecture combined with the userfriendly, web-based management interface allows IT professionals and businesses to control all incoming and outgoing emails with ease and to protect their users from spam, viruses, phishing and trojans.

## Proxy
### OpenSource / Free

* [Squid](http://www.squid-cache.org/) - Squid is a caching proxy for the Web supporting HTTP, HTTPS, FTP, and more. It reduces bandwidth and improves response times by caching and reusing frequently-requested web pages. Squid has extensive access controls and makes a great server accelerator. It runs on most available operating systems, including Windows and is licensed under the GNU GPL.
    - SSL Inspection - Squid is capable of doing SSL Inspection using a feature called SslBump Peek and Splice. This is supported in open source firewalls like pfSense.

## Load Balancing
### OpenSource / Free

* [HAProxy](http://www.haproxy.org/) - HAProxy is a free, very fast and reliable solution offering high availability, load balancing, and proxying for TCP and HTTP-based applications. It is particularly suited for very high traffic web sites and powers quite a number of the world's most visited ones. Over the years it has become the de-facto standard opensource load balancer, is now shipped with most mainstream Linux distributions, and is often deployed by default in cloud platforms.

## Sandbox
### OpenSource / Free

* [Cuckoo's Sandbox](https://cuckoosandbox.org/)  - Cuckoo Sandbox is the leading open source automated malware analysis system. You can throw any suspicious file at it and in a matter of minutes Cuckoo will provide a detailed report outlining the behavior of the file when executed inside a realistic but isolated environment.

## Threat Intelligence
### OpenSource / Free

* [MISP](https://github.com/MISP/MISP) - MISP is an open source software solution for collecting, storing, distributing and sharing cyber security indicators and threats about cyber security incidents analysis and malware analysis. MISP is designed by and for incident analysts, security and ICT professionals or malware reversers to support their day-to-day operations to share structured information efficiently.
* [AIL framework](https://github.com/CIRCL/AIL-framework) - AIL is a modular framework to analyse potential information leaks from unstructured data sources like pastes from Pastebin or similar services or unstructured data streams. AIL framework is flexible and can be extended to support other functionalities to mine or process sensitive information (e.g. data leak prevention).
* [Viper](https://github.com/viper-framework/viper) - Viper is a binary analysis and management framework. Its fundamental objective is to provide a solution to easily organize your collection of malware and exploit samples as well as your collection of scripts you created or found over the time to facilitate your daily research.

## IR Case Management & Orchestration
### OpenSource / Free

* [TheHive](https://github.com/TheHive-Project/TheHive) - A scalable, open source and free Security Incident Response Platform, tightly integrated with MISP (Malware Information Sharing Platform), designed to make life easier for SOCs, CSIRTs, CERTs and any information security practitioner dealing with security incidents that need to be investigated and acted upon swiftly.
* [Cortex](https://github.com/TheHive-Project/Cortex) - Cortex tries to solve a common problem frequently encountered by SOCs, CSIRTs and security researchers in the course of threat intelligence, digital forensics and incident response: how to analyze observables they have collected, at scale, by querying a single tool instead of several? Cortex, an open source and free software, has been created by TheHive Project for this very purpose. Observables, such as IP and email addresses, URLs, domain names, files or hashes, can be analyzed one by one or in bulk mode using a Web interface. Analysts can also automate these operations thanks to the Cortex REST API.

## Network Discovery & Vulnerability Management
* [Rumble](https://www.rumble.run/) - Rumble is fast and identifies assets without the need for credentials or special access. A single agent can assess an entire enterprise, or multiple agents can be used to limit cross-site traffic. Discover networks, large or small, in a fraction of the time required by legacy tools.
* [OpenVAS](https://www.openvas.org/) - OpenVAS is a full-featured vulnerability scanner. Its capabilities include unauthenticated testing, authenticated testing, various high level and low level Internet and industrial protocols, performance tuning for large-scale scans and a powerful internal programming language to implement any type of vulnerability test.

## WAF
### OpenSource / Free

* [Modsecurity](https://modsecurity.org/) - ModSecurity is an open source, cross-platform web application firewall (WAF) module. Known as the "Swiss Army Knife" of WAFs, it enables web application defenders to gain visibility into HTTP(S) traffic and provides a power rules language and API to implement advanced protections.

## Hardware
* [Intel NUC](https://www.intel.com/content/www/us/en/products/boards-kits/nuc.html) - Intel® NUC is a small form factor PC with a tiny footprint. Short for Next Unit of Computing, Intel® NUC (say it like “luck” or “truck”) puts full-sized PC power in the palm of your hand.
* [Mikrotik](https://mikrotik.com/products) - MikroTik  provides hardware and software for Internet connectivity in most of the countries around the world. MikroTik maintani the RouterOS software system that provides extensive stability, controls, and flexibility for all kinds of data interfaces and routing.
* [Raspberry Pi](https://www.raspberrypi.org/) - The Raspberry Pi (/paɪ/) is a series of small single-board computers developed in the United Kingdom by the Raspberry Pi Foundation to promote teaching of basic computer science in schools and in developing countries.
* [Supermicro Fanless & IoT](https://www.supermicro.com/en/products/embedded/servers) - Optimized systems designed for reliable, quiet operation in tight spaces.

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

* [Windows Evaluation Images](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise) - 90 day evaluations of Windows 10 Enterprise. To download the Windows 10 Enterprise 90-day trial edition, click the Sign in link at the top to log in with your Microsoft account.
* [Visual Studio Professional Subscription](https://visualstudio.microsoft.com/vs/pricing/) - Monthly subscription that provides Windows licenses for lab use.
* [Kali](https://www.kali.org/) - Kali Linux is an open source project that is maintained and funded by Offensive Security. Kali Linux has over 600 preinstalled penetration-testing programs, including Armitage (a graphical cyber attack management tool), Nmap (a port scanner), Wireshark (a packet analyzer), John the Ripper (a password cracker), Aircrack-ng (a software suite for penetration-testing wireless LANs), Burp suite and OWASP ZAP web application security scanners.
* [Alpine](https://alpinelinux.org/) - Small. Simple. Secure. Alpine Linux is a security-oriented, lightweight Linux distribution based on musl libc and busybox.
* [Ubuntu](https://ubuntu.com/) - Ubuntu is a free and open-source Linux distribution based on Debian. Ubuntu is officially released in three editions: Desktop, Server, and Core for the internet of things devices and robots. All the editions can run on the computer alone, or in a virtual machine.

## Adversary Emulation

* [MITRE CALDERA](https://github.com/mitre/caldera) - CALDERA is a cyber security framework designed to easily run autonomous breach-and-simulation exercises. It can also be used to run manual red-team engagements or automated incident response.
* [Atomic Red Teaming](https://atomicredteam.io/) - Atomic Red Team is a library of simple tests that every security team can execute to test their defenses. Tests are focused, have few dependencies, and are defined in a structured format that can be used by automation frameworks.
* [Infection Monkey](https://www.guardicore.com/infectionmonkey/) - The Infection Monkey is an open source Breach and Attack Simulation (BAS) tool that assesses the resiliency of private and public cloud environments to post-breach attacks and lateral movement.
* [Metta](https://github.com/uber-common/metta) - Metta is an information security preparedness tool. This project uses Redis/Celery, python, and vagrant with virtualbox to do adversarial simulation. This allows you to test (mostly) your host based instrumentation but may also allow you to test any network based detection and controls depending on how you set up your vagrants. The project parses yaml files with actions and uses celery to queue these actions up and run them one at a time without interaction.

## Other

* [Apache NiFi]() - An easy to use, powerful, and reliable system to process and distribute data.
