# GXPN — Indexed Terms

This file contains a consolidated list of indexed terms associated with advanced exploitation, reverse engineering, fuzzing, cryptography, networking, and runtime analysis.  
The list represents vocabulary only and does not include procedures, labs, commands, tools, or environment-specific details.

---

## Symbols

### **/GS**
↳ Labs: 5.1, 5.3  
↳ Related: DEP, W^X, Mitigation Controls

### **W^X**
↳ Labs: 4.2, 4.6, 5.3, 5.4  
↳ Related: DEP, NX Bit, ROP

### **XD / ED Bit**
↳ Related: DEP, NX Bit

---

## A

### **802.1Q**
↳ Labs: 1.2  
↳ Related: DTP, VLAN Participation, VLAN Hopping, CDP, Yersinia, Voice VLAN

### **802.1X**
↳ Labs: 1.2, 2.1  
↳ Related: NAC, RADIUS, EAP Shadow, User Impersonation

### **Accumulator Register (EAX/RAX)**
↳ Labs: 4.1, 4.3  
↳ Related: General-Purpose Registers, Calling Conventions

### **Address Space Layout Randomization (ASLR)**
↳ Labs: 4.3, 4.4, 4.6, 5.2, 5.3, 6.1  
↳ Related: Canaries, Stack Protection, Security Cookies, PIE, DEP

### **Advanced**
↳ Related: Post Exploitation

### **AES**
↳ Labs: 2.1  
↳ Related: Cryptography, CBC, OpenSSL

### **Alternative Payloads**
↳ Labs: 4.5, 6.1  
↳ Related: Library Loading, Environment Variables

### **American Fuzzy Lop (AFL)**
↳ Labs: 3.5  
↳ Related: Fuzzing, Sulley, BooFuzz, Code Coverage, DynamoRIO, WinAFL

### **AMSI**
↳ Labs: 2.5  
↳ Related: UAC, WDAC, Obfuscation, Sharpkiller

### **AppArmor**
↳ Related: SELinux

### **AppLocker**
↳ Labs: 2.6  
↳ Related: WDAC, Software Restriction Policy

### **ARP Spoofing**
↳ Labs: 1.3  
↳ Related: MITM, Ettercap, Responder

---

## B

### **Backup Designated Router (BDR)**
↳ Labs: 1.6  
↳ Related: OSPF

### **BetterCap**
↳ Labs: 1.3, 1.5  
↳ Related: Ettercap, MITM, Scapy, mitmproxy, sslstrip

### **BGP**
↳ Related: Routing Protocols

### **Blowfish**
↳ Related: Cryptography

### **BooFuzz**
↳ Labs: 3.4  
↳ Related: Fuzzing, Sulley, Code Coverage, AFL

### **brk()**
↳ Related: Heap, Memory Allocation

### **Browser Caching**
↳ Related: HTTP Headers

### **Brute-Forcing ASLR**
↳ Labs: 4.4  
↳ Related: ASLR, Probabilistic Exploitation

### **Bypassing NX Bit / W^X / DEP**
↳ Labs: 4.2, 4.6, 5.3, 5.4  
↳ Related: DEP, NX Bit, ROP

---

## C

### **C2**
↳ Related: Post Exploitation, Empire

### **Cain**
↳ Related: Credential Capture, HTTP Authentication

### **Calling Conventions**
↳ Labs: 4.1, 5.1  
↳ Related: Stack Operations, Registers

### **Canaries**
↳ Labs: 4.1, 5.2  
↳ Related: Stack Protection, Linux Stack Protection, Security Cookies

### **Captive Portal**
↳ Labs: 1.2  
↳ Related: NAC, TCP OS Fingerprinting, OSfuscate, Scapy, VLAN Manipulation, sslstrip

### **captive portal scam**
↳ Labs: 1.2  
↳ Related: Captive Portal

### **chunk**
↳ Related: IPv6, Heap, Low Fragmentation Heap

### **Cipher Block Chaining (CBC)**
↳ Labs: 2.2  
↳ Related: Padding Oracle, Cryptography

### **Cisco Discovery Protocol (CDP)**
↳ Related: DTP, Yersinia, Voice VLAN

### **Cloud-Based Cracking**
↳ Related: Password Attacks

### **Code Coverage**
↳ Labs: 3.2  
↳ Related: Fuzzing, AFL, Sulley, BooFuzz, DynamoRIO

### **Code Segment (CS)**
↳ Related: Stack Operations, ROP, W^X

### **Control Flow Guard (CFG)**
↳ Labs: 5.1  
↳ Related: Control Flow Integrity, Mitigation Controls

### **Control Flow Integrity (CFI)**
↳ Related: CFG, Exploit Mitigation

### **Control Registers**
↳ Related: Instruction Pointer

### **Counter (CTR)**
↳ Labs: 2.1  
↳ Related: ECB, CBC, Cryptography

### **CPU Modes**
↳ Related: Processor Access Modes

### **cpscam**
↳ Related: Captive Portal

### **crashbin_explorer.py**
↳ Labs: 3.4  
↳ Related: Fuzzing, Crash Analysis

### **crypto**
↳ Related: Cryptography

## D

### **Data Encryption Standard (DES)**
↳ Related: Cryptography, Symmetric Encryption

### **Data Execution Prevention (DEP)**
↳ Labs: 5.1, 5.3, 5.4  
↳ Related: SafeSEH, ASLR, Exploit Guard, ROP, Gadgets, VirtualProtect, NX Bit, W^X

### **Data Register (EDX/RDX)**
↳ Related: General-Purpose Registers

### **Data Segment (DS)**
↳ Related: Segment Registers, Object Files, W^X

### **Debugging**
↳ Labs: 4.1, 5.1, 6.1  
↳ Related: GNU Debugger (GDB), ROP, Gadgets, Stack Protection

### **Denial of Service (DoS)**
↳ Related: Fuzzing, Bug Discovery

### **Designated Router (DR)**
↳ Related: OSPF, Routing Protocols

### **dlmalloc**
↳ Related: Heap, Safe Unlinking, unlink()

### **Dlhell.py**
↳ Related: Library Loading, DLL Hijacking

### **Donut**
↳ Related: Shellcode, Payload Delivery

### **Drcov**
↳ Labs: 3.2  
↳ Related: Code Coverage, DynamoRIO, dynapstalker

### **Drrun**
↳ Labs: 3.2  
↳ Related: DynamoRIO, Code Coverage

### **Dynamic Host Configuration Protocol (DHCP)**
↳ Related: Network Access Control, IPv6, Fuzzing, Yersinia

### **Dynamic Link Libraries (DLLs)**
↳ Related: Library Loading, Shellcode, kernel32.dll, PE/COFF

### **Dynamic Trunking Protocol (DTP)**
↳ Related: VLAN Attacks, Yersinia

### **Dynamips**
↳ Related: Router Emulation, OSPF

### **DynamoRIO**
↳ Labs: 3.2  
↳ Related: Code Coverage, drcov, dynapstalker

### **dynapstalker**
↳ Labs: 3.2  
↳ Related: Code Coverage, DynamoRIO, drcov

---

## E

### **eapmd5fuzzies.py**
↳ Related: 802.1X, EAP

### **EAP Shadow Attack**
↳ Related: 802.1X, User Impersonation

### **EAP Type**
↳ Related: 802.1X, RADIUS

### **EAX/RAX**
↳ Related: General-Purpose Registers, Object Files

### **EDX/RDX**
↳ Related: General-Purpose Registers

### **ECX/RCX**
↳ Related: General-Purpose Registers

### **EBX/RBX**
↳ Related: General-Purpose Registers

### **EDR**
↳ Related: Defense Evasion, Post Exploitation

### **EGG Hunting**
↳ Labs: 5.3, 5.4  
↳ Related: Shellcode, Memory Corruption

### **Electronic Codebook (ECB)**
↳ Related: Cryptography, Block Ciphers

### **Empire**
↳ Related: C2, Post Exploitation

### **Ent (tool)**
↳ Related: Entropy Analysis, Cryptography

### **Environment Variable Shellcode Injection**
↳ Labs: 6.1  
↳ Related: Shellcode, Memory Corruption

### **Enhanced Mitigation Experience Toolkit (EMET)**
↳ Related: Exploit Guard, Mitigation Controls, DEP, ASLR

### **Escalation Tools**
↳ Related: Privilege Escalation, Post Exploitation

### **ESI/RSI**
↳ Related: General-Purpose Registers

### **EDI/RDI**
↳ Related: General-Purpose Registers

### **ESP/RSP**
↳ Related: Stack Pointer, Stack Operations

### **EBP/RBP**
↳ Related: Stack Frame, Calling Conventions

### **Ettercap**
↳ Labs: 1.3  
↳ Related: MITM, ARP Spoofing, sslstrip, Responder

### **Executable and Linking Format (ELF)**
↳ Labs: 4.1, 4.2  
↳ Related: PIE, PLT, GOT, Library Loading

### **Exploit Guard**
↳ Related: EMET, DEP, ASLR, ROP, Mitigation Controls

### **Export Address Table**
↳ Related: PE/COFF, ELF

### **Exploit Mitigation**
↳ Labs: 5.1, 5.2  
↳ Related: EMET, Exploit Guard

### **Exploit Suggester**
↳ Related: Vulnerability Assessment

### **Extra Segment (ES)**
↳ Related: Segment Registers, Object Files

---

## F

### **Final Snapshot (VMs)**
↳ Related: Lab Environment Management

### **FLAGS Registers**
↳ Related: General-Purpose Registers, Segment Registers

### **free()**
↳ Related: Heap, MemGC, MemProtect

### **Fuzzing**
↳ Labs: 3.4, 3.5  
↳ Related: Sulley, BooFuzz, Code Coverage, AFL

---

## G

### **Gadgets**
↳ Labs: 5.3, 5.4  
↳ Related: ROP, DEP, Shellcode, VirtualProtect

### **Gcc**
↳ Labs: 6.1  
↳ Related: GNU Debugger, Binary Compilation

### **Getenv()**
↳ Labs: 4.5  
↳ Related: Environment Variables, Shellcode

### **General-Purpose Registers**
↳ Related: Segment Registers, FLAGS Registers

### **GetProcAddress()**
↳ Related: Shellcode, Lazy Linking, PEB

### **GNU Debugger (GDB)**
↳ Labs: 4.1, 6.1  
↳ Related: Debugging, ROP, Gadgets, Stack Protection

### **Group Policy Objects**
↳ Related: Windows Security Controls

### **Grsecurity**
↳ Related: Kernel Hardening, Control Flow Protection

## H

### **Hash Extender**
↳ Labs: 2.3  
↳ Related: Hash Length Extension, Cryptography

### **Hash Identification**
↳ Related: Cryptography, Entropy Analysis

### **Heap**
↳ Labs: 4.5  
↳ Related: ASLR, PIE, Heap Cookies, Heap Spray, Low Fragmentation Heap, Kernel Hardening

### **Heap Cookies**
↳ Related: Heap, Heap Protection

### **Heap Spray**
↳ Related: Heap, Memory Corruption

### **Hot Standby Router Protocol (HSRP)**
↳ Related: Routing Protocols, Yersinia, VRRP

### **http_hijack.py**
↳ Related: HTTP Manipulation, MITM

### **HTTP Strict Transport Security (HSTS)**
↳ Related: HTTPS, SSL Stripping, Browser Security

---

## I

### **IDA Pro**
↳ Related: Reverse Engineering, Code Coverage

### **IDA sploiter**
↳ Related: ROP, Exploit Development

### **ifconfig**
↳ Related: Network Enumeration

### **Immunity Debugger**
↳ Labs: 5.1, 5.2, 5.3, 5.4  
↳ Related: Debugging, Windows Exploitation

### **Integers**
↳ Related: Fuzzing, Integer Overflows, Underflows

### **Initialization Vector (IV)**
↳ Related: Cryptography, CBC

### **IPv6**
↳ Related: Network Attacks, Scapy, modprobe

### **Instruction Pointer**
↳ Related: Control Registers, Execution Flow

### **IV Collision**
↳ Related: Padding Oracle, POODLE, CBC Bit Flip, Hash Extender

---

## J

### **JavaScript OS Validation**
↳ Related: OS Fingerprinting, Web Security

---

## K

### **kernel32.dll**
↳ Related: Shellcode, DLLs, Lazy Linking, Windows API

### **Kernel Hardening**
↳ Related: Mitigation Controls, Exploit Guard

---

## L

### **LAN Manipulation**
↳ Related: MITM, VLAN Attacks

### **Lazy Linking**
↳ Related: PLT, GOT, Library Loading

### **LD_LIBRARY_PATH**
↳ Related: Library Loading, Linux Runtime Linking

### **LD_PRELOAD**
↳ Related: Library Injection, Linux Exploitation

### **LdrpCheckNXCompatibility**
↳ Related: DEP, NX Bit

### **ldd**
↳ Related: ASLR, Library Loading

### **Library Loading**
↳ Related: DLL Hijacking, Shellcode

### **Link State Advertisements (LSAs)**
↳ Related: OSPF, Routing Protocols

### **Linker**
↳ Related: Loader, PLT, GOT

### **linux-gate.so.1**
↳ Related: ASLR, ELF

### **Linux Stack Protection**
↳ Related: Stack Protection

### **Loader**
↳ Related: Linker, Object Files

### **Loki**
↳ Related: Yersinia, Routing Attacks

### **Low Fragmentation Heap (LFH)**
↳ Related: Heap, Heap Integrity, Kernel Hardening

---

## M

### **MAC Address**
↳ Related: NAC, ARP Spoofing, Network Access

### **MAC OUI**
↳ Related: Device Fingerprinting

### **macshift**
↳ Related: MAC Spoofing

### **Magic Unicorn**
↳ Related: Payload Generation

### **MemGC**
↳ Related: Heap Protection, free(), MemProtect

### **Method to Escape**
↳ Related: Sandbox Evasion

### **Method to Escalate**
↳ Related: Privilege Escalation

### **MemProtect**
↳ Related: Heap Protection, free(), MemGC

### **Message Integrity Check (MIC)**
↳ Related: Exploit Guard, Cryptographic Integrity

### **Metasploit**
↳ Related: Exploit Frameworks, Post Exploitation

### **Mimikatz**
↳ Related: Credential Access, PowerSploit

### **MITM**
↳ Related: ARP Spoofing, Ettercap

### **mitmproxy**
↳ Related: HTTP Manipulation, SSL Stripping

### **mitmdump**
↳ Related: mitmproxy, Traffic Inspection

### **mmap()**
↳ Labs: 4.5  
↳ Related: Virtual Memory, ASLR

### **Modern Defenses**
↳ Related: Exploit Guard, EMET

### **modprobe**
↳ Related: IPv6, VLAN Attacks

### **mona.py**
↳ Labs: 5.1, 5.2, 5.3, 5.4  
↳ Related: ROP, Debugging

### **multiplyreplay**
↳ Related: Credential Replay

---

## N

### **Name Resolution**
↳ Related: Network Manipulation

### **Netmon Agent**
↳ Related: Fuzzing, Process Monitoring

### **Netwide Assembler (NASM)**
↳ Related: Shellcode, Null Bytes

### **Network Access Control (NAC)**
↳ Related: Captive Portal, 802.1X

### **Nmap**
↳ Related: Network Enumeration

### **33 Bytes**
↳ Related: Shellcode, NASM

### **NX Bit**
↳ Labs: 4.2, 4.6, 5.1, 5.3  
↳ Related: DEP, W^X

---

## O

### **Obfuscation**
↳ Related: AMSI, Evasion Techniques

### **Object Files**
↳ Related: Linker, Loader

### **objdump**
↳ Labs: 4.1  
↳ Related: Reverse Engineering, NASM

### **OllyDbg**
↳ Related: Debugging

### **Opcodes**
↳ Related: Assembly Instructions, Shellcode

### **Open Shortest-Path First (OSPF)**
↳ Related: Routing Protocols, LSAs

### **OpenSSL**
↳ Related: Cryptography, AES

### **OSfuscate**
↳ Related: OS Fingerprinting Evasion

---

## P

### **p0f**
↳ Related: Passive OS Fingerprinting

### **Packet Fence**
↳ Related: NAC

### **Padding Oracle**
↳ Related: CBC, Cryptographic Attacks

### **POODLE**
↳ Related: Padding Oracle, Legacy Crypto

### **Paging**
↳ Related: Virtual Memory

### **PaiMei**
↳ Related: Reverse Engineering, Debugging

### **Passive OS Fingerprinting**
↳ Related: TCP Stack Fingerprinting

### **PaX**
↳ Related: Memory Protections, NX Bit

### **Pcaphistogram**
↳ Related: Entropy Analysis

### **PE/COFF**
↳ Related: Windows Binaries, Loader

### **PEDA (GDB)**
↳ Related: Debugging, GNU Debugger

### **Physical Memory**
↳ Related: Processor Cache, Registers

### **Pickupline**
↳ Related: Captive Portal

### **Position Independent Executable (PIE)**
↳ Related: ASLR, ELF, Heap

### **PingCastle**
↳ Related: Active Directory Security

### **PKCS#5**
↳ Related: Cryptography, Padding

### **PKCS#7**
↳ Related: Cryptography, Padding

### **Pop / Pop / Ret**
↳ Labs: 5.2  
↳ Related: SEH, ROP

### **Post Exploitation**
↳ Related: C2, Privilege Escalation

### **Potato**
↳ Related: Privilege Escalation

### **PowerShell**
↳ Labs: 2.6  
↳ Related: Exploit Guard, Post Exploitation

### **PowerSploit / SharpSploit / PowerSharpPack**
↳ Related: Mimikatz, Post Exploitation

### **Procedure Epilogue**
↳ Related: Stack Operations

### **Procedure Linkage Table (PLT)**
↳ Labs: 4.2, 4.6  
↳ Related: Lazy Linking, ELF

### **Procedure Prologue**
↳ Related: Stack Operations

### **Process Environment Block (PEB)**
↳ Labs: 5.1  
↳ Related: TEB, SEH

### **Processor Access Modes**
↳ Related: CPU Modes

### **Processor Architecture**
↳ Related: x86, x64

### **Processor Cache**
↳ Related: Physical Memory

### **Processor Registers**
↳ Related: General-Purpose Registers, Segment Registers

### **Procmon Agent**
↳ Related: Process Monitoring

### **Product Security Testing**
↳ Related: Risk Analysis, Threat Modeling

### **Protected Mode**
↳ Related: Exploit Guard, EMET

### **PSConsoleHostReadline**
↳ Related: PowerShell

### **Pstalker**
↳ Related: Code Coverage, DynamoRIO

### **PUSHAD**
↳ Related: ROP, Stack Pivoting

### **Pwntools**
↳ Related: Exploit Development

### **PxE**
↳ Related: Credential Attacks

### **PyDbg**
↳ Related: Debugging

## R

### **RADIUS**
↳ Related: Network Access Control, 802.1X, PacketFence

### **RC4**
↳ Related: Cryptography, Stream Ciphers

### **readelf**
↳ Related: ELF, Binary Inspection

### **Request for Comment (RFC) Documents**
↳ Related: Networking Standards, HSTS, OSfuscate, VRRP

### **Responder**
↳ Related: Credential Capture, SMB, MITM

### **Restricted Desktops**
↳ Related: Kiosk Escapes, Application Whitelisting

### **ret2libc**
↳ Labs: 4.2, 4.6, 6.1  
↳ Related: DEP, W^X, libc, NX Bit

### **Return-Oriented Programming (ROP)**
↳ Labs: 5.3, 5.4  
↳ Related: Gadgets, DEP, ASLR, Control Flow Guard, VirtualProtect, Stack Pivoting

### **return-to-libc**
↳ Related: ret2libc

### **Reverse Engineering**
↳ Related: Debugging, IDA Pro, Binary Analysis

### **Risk Analysis**
↳ Related: Product Security Testing, Threat Modeling

### **Ropper**
↳ Related: ROP, Gadget Discovery

### **ROP Chain**
↳ Labs: 5.3, 5.4  
↳ Related: ROP, DEP, Stack Pivoting

### **Routing Protocols**
↳ Related: OSPF, BGP

### **Router VM**
↳ Related: Dynamips, Routing Protocols

### **Ruby**
↳ Related: Scripting, Exploit Automation

---

## S

### **Safe Unlinking**
↳ Related: Heap, unlink()

### **SafeSEH**
↳ Labs: 5.2  
↳ Related: SEH, DEP, Canaries, Pop / Pop / Ret

### **Savant**
↳ Related: Fuzzing Targets

### **Scapy**
↳ Labs: 3.1, 3.3  
↳ Related: Packet Crafting, Network Attacks, IPv6

### **Seatbelt**
↳ Labs: 2.6  
↳ Related: Host Enumeration, Privilege Escalation

### **Secure Desktop**
↳ Related: UAC, Restricted Desktops

### **Segment Registers**
↳ Labs: 4.1  
↳ Related: General-Purpose Registers, FLAGS Registers

### **SEHOP**
↳ Related: SafeSEH, Structured Exception Handling

### **SEH Overwrite**
↳ Related: Structured Exception Handling

### **SELinux**
↳ Related: AppArmor, Mandatory Access Control

### **Sharpkiller**
↳ Related: AMSI, Obfuscation

### **Shelter**
↳ Related: Payload Obfuscation

### **Shellcode**
↳ Labs: 4.1, 4.5, 6.1  
↳ Related: NASM, System Calls, ROP, Gadgets, Null Bytes

### **Simple Network Management Protocol (SNMP)**
↳ Related: Network Enumeration, NAC

### **SiteKiosk**
↳ Related: Restricted Desktops

### **Smashing the Stack**
↳ Related: Stack Exploitation

### **sniff()**
↳ Labs: 3.3  
↳ Related: Packet Capture, Scapy

### **Sniffer**
↳ Related: Packet Capture, MITM

### **socat**
↳ Related: IPv6 Tunneling, Network Pivoting

### **sockets**
↳ Related: System Calls, Handle Validation

### **Software Restriction Policy (SRP)**
↳ Related: WDAC, Application Control

### **Source Index (ESI/RSI)**
↳ Related: General-Purpose Registers

### **Spanning Tree Protocol (STP)**
↳ Related: Yersinia, VLAN Attacks

### **SprayWMI**
↳ Related: Payload Delivery

### **sslstrip**
↳ Related: HTTPS Downgrade, MITM

### **Stack Exploitation**
↳ Related: ret2libc, ROP, PIE, Canaries, Debugging

### **Stack Operations**
↳ Related: Procedure Prologue, Epilogue

### **Stack Pivoting**
↳ Related: ROP, Stack Protection

### **Stack Protection**
↳ Related: Canaries, ASLR, Exploit Guard, EMET

### **Stack Pointer (ESP/RSP)**
↳ Related: Stack Operations

### **Stream Cipher IV Collision**
↳ Related: Cryptographic Attacks

### **Stream Ciphers**
↳ Related: RC4, Cryptography

### **Structured Exception Handling (SEH)**
↳ Labs: 5.2  
↳ Related: SafeSEH, DEP, PEB, TEB

### **Sudo Killer**
↳ Related: Privilege Escalation

### **Sulley**
↳ Labs: 3.4  
↳ Related: Fuzzing, BooFuzz, AFL

### **Swap**
↳ Related: Virtual Memory

### **System Calls**
↳ Labs: 4.1  
↳ Related: Shellcode, Kernel Transitions

---

## T

### **Taof**
↳ Related: Packet Crafting

### **TCP Stack Fingerprinting**
↳ Related: Passive OS Fingerprinting

### **tcpick**
↳ Related: Packet Analysis

### **TFTP**
↳ Related: Network Protocols

### **Thread Environment Block (TEB)**
↳ Related: TIB, PEB, SEH

### **Thread Information Block (TIB)**
↳ Related: PEB, SEH, TEB

### **Tracing (Linux)**
↳ Labs: 3.2  
↳ Related: ltrace, Runtime Analysis

### **Tracing (Windows)**
↳ Related: ETW, API Monitoring

### **Triple DES (3DES)**
↳ Related: Cryptography

### **Tiny Tracer**
↳ Related: IDA Pro, Code Coverage

### **Twofish**
↳ Related: Cryptography

---

## U

### **unlink()**
↳ Related: Heap, Safe Unlinking

### **Use-After-Free (UAF)**
↳ Related: Heap, ROP, Stack Pivoting

### **User Account Control (UAC)**
↳ Related: AMSI, WDAC, Privilege Escalation

### **User Impersonation**
↳ Related: Captive Portal

### **User-Agent Impersonation**
↳ Related: OS Fingerprinting

---

## V

### **vconfig**
↳ Related: VLAN Participation, VLAN Hopping

### **Virtual Memory**
↳ Labs: 4.5  
↳ Related: Paging, ASLR

### **Virtual Router Redundancy Protocol (VRRP)**
↳ Related: HSRP

### **VirtualProtect()**
↳ Labs: 5.3, 5.4  
↳ Related: ROP, DEP, Gadgets

### **VLAN**
↳ Related: NAC, SNMP

### **VLAN Attacks**
↳ Related: VLAN Hopping

### **VLAN Hopping**
↳ Related: DTP, CDP

### **VLAN Participation**
↳ Related: VLAN Configuration

### **Voice VLAN**
↳ Related: CDP, VoIP

### **voiphopper**
↳ Related: Voice VLAN Attacks

---

## W

### **W^X**
↳ Related: DEP, NX Bit

### **Web Browser User-Agent Matching**
↳ Related: OS Validation

### **WinAFL**
↳ Related: AFL, Fuzzing

### **WinDBG**
↳ Related: Debugging, Windows Exploitation

### **Windows Core Components**
↳ Related: Windows Internals

### **Windows Defender Application Control (WDAC)**
↳ Related: AppLocker, UAC, AMSI

### **WinPcap**
↳ Related: Packet Capture

### **Wireshark**
↳ Related: Packet Analysis, Scapy

### **WOW64**
↳ Related: Windows Architecture

### **wrpcap()**
↳ Related: Scapy, Packet Capture

---

## X

### **x64/dbg**
↳ Related: Debugging

### **x86 Assembly Language**
↳ Labs: 4.1, 4.2  
↳ Related: Assembly, Calling Conventions

### **XD / ED Bit**
↳ Related: DEP, NX Bit

---

## Y

### **Yersinia**
↳ Related: VLAN Attacks, Routing Protocols, Loki

---

## Z

### **ZwSetInformationProcess()**
↳ Related: DEP Bypass, Windows Internals

