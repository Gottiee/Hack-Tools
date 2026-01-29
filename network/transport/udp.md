# UDP (User Datagram Protocol)

## Table of Contents

- [1. Overview](#1-overview)
- [2. UDP Port Scanning](#2-udp-port-scanning)
  - [2.1 How It Works](#21-how-it-works)
  - [2.2 Limitations & Slowness](#22-limitations--slowness)
- [3. Protocols Using UDP](#3-protocols-using-udp)
- [4. Attack Vectors](#4-attack-vectors)
  - [4.1 UDP Flood](#41-udp-flood)
  - [4.2 Amplification Attack](#42-amplification-attack)

---

## 1. Overview

UDP is a **connectionless**, **unreliable** transport layer (Layer 4) protocol. Unlike TCP, there is no handshake, no acknowledgment, no retransmission, and no ordering guarantee. You send a datagram and hope it arrives.

**Characteristics:**
- **No connection setup**: no handshake, data is sent immediately
- **No delivery guarantee**: no ACK, no retransmission. If a packet is lost, it's lost.
- **No ordering**: datagrams can arrive in any order
- **Minimal overhead**: header is only **8 bytes** (vs 20+ for TCP)
- **Fast**: no round-trip needed before sending data

**UDP Header (8 bytes):**
```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Length             |           Checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

UDP is used when **speed matters more than reliability**, or when the application handles reliability itself.

---

## 2. UDP Port Scanning

### 2.1 How It Works

UDP scanning works differently from TCP because there is no handshake to confirm a port is open.

```
Attacker sends UDP packet to port X:

  Case 1: Port CLOSED
  ← Target responds with ICMP "Destination Unreachable, Port Unreachable" (Type 3, Code 3)
  → Nmap reports: closed

  Case 2: Port OPEN
  ← Target sends a UDP response (application-specific) OR sends nothing at all
  → Nmap reports: open (if response) or open|filtered (if no response)

  Case 3: Port FILTERED (firewall drops the packet)
  ← No response at all
  → Nmap reports: open|filtered (same as open with no response)
```

```bash
# Nmap UDP scan
nmap -sU <target>

# Top 100 UDP ports only (faster)
nmap -sU --top-ports 100 <target>

# With version detection (sends protocol-specific probes to get real answers)
nmap -sU -sV <target>
```

### 2.2 Limitations & Slowness

**Why UDP scanning is slow and unreliable:**

1. **No positive confirmation**: when a port is open, most services send **nothing** back to a generic empty UDP packet. You can't distinguish "open" from "filtered by firewall". That's why nmap reports `open|filtered`.

2. **Timeout-based**: for every `open|filtered` port, nmap has to **wait for a timeout** (typically 1-2 seconds) to make sure no ICMP response is coming. With 65535 ports, that adds up fast.

3. **ICMP rate limiting**: most OS limit ICMP error messages (e.g. Linux sends only ~1 ICMP unreachable per second). So even for closed ports, the responses trickle in slowly. A full scan of 65535 ports can take **hours**.

4. **Firewalls drop silently**: if a firewall drops UDP packets without sending ICMP back, every filtered port looks the same as an open one.

**Workaround:** Use `-sV` (version detection) which sends **protocol-specific payloads** (e.g. a real DNS query to port 53). If the service responds, you get a confirmed `open`.

---

## 3. Protocols Using UDP

| Protocol | Port | Usage |
|----------|------|-------|
| DNS | 53 | Domain name resolution |
| DHCP | 67/68 | Automatic IP address assignment |
| TFTP | 69 | Trivial file transfer (no auth, used for PXE boot) |
| SNMP | 161/162 | Network device monitoring & management |
| NTP | 123 | Time synchronization |
| Syslog | 514 | Log forwarding |
| mDNS | 5353 | Multicast DNS (local network discovery) |
| LLMNR | 5355 | Link-Local Multicast Name Resolution (Windows) |
| NetBIOS-NS | 137 | NetBIOS Name Service |
| IPSec (IKE) | 500 | VPN key exchange |
| RADIUS | 1812/1813 | Network authentication |
| RTP | Dynamic | Real-time audio/video (VoIP, streaming) |

> **Telnet (23) and RDP (3389) are TCP, not UDP.** Telnet is a TCP interactive session. RDP primarily uses TCP (though it can use UDP for performance optimization on newer versions, the main connection is TCP).

---

## 4. Attack Vectors

### 4.1 UDP Flood

A volumetric DoS attack that sends a massive number of UDP packets to random ports on the target. For each packet hitting a closed port, the target must:

1. Check if any application is listening → no
2. Generate an ICMP "Port Unreachable" response
3. Send that ICMP packet back

This consumes **CPU** (generating ICMP replies) and **bandwidth** (sending them). If the flood is large enough, the target can't keep up and legitimate traffic is dropped.

```
Attacker → floods random UDP ports → Target
                                       ↓
                              Generates ICMP unreachable for each
                                       ↓
                              CPU exhaustion + bandwidth saturation
```

When the target gets overwhelmed, it stops responding to ICMP and the flood saturates the network link itself.

### 4.2 Amplification Attack

The attacker sends small requests to public servers with the **source IP spoofed as the victim's IP**. The servers send their (much larger) responses to the victim. The attacker amplifies their bandwidth.

```
Attacker (spoofed src = victim IP)
   |
   |-- small request (e.g. 60 bytes) --> Public DNS server
   |-- small request --> Public NTP server
   |-- small request --> Public Memcached server
   ...

Public servers send large responses TO THE VICTIM:
   DNS server    -- 3000 bytes --> Victim    (x50 amplification)
   NTP server    -- 4680 bytes --> Victim    (x556 amplification)
   Memcached     -- 60000 bytes --> Victim   (x51000 amplification)
```

**Common amplification factors:**

| Protocol | Port | Amplification Factor |
|----------|------|---------------------|
| DNS | 53 | x28 - x54 |
| NTP (monlist) | 123 | x556 |
| SSDP | 1900 | x30 |
| Memcached | 11211 | x10000 - x51000 |
| CharGen | 19 | x358 |
| SNMP | 161 | x6 |

**Why it works:** UDP has no handshake, so the source IP is never verified. The server trusts the spoofed source and sends the response to the victim.
