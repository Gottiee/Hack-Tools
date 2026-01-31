# IPv6

## Table of Contents

- [1. Overview](#1-overview)
  - [1.1 Address Format & Simplification](#11-address-format--simplification)
  - [1.2 Special Addresses](#12-special-addresses)
  - [1.3 No Broadcast — Multicast & Anycast](#13-no-broadcast--multicast--anycast)
  - [1.4 Auto-Configuration (SLAAC)](#14-auto-configuration-slaac)
  - [1.5 NDP (Neighbor Discovery Protocol)](#15-ndp-neighbor-discovery-protocol)
- [2. IPv4 vs IPv6](#2-ipv4-vs-ipv6)
- [3. Security Implications](#3-security-implications)
- [4. IPv6-Specific Attacks](#4-ipv6-specific-attacks)
  - [4.1 RA Spoofing (Router Advertisement)](#41-ra-spoofing-router-advertisement)
  - [4.2 NDP Attacks](#42-ndp-attacks)
  - [4.3 Dual-Stack Abuse](#43-dual-stack-abuse)

---

## 1. Overview

IPv6 is the successor to IPv4. The main reason for its creation is **address exhaustion** — IPv4 has ~4.3 billion addresses (32 bits), which is not enough for the modern internet. IPv6 uses **128-bit addresses**, providing 3.4 x 10^38 possible addresses (essentially unlimited).

### 1.1 Address Format & Simplification

An IPv6 address is 128 bits written as **8 groups of 4 hex digits** separated by colons:

```
Full:       2001:0db8:0000:0000:0001:0000:0000:0001
```

**Simplification rules:**

**Rule 1 — Leading zeros:** Remove leading zeros in each group.
```
2001:0db8:0000:0000:0001:0000:0000:0001
  →  2001:db8:0:0:1:0:0:1
```

**Rule 2 — Consecutive zero groups:** Replace the **longest** consecutive run of all-zero groups with `::`. You can only use `::` **once** per address (otherwise the address would be ambiguous).
```
2001:db8:0:0:1:0:0:1
  →  2001:db8::1:0:0:1       (replaces the first 0:0)
```

**More examples:**
```
fe80:0000:0000:0000:0000:0000:0000:0001
  →  fe80::1                               (6 consecutive zero groups → ::)

2001:0db8:0000:0001:0000:0000:0000:0001
  →  2001:db8:0:1::1                       (:: replaces the longest run of zeros)

0000:0000:0000:0000:0000:0000:0000:0001
  →  ::1                                    (loopback)

0000:0000:0000:0000:0000:0000:0000:0000
  →  ::                                     (unspecified address)
```

**Wrong (ambiguous — :: used twice):**
```
2001:db8::1::1    ← INVALID, can't tell where the zeros are
```

### 1.2 Special Addresses

| Address | IPv4 Equivalent | Purpose |
|---------|-----------------|---------|
| `::1` | `127.0.0.1` | Loopback (localhost) |
| `::` | `0.0.0.0` | Unspecified address (listening on all interfaces) |
| `fe80::/10` | `169.254.0.0/16` | Link-local (auto-assigned, not routable, used by NDP) |
| `fc00::/7` (`fd00::/8` in practice) | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | Unique Local Address (ULA) — private, not routed on internet |
| `ff00::/8` | N/A | Multicast |
| `2000::/3` | Public IPs | Global Unicast Address (routable on internet) |
| `::ffff:192.168.1.1` | N/A | IPv4-mapped IPv6 address (for dual-stack transition) |

### 1.3 No Broadcast — Multicast & Anycast

IPv6 has **no broadcast**. Instead it uses:

**Multicast** (`ff00::/8`): A packet sent to a multicast address is delivered to **all members of a group** (only those who subscribed, not the entire network like broadcast).

| Multicast Address | Who Receives It |
|-------------------|-----------------|
| `ff02::1` | All nodes on the link (like IPv4 broadcast but opt-in) |
| `ff02::2` | All routers on the link |
| `ff02::1:ff00:0/104` | Solicited-node multicast (used by NDP to find a specific host) |

**Anycast**: A packet sent to an anycast address is delivered to the **nearest** device that shares that address (used for load balancing, e.g. DNS root servers).

### 1.4 Auto-Configuration (SLAAC)

In IPv4 you need DHCP to get an IP. In IPv6, a host can **automatically generate its own address** without any server, using **SLAAC (Stateless Address Autoconfiguration)**:

```
1. Host generates a link-local address (fe80::) using its MAC address
   MAC: AA:BB:CC:DD:EE:FF
    → Insert FFFE in the middle: AA:BB:CC:FF:FE:DD:EE:FF
    → Flip 7th bit: A8:BB:CC:FF:FE:DD:EE:FF
    → Link-local: fe80::a8bb:ccff:fedd:eeff

2. Host sends Router Solicitation (RS) to ff02::2 (all routers)

3. Router responds with Router Advertisement (RA) containing:
   - Network prefix (e.g. 2001:db8:1::/64)
   - Default gateway
   - DNS server (optional, via RDNSS option)

4. Host combines prefix + its interface ID:
   → Global address: 2001:db8:1::a8bb:ccff:fedd:eeff
```

> **Privacy concern:** Since the interface ID is derived from the MAC address, it's a stable identifier that can be used to track a device across networks. Modern OS use **Privacy Extensions (RFC 4941)** — they generate a random interface ID that changes periodically.

### 1.5 NDP (Neighbor Discovery Protocol)

NDP is the IPv6 replacement for ARP (and more). It uses ICMPv6 messages to perform several functions:

| NDP Function | ICMPv6 Type | Replaces (IPv4) |
|-------------|-------------|-----------------|
| Router Solicitation (RS) | 133 | N/A (part of DHCP) |
| Router Advertisement (RA) | 134 | N/A (part of DHCP) |
| Neighbor Solicitation (NS) | 135 | ARP Request |
| Neighbor Advertisement (NA) | 136 | ARP Reply |
| Redirect | 137 | ICMP Redirect |

**Neighbor Solicitation / Advertisement** = the IPv6 equivalent of ARP:
```
Host A wants to find the MAC of 2001:db8::5:

1. Host A sends Neighbor Solicitation (NS) to the solicited-node multicast address
   "Who has 2001:db8::5? Tell fe80::a8bb:ccff:fedd:eeff"

2. Host B (who has that IP) responds with Neighbor Advertisement (NA)
   "2001:db8::5 is at MAC AA:BB:CC:DD:EE:05"
```

---

## 2. IPv4 vs IPv6

| Criteria | IPv4 | IPv6 |
|----------|------|------|
| Address size | 32 bits | 128 bits |
| Notation | Dotted decimal (192.168.1.1) | Hex with colons (2001:db8::1) |
| Address space | ~4.3 billion | ~3.4 x 10^38 |
| Broadcast | Yes | No (replaced by multicast) |
| ARP | Yes (separate protocol) | No (replaced by NDP, part of ICMPv6) |
| NAT | Common (address exhaustion workaround) | Not needed (enough addresses for every device) |
| Auto-config | DHCP required | SLAAC built-in (DHCP optional: DHCPv6) |
| Header | Variable length (20-60 bytes, options field) | Fixed 40 bytes (simpler, faster to process) |
| Fragmentation | Routers can fragment | Only the source host fragments (routers never fragment) |
| IPsec | Optional | Built into the protocol (but not always enforced) |

---

## 3. Security Implications

**The core problem:** Most organizations deploy IPv6 alongside IPv4 (dual-stack) but only configure security for IPv4. This creates a **blind spot**.

**IPv6 SEND (SEcure Neighbor Discovery):** An extension of NDP that uses cryptographic signatures (CGA — Cryptographically Generated Addresses) to authenticate NDP messages. In theory it prevents NDP spoofing. In practice, **almost nobody deploys SEND** — it requires a PKI infrastructure and is complex to manage. So NDP spoofing remains viable on most networks.

**Key security issues:**
- Firewalls may only inspect IPv4 traffic, letting IPv6 through unfiltered
- IDS/IPS rules often don't cover IPv6
- Logging may not capture IPv6 traffic
- Network segmentation (VLANs, ACLs) may not apply to IPv6
- IPv6 tunneling protocols (6to4, Teredo, ISATAP) can encapsulate IPv6 inside IPv4, **bypassing IPv4 firewalls entirely**

---

## 4. IPv6-Specific Attacks

### 4.1 RA Spoofing (Router Advertisement)

In IPv6, routers announce themselves by sending **Router Advertisement (RA)** messages to `ff02::1` (all nodes). These contain:
- Default gateway address
- Network prefix
- DNS server (RDNSS option)
- MTU, hop limit, etc.

Since any device can send RA messages and **there is no authentication by default**, an attacker can:

**1. Become the default gateway (MITM):**
```
Attacker sends RA:
  "I am the router, gateway = fe80::evil, prefix = 2001:db8::/64"

Victims update their routing table → all traffic flows through attacker
```

**2. Spoof the DNS server:**
```
Attacker sends RA with RDNSS option:
  "DNS server = fe80::evil"

Victims use attacker's DNS → attacker controls name resolution
  → Phishing, credential theft, malware delivery
```

**3. Assign a rogue prefix (isolation/interception):**
```
Attacker sends RA with a fake prefix:
  "prefix = fd00:dead::/64"

Victims auto-configure an address on this prefix
  → Attacker controls this subnet entirely
  → Can intercept all traffic within this prefix
```

**Tools:**
```bash
# fake_router6 from THC-IPv6 toolkit
fake_router6 eth0 2001:db8:evil::/64

# mitm6 — specifically designed for AD environments
# Sends RA to make victims use attacker as DNS (→ NTLM relay)
mitm6 -d company.local
```

### 4.2 NDP Attacks

Since NDP replaces ARP, all ARP-style attacks have an IPv6 equivalent:

**Neighbor Advertisement Spoofing** (= ARP poisoning for IPv6):
```
Attacker sends forged Neighbor Advertisement:
  "2001:db8::gateway is at MAC aa:bb:cc:dd:ee:ff (attacker's MAC)"

Same result as ARP poisoning → MITM
```

**NDP Exhaustion:** Flood the network with Neighbor Solicitations for every address in a /64 subnet. The router tries to resolve each one, filling its neighbor cache → DoS.

```bash
# THC-IPv6 toolkit
parasite6 eth0        # NDP poisoning (like arpspoof)
flood_router6 eth0    # Flood fake RAs
```

**Mitigations:**
- RA Guard (switch feature that blocks RAs from non-router ports)
- DHCPv6 Guard
- SEND (rarely deployed)
- IPv6 First Hop Security (Cisco)

### 4.3 Dual-Stack Abuse

Most modern OS have IPv6 **enabled by default** (Windows, Linux, macOS), even when the network is IPv4-only and nobody configured IPv6. This means:

**1. Firewall bypass:** The firewall filters IPv4 traffic but IPv6 rules are missing or permissive. An attacker communicates with the target over IPv6 and bypasses all IPv4 rules.

**2. Log evasion:** SIEM and monitoring tools are configured to parse IPv4 addresses. IPv6 connections may not appear in logs or trigger alerts.

**3. Rogue IPv6 infrastructure:** On a network with no legitimate IPv6 router, the attacker is the **only one sending RAs**. Every host with IPv6 enabled will accept the attacker as their default gateway and DNS — with zero competition.

```
IPv4-only corporate network:
  - No IPv6 router exists
  - All hosts have IPv6 enabled (default)

Attacker runs mitm6:
  1. Sends Router Advertisements
  2. All hosts auto-configure IPv6 with attacker as gateway + DNS
  3. Attacker replies to DNS queries with their own IP
  4. Hosts connect to attacker thinking it's the real server
  5. Attacker captures NTLM hashes via HTTP auth prompt
  6. Relays hashes to AD (ntlmrelayx) → domain compromise
```

This is one of the most practical IPv6 attacks and is heavily used in **Active Directory pentesting** with the `mitm6` + `ntlmrelayx` combo.

```bash
# Terminal 1: mitm6 poisons DNS via IPv6
mitm6 -d corp.local

# Terminal 2: relay captured NTLM auth
ntlmrelayx.py -6 -t ldaps://dc01.corp.local -wh fakewpad.corp.local -l loot
```
