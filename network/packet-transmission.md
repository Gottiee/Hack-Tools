# Packet Transmission

## Table of Contents

- [1. Encapsulation](#1-encapsulation)
- [2. MTU (Maximum Transmission Unit)](#2-mtu-maximum-transmission-unit)
- [3. IP Fragmentation](#3-ip-fragmentation)
  - [3.1 IDS/IPS Bypass via Fragmentation](#31-idsips-bypass-via-fragmentation)

---

## 1. Encapsulation

Encapsulation is the process where each layer of the OSI model **wraps** the data from the layer above by adding its own **header** (and sometimes a trailer). Each layer treats everything it receives from above as its payload.

Each layer has its own name for the data unit:

| Layer | Data Unit Name |
|-------|---------------|
| 7-5 (Application) | Data |
| 4 (Transport) | Segment (TCP) / Datagram (UDP) |
| 3 (Network) | Packet |
| 2 (Data Link) | Frame |
| 1 (Physical) | Bits |

### Example: HTTP packet journey

When your browser sends `GET /index.html`:

```
Layer 7 (Application)  : [HTTP Request: "GET /index.html"]

Layer 4 (Transport)    : [TCP Header (src port, dst port 80, seq, ack, flags)] [HTTP Data]

Layer 3 (Network)      : [IP Header (src IP, dst IP, TTL, protocol)] [TCP Header] [HTTP Data]

Layer 2 (Data Link)    : [Ethernet Header (src MAC, dst MAC)] [IP Header] [TCP Header] [HTTP Data] [FCS Trailer]

Layer 1 (Physical)     : 01101001 01110100... (electrical signals / light / radio)
```

The **reverse process** (decapsulation) happens at the receiver: each layer strips its header and passes the payload up.

---

## 2. MTU (Maximum Transmission Unit)

The MTU is the **maximum size of a single frame** that can be transmitted on a network link, **including the Layer 3 header but excluding the Layer 2 header**.

- Default Ethernet MTU: **1500 bytes**
- This means the IP packet (header + payload) cannot exceed 1500 bytes on standard Ethernet

**What happens when a packet exceeds the MTU:**

1. If the **DF (Don't Fragment) flag is set** in the IP header: the packet is **dropped** and the router sends back an ICMP `Type 3, Code 4 - Fragmentation Needed` message. This is the basis of **Path MTU Discovery**.

2. If the **DF flag is NOT set**: the router **fragments** the packet into smaller pieces (see section 3).

**Example scenario:**
```
Host sends a 4000-byte IP packet on Ethernet (MTU 1500):
  - DF=1 → packet dropped, ICMP error sent back
  - DF=0 → router splits into 3 fragments (1500 + 1500 + 1040 bytes)
```

---

## 3. IP Fragmentation

When a packet is larger than the MTU and the DF flag is not set, the router **splits it into fragments** that each fit within the MTU.

Each fragment contains:
- **Identification field**: same value for all fragments of the original packet, so the receiver can group them
- **Fragment Offset**: position of this fragment relative to the start of the original payload (in units of 8 bytes)
- **MF (More Fragments) flag**: set to 1 on all fragments except the last one

**Example: 4000-byte packet on MTU 1500**
```
Original: [IP Header 20B] [Payload 3980B]

Fragment 1: [IP Header 20B] [Payload 1480B]  offset=0,    MF=1
Fragment 2: [IP Header 20B] [Payload 1480B]  offset=185,  MF=1   (185 x 8 = 1480)
Fragment 3: [IP Header 20B] [Payload 1020B]  offset=370,  MF=0   (370 x 8 = 2960)
```

Fragments can arrive **out of order**. The receiver uses the Identification field + Fragment Offset to **reassemble** the original packet.

**Important:** Only the **first fragment** contains the Transport layer header (TCP/UDP ports). Other fragments only have the IP header.

---

### 3.1 IDS/IPS Bypass via Fragmentation

Because IDS/IPS inspect packet content to detect malicious payloads, fragmentation can be abused to **split the signature across multiple fragments** that the IDS fails to reassemble.

#### Tiny Fragment Attack

Create fragments so small (8 or 16 bytes of payload) that the **TCP header itself gets split** across two fragments. The first fragment has only the source/destination ports, the second has the TCP flags. The IDS cannot read the full TCP header from a single fragment, so it lets it through.

```bash
# Nmap fragmented scan (8-byte fragments)
nmap -f <target>

# 16-byte fragments
nmap -ff <target>

# Custom fragment size
nmap --mtu 16 <target>
```

#### Overlapping Fragment Attack

Send fragments where the **offsets overlap**. The second fragment **rewrites part of the first** during reassembly. The IDS reassembles using one strategy (e.g. keeps first), but the target OS uses another (e.g. keeps last), producing different results.

```
Fragment 1: offset=0,  payload="GET /safe.html"
Fragment 2: offset=5,  payload="/evil.php..."    ← overlaps offset 5

IDS sees:  "GET /safe.html"    (keeps first)
Target OS: "GET /evil.php..."  (keeps last, Linux/Windows behavior varies)
```

#### Fragment Timeout Attack (DoS)

Send many fragments with the **same Identification field but never send the last one** (MF=0). The receiver holds all fragments in memory waiting for reassembly. Flooding with incomplete fragments **exhausts the reassembly buffer**.

```
Attacker sends thousands of:
  [ID=1234] Fragment offset=0, MF=1
  [ID=1234] Fragment offset=185, MF=1
  [ID=1234] Fragment offset=370, MF=1
  ... (last fragment with MF=0 is never sent)
  → Receiver holds all fragments in memory → memory exhaustion
```
