# ARP (Address Resolution Protocol)

## Table of Contents

1. [Overview](#overview)
2. [How ARP Works](#how-arp-works)
   - [ARP Request / Reply](#arp-request--reply)
   - [ARP Cache](#arp-cache)
3. [Packet Structure](#packet-structure)
4. [Gratuitous ARP](#gratuitous-arp)
5. [Exploitation](#exploitation)
   - [ARP Spoofing / Poisoning](#arp-spoofing--poisoning)
   - [Man-in-the-Middle (MITM)](#man-in-the-middle-mitm)
   - [Tools](#tools)

---

## Overview

Resolves an IPv4 address to a MAC address on a local network (Layer 2).
ARP operates only within a broadcast domain (same subnet). It has no authentication mechanism, which is the root cause of all ARP-based attacks.

## How ARP Works

### ARP Request / Reply

1. Host A wants to communicate with `192.168.1.5` but doesn't know its MAC address.
2. Host A sends an **ARP Request** as a **broadcast** (`ff:ff:ff:ff:ff:ff`): *"Who has 192.168.1.5? Tell 192.168.1.1"*
3. Every host on the subnet receives the frame, but only the owner of `192.168.1.5` responds.
4. Host B replies with a **unicast ARP Reply**: *"192.168.1.5 is at aa:bb:cc:dd:ee:ff"*
5. Host A stores the mapping in its ARP cache and can now send frames directly.

### ARP Cache

Each host maintains a local ARP table that maps IP addresses to MAC addresses.
- Entries are **dynamic** (learned from replies, expire after a timeout, usually 60-300s depending on the OS).
- Entries can also be **static** (manually configured, never expire).
- A host updates its cache whenever it receives a valid ARP reply, **even if it never sent a request** — this is the key weakness exploited in attacks.

```bash
# View ARP table
arp -a            # Windows / Linux
ip neigh show     # Linux
```

## Packet Structure

| Field                  | Size    | Description                              |
|------------------------|---------|------------------------------------------|
| Hardware Type          | 2 bytes | `1` = Ethernet                           |
| Protocol Type          | 2 bytes | `0x0800` = IPv4                          |
| Hardware Address Len   | 1 byte  | `6` (MAC = 6 bytes)                      |
| Protocol Address Len   | 1 byte  | `4` (IPv4 = 4 bytes)                     |
| Operation              | 2 bytes | `1` = Request, `2` = Reply               |
| Sender MAC             | 6 bytes | MAC of the sender                        |
| Sender IP              | 4 bytes | IP of the sender                         |
| Target MAC             | 6 bytes | MAC of the target (`00:00:00:00:00:00` in requests) |
| Target IP              | 4 bytes | IP of the target                         |

Total ARP payload: **28 bytes**, encapsulated in an Ethernet frame with EtherType `0x0806`.

## Gratuitous ARP

A Gratuitous ARP is an ARP Reply sent **without** a prior request. A host broadcasts it to announce or update its own IP-to-MAC mapping to the entire subnet.

Legitimate uses:
- IP failover (e.g., VRRP/HSRP updating the virtual IP to a new MAC)
- A host updating the network after a NIC change

The problem: any host can send a gratuitous ARP claiming **any** IP, and receivers will blindly update their cache. There is **no verification**.

## Exploitation

### ARP Spoofing / Poisoning

The attacker sends crafted ARP Replies (or Gratuitous ARPs) to associate their own MAC address with the IP of a legitimate host (typically the gateway).

This is **not** a flood. It's targeted poisoning: you send periodic ARP replies to the victim(s) saying *"the gateway IP is at [attacker MAC]"*. The victim updates its cache and starts forwarding traffic to the attacker.

To maintain the poisoning, replies are sent at regular intervals (every 1-2s) because dynamic ARP entries expire.

### Man-in-the-Middle (MITM)

Once ARP poisoning is in place, the attacker sits between the victim and the gateway. The attacker must enable **IP forwarding** to relay packets, otherwise the victim loses connectivity.

From this position:
- **Sniff traffic** — capture cleartext credentials, HTTP, etc.
- **SSL stripping** — downgrade HTTPS to HTTP using tools like `sslstrip` (less effective today due to HSTS)
- **DNS spoofing** — modify DNS responses to redirect the victim to attacker-controlled servers

### Tools

| Tool          | Usage                                                     |
|---------------|-----------------------------------------------------------|
| `arpspoof`    | Simple ARP poisoning (part of `dsniff` suite)             |
| `ettercap`    | ARP poisoning + MITM + plugin system                     |
| `bettercap`   | Modern successor to ettercap, scriptable, active project  |
| `scapy`       | Craft custom ARP packets in Python (useful for tooling)   |
