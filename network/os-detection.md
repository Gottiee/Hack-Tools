# OS Detection (Remote Fingerprinting)

## Table of Contents

- [1. Overview](#1-overview)
- [2. TCP Window Size](#2-tcp-window-size)
- [3. TTL (Time To Live)](#3-ttl-time-to-live)

---

## 1. Overview

Different operating systems implement the TCP/IP stack differently. These implementation details leak information in every packet sent, allowing an attacker to **guess the remote OS without any authentication**. This is called passive or active OS fingerprinting.

Tools: `nmap -O`, `p0f` (passive), `xprobe2`

---

## 2. TCP Window Size

Each OS sets a different **default initial window size** in the first SYN packet. Since this is hardcoded in the TCP/IP stack before any negotiation, it acts as a fingerprint.

| OS | Default Initial Window Size |
|----|-----------------------------|
| Linux 2.6+ | 5840 |
| Linux 4.x+ | 29200 |
| Linux 5.x+ | 64240 |
| Windows XP | 65535 |
| Windows 7/8 | 8192 |
| Windows 10/11 | 64240 |
| Windows Server 2019+ | 64240 |
| macOS | 65535 |
| FreeBSD | 65535 |
| Cisco IOS | 4128 |

> **Note:** These values can be tuned by sysadmins, so window size alone is not 100% reliable. It is one signal among many that tools like nmap combine together.

---

## 3. TTL (Time To Live)

The TTL is set to a default value by the OS when a packet is created. Each router decrements it by 1. By looking at the TTL of a received packet, you can estimate the original value and deduce the OS.

| OS | Default TTL |
|----|-------------|
| Linux | 64 |
| macOS | 64 |
| Windows | 128 |
| Cisco / Solaris | 255 |
| FreeBSD | 64 |

**How to use it:**

If you receive a packet with `TTL=118`, the original value was likely `128` (128 - 10 hops = 118), which means **Windows**.

If you receive `TTL=52`, the original was likely `64` (64 - 12 hops = 52), which means **Linux or macOS**.

```bash
# Quick check with ping
ping -c 1 <target>

# Nmap OS detection (uses TTL + window size + many other probes)
nmap -O <target>

# Passive fingerprinting (sniff traffic without sending anything)
p0f -i eth0
```
