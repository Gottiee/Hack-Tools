# VLAN (Virtual Local Area Network)

## Table of Contents

1. [Overview](#overview)
2. [How VLANs Work](#how-vlans-work)
   - [802.1Q Tagging](#8021q-tagging)
   - [Access vs Trunk Ports](#access-vs-trunk-ports)
3. [Exploitation](#exploitation)
   - [Switch Spoofing](#switch-spoofing)
   - [Double Tagging](#double-tagging)
   - [Tools](#tools)

---

## Overview

Divides a single physical network into multiple **isolated broadcast domains** at Layer 2. Hosts on different VLANs cannot communicate without a router (or L3 switch) — it's like being on separate physical networks.

Each VLAN has an ID (1–4094). VLAN 1 is the default and is often the **native VLAN** (important for double tagging).

## How VLANs Work

### 802.1Q Tagging

When a frame needs to travel between switches (over a trunk link), a **4-byte 802.1Q tag** is inserted into the Ethernet frame header containing the VLAN ID.

When the frame arrives at the destination switch, the tag is read to determine which VLAN it belongs to, then the tag is **stripped** before delivering to the end host.

A trunk is not a "bridge between two VLANs" — it's a link between switches that **carries traffic for multiple VLANs** simultaneously, each frame tagged with its VLAN ID.

### Access vs Trunk Ports

- **Access port** — connected to an end device (PC, server). Belongs to a single VLAN. Frames are **untagged** — the switch adds/removes the tag internally.
- **Trunk port** — connected to another switch or router. Carries frames from **multiple VLANs**, each tagged with 802.1Q.

Key detail: the **native VLAN** on a trunk is sent **untagged**. This is what makes double tagging possible.

## Exploitation

### Switch Spoofing

The attacker's machine negotiates a trunk link with the switch using **DTP (Dynamic Trunking Protocol)**. If the switch port is set to `dynamic auto` or `dynamic desirable` (common defaults on Cisco), it will accept the negotiation.

Once the trunk is established, the attacker receives traffic from **all VLANs** carried on that trunk and can send frames into any of them.

This works because the attacker pretends to be a switch, not because they forge frames — the switch willingly opens the trunk.

### Double Tagging

The attacker sends a frame with **two 802.1Q tags**:
1. Outer tag = **native VLAN** (e.g., VLAN 1)
2. Inner tag = **target VLAN** (e.g., VLAN 50)

What happens:
1. The first switch sees the outer tag matches the native VLAN → **strips it** (native VLAN is sent untagged on trunk).
2. The frame goes out on the trunk with only the **inner tag** remaining (VLAN 50).
3. The second switch delivers the frame to VLAN 50.

Limitations:
- **One-way only** — responses come back to VLAN 50, not to the attacker. No bidirectional communication.
- Only works if the attacker is on the **native VLAN**.
- Only works across **trunk links**.

### Tools

| Tool        | Usage                                                  |
|-------------|--------------------------------------------------------|
| `yersinia`  | DTP attacks (switch spoofing), VLAN hopping            |
| `frogger`   | VLAN hopping (double tagging)                          |
| `scapy`     | Craft double-tagged 802.1Q frames manually in Python   |
