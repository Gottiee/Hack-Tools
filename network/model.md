# Network Models

## 1. OSI Model

| # | Layer | Protocols | Equipment |
|---|-------|-----------|-----------|
| 7 | Application | HTTP, DHCP, DNS, FTP, SSH, SMTP, SNMP | WAF, Proxy, Load Balancer |
| 6 | Presentation | SSL/TLS, JPEG, ASCII, MIME, GZip | - |
| 5 | Session | NetBIOS, RPC, SOCKS, PPTP | - |
| 4 | Transport | TCP, UDP | Firewall L4 |
| 3 | Network | IPv4, IPv6, ICMP, ARP, OSPF, BGP | Router |
| 2 | Data Link | Ethernet, Wi-Fi (802.11), PPP | Switch, Bridge |
| 1 | Physical | Electrical signals, fiber optics, radio waves | Cable, Hub, Repeater |

---

## 2. TCP/IP Model

| # | Layer | OSI Equivalence |
|---|-------|-----------------|
| 4 | Application | Session + Presentation + Application (5-6-7) |
| 3 | Transport | Transport (4) |
| 2 | Internet | Network (3) |
| 1 | Network Access | Data Link + Physical (1-2) |

---

## 3. Differences OSI vs TCP/IP

| Criteria | OSI | TCP/IP |
|----------|-----|--------|
| Layers | 7 | 4 |
| Origin | ISO standard (theoretical) | DARPA / real implementation |
| Approach | Describes how networking **should** work | Describes how networking **actually** works on the Internet |
| Usage | Reference model for teaching & troubleshooting layer by layer | Practical model used to build protocols and debug real traffic |
| Protocols | Model first, protocols assigned after | Protocols first (TCP, IP), model built around them |
| Session / Presentation | Dedicated layers | Merged into Application |
