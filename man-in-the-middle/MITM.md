# Man in the middle

A Man-in-the-Middle (MITM) attack occurs when an attacker intercepts and potentially alters the communication between two parties without their knowledge, allowing the attacker to eavesdrop, steal sensitive information, or inject malicious data.

### Table of content

- [All OS](#all-os)
- [Linux](#linux)
- [Windows](#windows)

## All OS

### DHCP spoofing

DHCP spoofing is a Man-in-the-Middle attack where the attacker sets up a rogue DHCP server on the network to respond to DHCP requests, thereby assigning themselves as the default gateway and DNS server, allowing them to intercept and manipulate network traffic.

### arp poisoning

ARP poisoning is a Man-in-the-Middle attack where the attacker sends falsified ARP (Address Resolution Protocol) messages to associate their MAC address with the IP address of another host, enabling them to intercept, modify, or block data intended for that host.

- `ettercap -T -q -i eth0 -M  ARP /ip_victime1// /ip_victime2//`
- `arpspoof`

### Dns spoofing

DNS spoofing, a type of Man-in-the-Middle attack, involves the manipulation of DNS resolution queries and responses to redirect traffic to a malicious server. By corrupting the DNS cache with false information, attackers can deceive users into visiting spoofed websites or redirect legitimate traffic to malicious destinations.

- `bettercap`
- `dnsspoof`

## Linux

## Windows