# DNS (Domain Name System)

## Table of Contents

1. [Overview](#overview)
2. [How DNS Works](#how-dns-works)
   - [Resolution Process](#resolution-process)
   - [Key Record Types](#key-record-types)
3. [Packet Structure](#packet-structure)
4. [DNSSEC](#dnssec)
5. [Exploitation](#exploitation)
   - [DNS Enumeration](#dns-enumeration)
   - [Zone Transfer (AXFR)](#zone-transfer-axfr)
   - [DNS Spoofing](#dns-spoofing)
   - [DNS Tunneling](#dns-tunneling)
   - [Tools](#tools)

---

## Overview

Translates domain names to IP addresses (and vice versa via reverse lookups). Runs on **port 53** — UDP for standard queries, TCP for zone transfers and responses larger than 512 bytes.

DNS has **no built-in authentication**, which is why DNSSEC exists as a separate layer.

## How DNS Works

### Resolution Process

1. Client sends a query to its configured **recursive resolver** (e.g., `8.8.8.8`).
2. Resolver checks its **cache**. On cache miss:
   - Queries a **root server** (`.`) → gets referred to the TLD server (e.g., `.com`)
   - Queries the **TLD server** → gets referred to the **authoritative server** for the domain (e.g., `example.com`)
   - Queries the **authoritative server** → gets the final answer (the IP)
3. Resolver **caches** the result (respects TTL) and returns it to the client.

### Key Record Types

| Type    | Purpose                            | Red team relevance                     |
|---------|------------------------------------|----------------------------------------|
| `A`     | Domain → IPv4                      | Target IP discovery                    |
| `AAAA`  | Domain → IPv6                      | Hidden IPv6 targets                    |
| `MX`    | Mail server for the domain         | Target mail infra, phishing            |
| `NS`    | Authoritative name servers         | Zone transfer targets                  |
| `TXT`   | Arbitrary text (SPF, DKIM, etc.)   | Info leak, SPF misconfig               |
| `CNAME` | Alias to another domain            | Subdomain takeover if dangling         |
| `PTR`   | IP → Domain (reverse lookup)       | Recon, identify hosts                  |
| `SOA`   | Zone metadata (serial, admin)      | Admin email leak                       |

## Packet Structure

| Field          | Size      | Description                                          |
|----------------|-----------|------------------------------------------------------|
| Transaction ID | 2 bytes   | Matches request to response — critical for spoofing  |
| Flags          | 2 bytes   | QR (query/response), Opcode, RCODE, etc.             |
| Questions      | 2 bytes   | Number of questions                                  |
| Answer RRs     | 2 bytes   | Number of answer records                             |
| Authority RRs  | 2 bytes   | Number of authority records                          |
| Additional RRs | 2 bytes   | Number of additional records                         |

Header = **12 bytes** fixed, followed by variable-length question and answer sections.

For spoofing, the attacker needs to match the **Transaction ID** + **source port** of the original query.

## DNSSEC

DNSSEC adds **cryptographic signatures** to DNS responses, allowing the client to verify that the answer actually comes from the authoritative server and hasn't been tampered with.

How it works:
- The authoritative server signs its records with a private key.
- The client (or resolver) verifies the signature using the corresponding public key, which is published as a `DNSKEY` record.
- A chain of trust goes from the root zone down to the domain, each level signing the keys of the level below (via `DS` records).

What it **does** protect against: forged DNS responses (spoofing, cache poisoning).

What it **does not** protect against: DNS enumeration, zone transfers, tunneling. It only guarantees authenticity, not confidentiality.

In practice, DNSSEC adoption is still incomplete — many domains don't enable it.

## Exploitation

### DNS Enumeration

Discover subdomains and records to map the attack surface of a target.

Techniques:
- **Brute-force subdomains** — query a wordlist (`admin.target.com`, `dev.target.com`, ...)
- **Reverse lookups** — PTR queries on IP ranges to find hostnames
- **Record dumping** — query all useful record types (A, MX, NS, TXT, SOA) for a domain
- **Passive recon** — certificate transparency logs, search engines, public datasets

### Zone Transfer (AXFR)

A zone transfer replicates the **entire DNS zone** from an authoritative server. It's meant for syncing secondary DNS servers, but if misconfigured, anyone can request it.

```bash
dig axfr @ns1.target.com target.com
```

If it works, you get **every record** in the zone in one query — full map of the target's DNS infrastructure. Most servers today block this, but it's always worth checking.

### DNS Spoofing

Inject a forged DNS response to redirect the victim to an attacker-controlled IP.

Two scenarios:
- **Via MITM** (e.g., ARP poisoning) — intercept the DNS query and reply before the real server does. Straightforward if you're already on the path.
- **Remote (Kaminsky attack)** — race the legitimate response by brute-forcing the **Transaction ID** and **source port**. Much harder but doesn't require being on the local network.

DNSSEC prevents this if enabled — the forged response won't have a valid signature.

### DNS Tunneling

Encode data inside DNS queries/responses to exfiltrate data or establish a C2 channel through firewalls that allow outbound DNS.

How it works:
- Data is encoded (base32/base64) as subdomain labels: `aGVsbG8.tunnel.attacker.com`
- The attacker controls the authoritative server for `attacker.com` and decodes the data
- Responses carry data back in TXT or CNAME records

Slow bandwidth but effective for bypassing firewalls that don't inspect DNS content.

### Tools

| Tool          | Usage                                                    |
|---------------|----------------------------------------------------------|
| `dig`         | Manual DNS queries, zone transfers, record inspection    |
| `dnsenum`     | Automated enumeration, zone transfer, brute-force        |
| `subfinder`   | Passive subdomain discovery (APIs, cert transparency)    |
| `dnsrecon`    | Full DNS recon: zone transfer, enum, reverse lookup      |
| `iodine`      | DNS tunneling (C2 / exfil)                               |
| `dnscat2`     | Encrypted C2 channel over DNS                            |
| `responder`   | Poison LLMNR/NBT-NS/mDNS to capture hashes (local net)  |
