# Routing

## Table of Contents

- [1. Overview](#1-overview)
- [2. Static vs Dynamic Routing](#2-static-vs-dynamic-routing)
- [3. Routing Protocols](#3-routing-protocols)
  - [3.1 IGP (Interior Gateway Protocols)](#31-igp-interior-gateway-protocols)
  - [3.2 EGP (Exterior Gateway Protocol)](#32-egp-exterior-gateway-protocol)
- [4. BGP Hijacking](#4-bgp-hijacking)
- [5. Source Routing](#5-source-routing)

---

## 1. Overview

Routing is the process of **selecting a path** for traffic across one or more networks. When a packet leaves a host, it needs to find its way to the destination — which may be on the same local network or on the other side of the internet, crossing dozens of routers.

Each router maintains a **routing table** — a list of rules that says "to reach network X, forward the packet to next-hop Y via interface Z."

```
Example routing table (simplified):
Destination        Next Hop         Interface    Metric
10.0.1.0/24        directly connected   eth0       0
10.0.2.0/24        10.0.1.1             eth0       1
0.0.0.0/0          10.0.1.254           eth0       10     ← default route
```

**How a router decides:**
1. Packet arrives with destination IP `10.0.2.50`
2. Router checks its routing table for the **most specific match** (longest prefix)
3. `10.0.2.0/24` matches → forward to next-hop `10.0.1.1` via `eth0`
4. If no match → use the **default route** (`0.0.0.0/0`)
5. If no default route → drop the packet, send ICMP Destination Unreachable

---

## 2. Static vs Dynamic Routing

**Static routing:** Routes are **manually configured** by an administrator. They don't change unless someone edits them.

```bash
# Linux: add a static route
ip route add 10.0.2.0/24 via 10.0.1.1

# Cisco: add a static route
ip route 10.0.2.0 255.255.255.0 10.0.1.1

# Windows: add a static route
route add 10.0.2.0 mask 255.255.255.0 10.0.1.1
```

**Dynamic routing:** Routers run a **routing protocol** that automatically discovers neighbors, exchanges route information, and adapts when the network topology changes (link goes down, new router added, etc.).

| Criteria | Static | Dynamic |
|----------|--------|---------|
| Configuration | Manual | Automatic |
| Adapts to changes | No (must be updated by admin) | Yes (converges automatically) |
| CPU/bandwidth usage | None | Protocol overhead |
| Scale | Small networks | Large networks |
| Security | Less attack surface | Protocol can be spoofed/poisoned |
| Use case | Home router, small office, default route | Enterprise, ISP, datacenter |

**Your home router example:** The router has a static default route pointing to your ISP's gateway. It doesn't need dynamic routing because there's only one path out. But inside an enterprise network with redundant links and hundreds of routers, dynamic routing is mandatory.

---

## 3. Routing Protocols

The key distinction is **where** the protocol operates:

- **IGP (Interior Gateway Protocol):** Routing **within** a single organization's network (called an Autonomous System / AS)
- **EGP (Exterior Gateway Protocol):** Routing **between** different organizations / Autonomous Systems on the internet

```
        AS 100 (Company A)              AS 200 (Company B)
    ┌──────────────────────┐        ┌──────────────────────┐
    │  OSPF / EIGRP / RIP  │        │  OSPF / EIGRP / RIP  │
    │   (IGP - internal)   │        │   (IGP - internal)   │
    │                      │        │                      │
    │  R1 ──── R2 ──── R3 ─┼── BGP ─┼─ R4 ──── R5 ──── R6 │
    │          │            │ (EGP)  │          │           │
    │          R7           │        │          R8          │
    └──────────────────────┘        └──────────────────────┘
```

### 3.1 IGP (Interior Gateway Protocols)

| Protocol | Full Name | Algorithm | Usage |
|----------|-----------|-----------|-------|
| RIP | Routing Information Protocol | Distance Vector (hop count, max 15) | Legacy, small networks. Simple but slow to converge. Almost never used in production today. |
| OSPF | Open Shortest Path First | Link-State (Dijkstra's algorithm) | Most common IGP. Open standard. Builds a complete map of the network topology and computes the shortest path. Fast convergence. |
| EIGRP | Enhanced Interior Gateway Routing Protocol | Hybrid (Distance Vector + Link-State features) | Cisco proprietary (now partially open). Very fast convergence. Common in Cisco-only environments. |
| IS-IS | Intermediate System to Intermediate System | Link-State | Used by large ISPs and datacenters. Similar to OSPF but scales better for very large networks. |

**Distance Vector vs Link-State:**
- **Distance Vector** (RIP): Each router only knows its direct neighbors and their advertised distances. Like asking for directions at each intersection — "how far is the destination?" Slow, limited view.
- **Link-State** (OSPF, IS-IS): Each router has a **complete map** of the entire network. Like having a GPS. Faster convergence, better decisions, more CPU/memory usage.

### 3.2 EGP (Exterior Gateway Protocol)

| Protocol | Full Name | Usage |
|----------|-----------|-------|
| BGP | Border Gateway Protocol (v4) | **The only EGP in use today.** Routes traffic between Autonomous Systems on the internet. Every ISP, cloud provider, and large enterprise uses BGP. It is literally the protocol that holds the internet together. |

BGP is a **path vector** protocol. Instead of just counting hops, it tracks the **full AS path** (list of Autonomous Systems the route traverses). Routers choose routes based on policies (business relationships, cost, performance) rather than just shortest path.

```
Route to 8.8.8.8 (Google DNS):
  Path 1: AS100 → AS200 → AS15169 (Google)     ← 2 AS hops
  Path 2: AS100 → AS300 → AS400 → AS15169       ← 3 AS hops
  BGP prefers Path 1 (shorter AS path, but policies can override)
```

**BGP is based on trust.** Routers announce which IP prefixes they own, and their neighbors believe them. There is **no built-in authentication** of route ownership. This is what makes BGP hijacking possible.

---

## 4. BGP Hijacking

BGP hijacking is when an attacker (or a misconfigured router) **announces IP prefixes it doesn't own**. Since BGP is based on trust, neighboring routers accept the announcement and start routing traffic for those prefixes to the attacker.

**How it works:**

```
Normal: Traffic to 1.2.3.0/24 → AS200 (legitimate owner)

Attack: AS666 announces "I own 1.2.3.0/24" (or more specific: 1.2.3.0/25)
  → BGP routers prefer more specific prefixes
  → Internet starts routing 1.2.3.0/24 traffic to AS666

Result:
  - Traffic interception (MITM on a massive scale)
  - Denial of service (traffic blackholed)
  - Credential theft (redirect users to fake services)
```

**Real-world examples:**
- **2018 — Amazon Route 53 hijack:** Attackers hijacked Amazon DNS IPs via BGP to redirect cryptocurrency traffic and steal $150,000 in Ethereum
- **2022 — Russia hijacked Twitter/Facebook prefixes** during the Ukraine conflict
- **Pakistan accidentally hijacked YouTube (2008):** Pakistan Telecom announced YouTube's prefix to block it domestically, but the announcement leaked globally → YouTube was down worldwide for hours

**Why it's dangerous:**
- Affects the **entire internet**, not just one network
- Can be used to intercept TLS traffic if combined with fraudulent certificates
- Difficult to detect quickly (can take minutes to hours)

**Mitigations:**
- **RPKI (Resource Public Key Infrastructure):** Cryptographically signs route origins so routers can verify that an AS is authorized to announce a prefix. Adoption is growing but still incomplete (~40% of routes in 2025).
- **BGP monitoring services:** detect anomalous announcements (BGPStream, RIPE RIS)
- **Route filtering:** ISPs filter customer announcements to only accept prefixes they're authorized to announce

---

## 5. Source Routing

Normally, **routers decide** the path a packet takes (hop by hop). Source routing flips this: the **sender specifies the exact route** the packet must follow, listing every router it should pass through.

**Two types in IPv4:**
- **Loose Source Routing (LSRR):** Packet must pass through the listed routers, but can take any path between them
- **Strict Source Routing (SSRR):** Packet must follow the exact path specified, no deviations

**Why it's dangerous:**

```
Normal:  Attacker → Router A → Router B → Target
         (routers choose the path, attacker has no control)

Source Routing:  Attacker sets route: Attacker → Trusted Server → Target
         (packet appears to come from Trusted Server's network)
         → Can bypass IP-based access controls
         → Can bypass firewalls that trust certain source IPs/networks
         → Can map internal network topology
```

**Why it's disabled by default:**
- Almost every modern OS and router **drops source-routed packets**
- Linux: `net.ipv4.conf.all.accept_source_route = 0` (default)
- Cisco: `no ip source-route` (default since IOS 12.0)
- Windows: disabled since Windows XP SP2

The risk is only relevant on legacy or misconfigured equipment. But it's still worth knowing for pentesting old infrastructure.

```bash
# Check if source routing is disabled (Linux)
sysctl net.ipv4.conf.all.accept_source_route
# Expected: 0

# Test with nmap (will fail on modern systems)
nmap --ip-options "L 10.0.0.1 10.0.0.2" <target>
```
