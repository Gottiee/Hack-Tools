# TCP (Transmission Control Protocol)

## Table of Contents

- [1. Overview](#1-overview)
- [2. TCP Flags](#2-tcp-flags)
- [3. Connection Lifecycle](#3-connection-lifecycle)
  - [3.1 Three-Way Handshake (Opening)](#31-three-way-handshake-opening)
  - [3.2 Four-Way Teardown (Closing)](#32-four-way-teardown-closing)
  - [3.3 TCP States](#33-tcp-states)
- [4. Sequence & Acknowledgment Numbers](#4-sequence--acknowledgment-numbers)
  - [4.1 How They Work](#41-how-they-work)
  - [4.2 Security Importance](#42-security-importance)
  - [4.3 TCP Sequence Prediction Attack](#43-tcp-sequence-prediction-attack)
- [5. TCP Window Size](#5-tcp-window-size)
  - [5.1 How It Works](#51-how-it-works)
  - [5.2 OS Fingerprinting via Window Size](#52-os-fingerprinting-via-window-size)
- [6. Idle Scan (Zombie Scan)](#6-idle-scan-zombie-scan)

---

## 1. Overview

TCP is a **connection-oriented**, **reliable** transport layer (Layer 4) protocol. Before any data is exchanged, both sides must establish a connection (three-way handshake). TCP guarantees:

- **Delivery**: every segment is acknowledged. If no ACK is received, the sender retransmits.
- **Order**: sequence numbers ensure data is reassembled in the correct order, even if segments arrive out of order.
- **Integrity**: a checksum in the header detects corrupted data.
- **Flow control**: the receiver advertises how much data it can handle (window size) to prevent being overwhelmed.

TCP is used by protocols that need reliability: HTTP, SSH, FTP, SMTP, etc.

---

## 2. TCP Flags

| Flag | Name | Role |
|------|------|------|
| SYN | Synchronize | Initiates a connection. The sender proposes an Initial Sequence Number (ISN). |
| ACK | Acknowledge | Confirms receipt of data. The ack number tells the sender "I received everything up to this byte, send the next." |
| FIN | Finish | Gracefully terminates a connection. The sender says "I have no more data to send." |
| RST | Reset | Abruptly kills a connection. No negotiation, the connection is immediately destroyed. Sent when something is wrong (e.g. packet received on a closed port). |
| PSH | Push | Tells the receiver to **immediately deliver the data to the application** instead of waiting for the buffer to fill up. Normally, TCP accumulates data in a buffer before passing it to the application. PSH bypasses this and forces instant delivery. Used in interactive protocols (SSH keystrokes, HTTP responses). |
| URG | Urgent | Signals that some data in the segment is urgent and should be processed before other data. The Urgent Pointer field indicates where the urgent data ends. Rarely used in practice. |
| ECE | ECN-Echo | Used for congestion notification. The receiver tells the sender "I received a congestion signal from the network." |
| CWR | Congestion Window Reduced | The sender's response to ECE: "I received your congestion warning and I slowed down." |

---

## 3. Connection Lifecycle

### 3.1 Three-Way Handshake (Opening)

```
Client                           Server
  |                                |
  |  ---- SYN (seq=100) ------->  |   1. Client picks an ISN (100) and sends SYN
  |                                |
  |  <--- SYN-ACK --------------  |   2. Server picks its own ISN (300) and
  |       (seq=300, ack=101)       |      acknowledges client's ISN+1
  |                                |
  |  ---- ACK (ack=301) ------->  |   3. Client acknowledges server's ISN+1
  |                                |
  |     CONNECTION ESTABLISHED     |
```

**Why 3 steps?** Both sides need to agree on initial sequence numbers. SYN exchanges the client's ISN, SYN-ACK exchanges the server's ISN + confirms the client's, ACK confirms the server's. This ensures both sides are synchronized.

### 3.2 Four-Way Teardown (Closing)

```
Client                           Server
  |                                |
  |  ---- FIN ----------------->  |   1. Client says "I'm done sending"
  |                                |
  |  <--- ACK -----------------  |   2. Server acknowledges
  |                                |      (server can still send data here)
  |                                |
  |  <--- FIN -----------------  |   3. Server says "I'm done too"
  |                                |
  |  ---- ACK ----------------->  |   4. Client acknowledges
  |                                |
  |     CONNECTION CLOSED          |
```

**Why 4 steps instead of 3?** Because closing is **asymmetric**. When the client sends FIN, it only means "I'm done sending." The server might still have data to send. So the server first ACKs the client's FIN, finishes sending its remaining data, then sends its own FIN. That's why there are 2 separate FIN+ACK exchanges.

**RST alternative:** Either side can send RST at any point to immediately destroy the connection without negotiation. No FIN/ACK exchange needed.

### 3.3 TCP States

| State | Side | Description |
|-------|------|-------------|
| CLOSED | Both | No connection exists. |
| LISTEN | Server | Waiting for an incoming SYN (server has a port open). |
| SYN_SENT | Client | SYN sent, waiting for SYN-ACK from server. |
| SYN_RECEIVED | Server | SYN received, SYN-ACK sent, waiting for final ACK. |
| ESTABLISHED | Both | Three-way handshake complete. Data can flow both ways. |
| FIN_WAIT_1 | Initiator | FIN sent, waiting for ACK from the other side. |
| FIN_WAIT_2 | Initiator | ACK received for our FIN, waiting for the other side's FIN. |
| TIME_WAIT | Initiator | Other side's FIN received and ACK sent. Waits 2x MSL (Max Segment Lifetime, typically 60s) before fully closing, to ensure the last ACK was received. |
| CLOSE_WAIT | Receiver | Received FIN from the other side, ACK sent. Waiting for the local application to close its end. |
| LAST_ACK | Receiver | FIN sent after CLOSE_WAIT, waiting for the final ACK. |

```
Client state flow:    CLOSED -> SYN_SENT -> ESTABLISHED -> FIN_WAIT_1 -> FIN_WAIT_2 -> TIME_WAIT -> CLOSED
Server state flow:    CLOSED -> LISTEN -> SYN_RECEIVED -> ESTABLISHED -> CLOSE_WAIT -> LAST_ACK -> CLOSED
```

---

## 4. Sequence & Acknowledgment Numbers

### 4.1 How They Work

Every byte of data sent over TCP is assigned a **sequence number**. The acknowledgment number tells the sender which byte the receiver expects next.

**Example: sending "HELLO" (5 bytes)**

```
1. Client sends: seq=100, data="HEL" (3 bytes)
   → Client is saying: "Here are bytes 100, 101, 102"

2. Server responds: ack=103
   → Server is saying: "I received everything up to byte 102. Send byte 103 next."

3. Client sends: seq=103, data="LO" (2 bytes)
   → Client sends bytes 103, 104

4. Server responds: ack=105
   → "Got everything. Next expected byte: 105"
```

**Lost packet scenario:**

```
1. Client sends: seq=100, data="HEL" (3 bytes)       → arrives
2. Client sends: seq=103, data="LO"  (2 bytes)       → LOST
3. Client sends: seq=105, data=" WO" (3 bytes)        → arrives

4. Server responds: ack=103  (duplicate ACK)
   → "I still need byte 103, everything after is out of order"

5. Client retransmits: seq=103, data="LO"             → arrives

6. Server responds: ack=108
   → "Got everything now up to byte 107"
```

### 4.2 Security Importance

Sequence numbers are critical for security because TCP uses them to **validate that a segment belongs to a legitimate connection**. If an attacker can guess or predict the sequence number, they can:

- **Inject data** into an existing connection (TCP injection)
- **Hijack a session** by sending a RST with the right sequence number to kill a legitimate connection, then take over
- **Spoof a connection** without ever seeing the server's response (blind spoofing)

Modern OS use **randomized ISN** (Initial Sequence Number) to make prediction nearly impossible. Older systems (pre-2000s) used predictable patterns (incremental, time-based).

### 4.3 TCP Sequence Prediction Attack

The **ISN (Initial Sequence Number)** is the first sequence number chosen by each side during the three-way handshake. If the ISN generation is **predictable**, an attacker can perform a blind spoofing attack:

```
1. Attacker connects to server multiple times to observe ISN pattern
   → Notices ISN increments by ~64000 each time

2. Attacker spoofs source IP as trusted_host (e.g. 10.0.0.5)

3. Attacker sends SYN to server with src=10.0.0.5
   → Server sends SYN-ACK to real 10.0.0.5 (attacker never sees it)

4. Attacker PREDICTS the server's ISN based on the pattern
   → Sends ACK with ack=predicted_ISN+1

5. If prediction is correct: connection is established
   → Attacker can now send commands as 10.0.0.5 (e.g. rsh, rlogin)
```

**Mitigations:**
- RFC 6528: randomized ISN generation (all modern OS)
- Encryption (SSH instead of rsh/rlogin)
- IP source validation (ingress filtering)

---

## 5. TCP Window Size

### 5.1 How It Works

The TCP window size is a value in the TCP header that tells the sender: **"I can receive up to X bytes before you need to wait for my ACK."** It is a **flow control** mechanism.

Each side of the connection advertises its own window size independently. The window size changes dynamically during the connection based on how fast the receiver can process data.

```
Example:
  Server advertises window = 65535 bytes

  Client sends 16000 bytes → window remaining: 49535
  Client sends 16000 bytes → window remaining: 33535
  Server processes data, sends ACK with window = 65535 (refilled)
  Client can send 65535 bytes again
```

If the receiver is overwhelmed, it shrinks the window. If it sends `window=0`, the sender must **stop completely** and wait (zero window probe).

### 5.2 OS Fingerprinting via Window Size

Each operating system sets a **different default initial window size** in the SYN packet. Since this value is set before any negotiation, it acts as a fingerprint. Tools like `nmap -O` and `p0f` use this (among other TCP/IP stack characteristics) to guess the remote OS.

See [OS Detection](/network/os-detection.md) for the full table and other detection methods.

---

## 6. Idle Scan (Zombie Scan)

### What is IP ID?

Every IP packet has an **Identification field** (IP ID) in its header. It is used to reassemble fragmented packets. Many operating systems increment this value **globally by 1** for each packet sent. This predictable behavior is what makes the idle scan possible.

**Important limitation:** The zombie machine must have a **globally incremental IP ID**. This is increasingly rare on modern OS (Linux randomizes IP ID, Windows uses per-connection counters since Vista). You need to find a truly idle machine with old/simple IP ID behavior (old printers, embedded devices, legacy servers).

### How It Works

The attacker never sends a single packet to the target from their own IP. They use a zombie machine as a proxy to determine port state.

```
STEP 1: Probe zombie's current IP ID
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Attacker              Zombie
  |  -- SYN/ACK -->     |         Attacker sends unsolicited SYN/ACK
  |  <-- RST (ID=100)   |         Zombie replies RST (no connection exists)
  |                      |         Attacker notes: IP ID = 100

STEP 2: Send spoofed SYN to target
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Attacker                            Target
  |  -- SYN (src=zombie) -------->    |    Attacker sends SYN pretending to be zombie
  |                                   |

  Case A: Port OPEN                 Case B: Port CLOSED
  Target -> Zombie: SYN-ACK        Target -> Zombie: RST
  Zombie -> Target: RST (ID=101)   Zombie does nothing (ignores RST)
  (zombie's IP ID incremented!)    (zombie's IP ID stays the same)

STEP 3: Probe zombie's IP ID again
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Attacker              Zombie
  |  -- SYN/ACK -->     |
  |  <-- RST (ID=?)     |

  If ID=102 → port is OPEN  (zombie sent 1 extra packet: the RST to target)
  If ID=101 → port is CLOSED (zombie sent nothing to target)
```

**Advantages:**
- Completely stealthy: target only sees packets from the zombie IP, never from the attacker
- Can bypass IP-based firewall rules (if zombie IP is trusted)

**Nmap command:**
```bash
nmap -sI <zombie_ip> <target>
```
