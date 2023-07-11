# .pcap file

PCAP files are data files created using a program. These files contain packet data of a network and are used to analyze the network characteristics.

### Table of Contents

- [Tshark](#tshark)
- [Docu](#documentation)

## Tshark

#### Explanation

TShark is a network protocol analyzer.

It lets you capture packet data from a live network, or read packets from a previously saved capture file, either printing a decoded form of those packets to the standard output or writing the packets to a file.

#### Usage

```bash
$>tshark -r file.pcap -V
$>#-r is for read a file
$>#-V is for print packet details
```

#### Documentation

- [Man tshark](https://linux.die.net/man/1/tshark)

---

[**:arrow_right_hook:Back home**](../README.md)
