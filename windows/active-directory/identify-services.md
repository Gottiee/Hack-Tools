# Identifying services

Identifying services during an Active Directory pentest is crucial for understanding the network's attack surface and pinpointing potential vulnerabilities that can be exploited.

### Table of Content

- [Identify Domain Computer](#identify-domain-computer)
- **List of services**
- [NetBios](#netbios)
    - [Tools Netbios](#tools-netbios)
- [SMB](#smb)
    - [Common Share](#common-share)
    - [Tools SMB](#tools-smb)
- [Kerberos](#kerberos)
    - [Possible attack](#possible-attack-with-kerberos)
- [SMTP](#smtp)

## Identify Domain Computer

To identify the domain computer, the following three services must be running: 

- LDAP
- Kerberos
- DNS

## NetBios

NETBIOS is a protocol that allows applications on different computers to communicate within a local area network (LAN). It provides services related to the session layer of the OSI model, allowing applications to establish and manage connections, as well as share data.

**Ports**

- 135
- 137
- 138
- 139 (netbios SMB)

Key Features:

- **Name Service**: Provides name registration and resolution, allowing computers to identify each other by name rather than by IP address.
- **Session Service**: Establishes and manages sessions between applications on different computers.
- **Datagram Distribution Service**: Manages the distribution of data packets.

**Benefits in Active Directory (AD) Pentesting**

- **Network Enumeration**: NETBIOS can be used to discover and enumerate machines within the network, identifying potential targets for further investigation.
- **Service Identification**: By querying NETBIOS, pentesters can gather information about the services running on different machines, which helps in identifying vulnerabilities.
- **Domain Information**: NETBIOS can provide valuable information about domain structure, including domain controllers and other critical infrastructure components.

### Tools Netbios

- `nmblookup -A <ip>`
- `enum4linux -A X.X.X.X`
- `nbtscan <IP>/30`
- `sudo nmap -sU -sV -T4 --script nbstat.nse -p137 -Pn -n <IP>`

## SMB

SMB is a network file sharing protocol used primarily in Windows environments to allow applications and users to read and write to files and request services from server programs in a computer network.

**Common Ports**

- 445
- 139 (NetBios / RPC)

Key Features:

- File Sharing: SMB enables shared access to files, printers, and serial ports between nodes on a network.
- Network Browsing: Facilitates the discovery of shared resources within a network.
- Authentication: Uses NTLM or Kerberos for authentication within a Windows Active Directory (AD) environment.
- Communication: Provides a way for client machines to communicate with network resources such as files, printers, and services.

**Benefits in Active Directory (AD) Pentesting**

- Network Enumeration:
    - Resource Discovery: SMB can be used to enumerate shares, printers, and other resources within the network.
    - Host Identification: Pentesters can identify machines and their roles within the AD environment (e.g., domain controllers, member servers).
- Information Gathering:
    - User and Group Information: SMB can reveal detailed information about users, groups, and other entities within the domain.
    - Access Permissions: Insight into access permissions on shared resources can help identify potential weaknesses.
- Credential Harvesting:
    - SMB Relay Attacks: Can be used to capture and relay credentials, allowing attackers to authenticate to other network services.
    - NTLM Hash Extraction: Tools like Responder can capture NTLM hashes which can then be cracked or relayed.
- Exploiting Vulnerabilities:
    - EternalBlue: SMB vulnerabilities such as those exploited by EternalBlue can allow remote code execution.
    - Privilege Escalation: Misconfigured SMB shares or permissions can lead to privilege escalation within the network.
- Lateral Movement:
    - Accessing Sensitive Data: SMB allows attackers to move laterally by accessing files and directories across different machines.
    - Spreading Malware: Malware and ransomware often leverage SMB to propagate across the network.

### Common Share

- IPC$ (Inter-Process Communication)
    - Access to the IPC$ share can be obtained through an anonymous null session, allowing for interaction with services exposed via named pipes.$
- C$ (Admin Share)
    - Administrators for remote administration and management.
- ADMIN$ (Administrative Share)
    - A hidden share for the Windows directory, typically C:\Windows. Used for remote administration.
- NETLOGON
    - A share containing logon scripts and policies for users and computers in a domain. Located on domain controllers.
- SYSVOL
    - A share on domain controllers that stores the server copy of the domain’s public files, which are necessary for domain-wide operations.
    - `grep 'cpassword='` (mdp en claire)
- Backups
    - Shares dedicated to storing backups of critical data. Often used by backup services or scripts

### Tools SMB

- `smbclient -L <ip>`
- `enum4linux -A target_ip`
- `nxc smb -h`

## Kerberos

Kerberos is an authentication protocol used within Windows Active Directory (AD) environments to verify the identities of users and services. It is based on symmetric key cryptography and works through a ticketing system, which helps to ensure secure authentication and communication within a network.

**How Kerberos Works**

- Authentication Service (AS) Request/Response:
    - When a user logs in, their client machine sends a request to the Key Distribution Center (KDC), specifically to the Authentication Service.
    - The KDC verifies the user's credentials and, if valid, issues a Ticket Granting Ticket (TGT). This TGT is encrypted with the user's password hash and can only be decrypted by the KDC.
- Ticket Granting Service (TGS) Request/Response:
    - The client now uses the TGT to request access to a specific service (e.g., a file server) from the Ticket Granting Service (also part of the KDC).
    - The TGS validates the TGT and issues a Service Ticket (ST), which the client can then use to authenticate to the requested service.
- Service Request/Response:
    - The client presents the Service Ticket to the target service.
    - If the ticket is valid, the service grants access to the client.

**Key Components:**

- Key Distribution Center (KDC): The trusted third-party server that issues tickets. It consists of two services:
    - Authentication Service (AS)
    - Ticket Granting Service (TGS)
- Ticket Granting Ticket (TGT): A ticket used to obtain service tickets.
- Service Ticket (ST): A ticket used to access a specific service.

### Possible attack with kerberos

- Kerberoasting:
    - *Description*: An attack where an attacker requests service tickets for service accounts and attempts to crack them offline.
    - `GetUserSPNs.py DOMAIN.local/user:password123 -outputfile ticket.txt`
- Pass-the-Ticket (PtT):
    -  An attacker uses a stolen TGT or ST to authenticate to services without needing the user's password.
    - dump tgt /tgs ticket from memory
- AS-REP Roasting:
    -  An attack that targets user accounts not requiring pre-authentication.
    - Identifying users with DONT_REQUIRE_PREAUTH set and capturing their AS-REP responses.
    - `GetNPUsers.py -request -format hashcat -outputfile ASREProastables.txt -usersfile users.txt -dc-ip "$DC_IP" "$DOMAIN"`

### SMTP

SMTP, or Simple Mail Transfer Protocol, is a protocol used for sending and receiving email.

- Information Gathering: By querying the SMTP service, testers can gather information about the email server, such as supported authentication mechanisms, available commands, and the software version in use. This information can help identify potential vulnerabilities.
- Credential Harvesting: SMTP servers that support authentication may allow penetration testers to capture and crack email credentials. These credentials can then be used for further attacks within the organization.
- Privilege Escalation and Lateral Movement: By compromising email accounts, testers can potentially escalate privileges and move laterally within the network. Email accounts often have access to sensitive information and can be used to reset passwords or gain access to other systems.

**Account brut force**

- `swaks`

### SNMP

SNMP, or Simple Network Management Protocol, is a protocol used for network management, enabling administrators to manage network performance, find and solve network problems, and plan for network growth.

Listing account : `snmpwalk -c public <ip>`

### LDAP

LDAP, or Lightweight Directory Access Protocol, is a protocol used for accessing and managing directory services. It contains information about all the objects within the AD environment, such as users, groups, computers, and other resources.

In pentest, we can gather informations about the database with those commands:

- `ldapsearch`
- `enum4linux -A X.X.X.X`
- `nxc ldap`

### RDP

RDP, or Remote Desktop Protocol, is a proprietary protocol developed by Microsoft that allows users to connect to and control a remote computer over a network connection.

Port : **3398**

- `nmap -p 3389 --script rdp-ntlm-info <target_ip>`

- Linux tool for connect to the rdp server:
    - `xfreerdp`
- Connection interface : `xfreerdp -sec-nla /v:IP`


