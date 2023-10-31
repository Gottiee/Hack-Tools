# Command injection

OS command injection is also known as shell injection. It allows an attacker to execute operating system (OS) commands on the server that is running an application, and typically fully compromise the application and its data. Often, an attacker can leverage an OS command injection vulnerability to compromise other parts of the hosting infrastructure, and exploit trust relationships to pivot the attack to other systems within the organization.

## Usefull command to execute

linux | windows | info
--- | --- | ---
`whoami` | `whoami` | current user name
`uname -a` | `ver` | operating system
`ifconfig` | `ipconfig /all` | network conf
`netstat -an` | `netstat -an` | network connections
`ps -ef` | `tasklist` | running process

### Documentation

- [portswigger](https://portswigger.net/web-security/os-command-injection)

---

[**:arrow_right_hook: Back home**](/README.md)