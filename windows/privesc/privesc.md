# Windows privilege escalation

### Table of content

- [dll injection](#dll-injection)
- [unprotected path](#unprotected-path)
- [scheduled task](#scheduled-task)
- [always install elevated](#always-install-elevated)
- [autorun](#autorun)
- [cve](#cve)
- [tools](#tools)

## dll injection

DLL injection, an attack technique used to run arbitrary code in the address space of another process by injecting a dynamic-link library (DLL), allows attackers to execute malicious code and potentially take control of the targeted application.

## unprotected path

Unprotected path privilege escalation is an attack where an attacker exploits writable directories to execute malicious binaries with elevated privileges when a legitimate program runs.

## scheduled task

Windows scheduled task privilege escalation is an attack where an attacker exploits misconfigured or vulnerable scheduled tasks to gain elevated privileges on the system.

## always install elevated

Windows "AlwaysInstallElevated" privilege escalation is an attack where an attacker leverages a misconfigured policy that allows any user to install MSI packages with elevated (administrative) privileges, potentially gaining full control over the system.

## autorun

Windows autorun privilege escalation is an attack where an attacker takes advantage of the autorun functionality to execute malicious code with elevated privileges whenever the system starts or a specific event triggers.

## cve

Windows CVE-based privilege escalation is an attack where an attacker exploits a known vulnerability (Common Vulnerabilities and Exposures) in the Windows operating system to gain higher privileges on the system.

## tools

- [winpeas] to analyse the entire system and try to detect privesc (https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS)