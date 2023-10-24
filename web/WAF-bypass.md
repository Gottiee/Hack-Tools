# WAF bypass XSS

WAF is a firewall which Using a set of rules to distinguish between normal requests and malicious requests and Sometimes they use a learning mode to add rules automatically through learning about user behaviour.

## Blocked tag / attribute

[here](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) you can found all tags/attribute to brut force with burpsuite.

First find a tag allowed, then an attribute allowed.

:warning: Only one body tag is allow by HTML, it gonna erase the second one and give it attribute to the first one.

[WAF bypass github](https://github.com/0xInfection/Awesome-WAF#evasion-techniques)
