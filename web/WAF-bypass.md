# WAF bypass XSS

WAF is a firewall which Using a set of rules to distinguish between normal requests and malicious requests and Sometimes they use a learning mode to add rules automatically through learning about user behaviour.

### Table of content

- [blocked tag / attribute](#blocked-tag--attribute)
    - [Only custome tags allowed](#only-custom-tag-allowed)

## Blocked tag / attribute

[here](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) you can found all tags/attribute to brut force with burpsuite.

First find a tag allowed, then an attribute allowed.

:warning: Only one body tag is allow by HTML, it gonna erase the second one and give it attribute to the first one.

[WAF bypass github](https://github.com/0xInfection/Awesome-WAF#evasion-techniques)
### Only custom tag allowed

Custome tags can be create this way: 

```HTML
<mytag></mytag>
<!--or-->
<mytag>
```

This tags inherited from their parents basic attribute.

```HTML
<custome id="ez" onfocus=alert() tabindex=1>
```

Exlanation:

- `id` : use to create an anchor to trigger the onfocus event
- `onfocus` : is triggered when an element is focused
- `tabindex` : allow an element to catch the focus (the int `1` indicate in which order)

:warning: dont forget to use `#ez` at the end of the URL to create an anchor and focus on the attribute to trigger the `onfocus`