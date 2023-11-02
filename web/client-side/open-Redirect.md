# Open Redirect

"Open Redirect" is a web vulnerability that allows attackers to send users from a trusted website to a harmful one. It happens when a website uses user input in a way that can be manipulated, leading to potential security risks like phishing attacks or data theft.

### Talbe of Content

- [Theory](#theory)
- [Common sinks which lead to DOM-based open redirection](#common-sinks-which-lead-to-dom-based-open-redirection)
- [Exploit](#exploit)

## Common sinks which lead to DOM-based open redirection

```js
location
location.host
location.hostname
location.href
location.pathname
location.search
location.protocol
location.assign()
location.replace()
open()
element.srcdoc
XMLHttpRequest.open()
XMLHttpRequest.send()
jQuery.ajax()
$.ajax()
```

## Theory

Open Redirect occur when a user can redirect a web page to his own webpage:

Imagine `https://normal-site.com` can take as get method: `https://normal-site.com?url="https://twitter.com"`

It redirect user Without checking anything.

So `https://normal-site.com?url="https://phising.com"` will work.

I send you a mail to recover your google web authentification with this link: `https://google.com/auth/redirect?url="https://phising.com"`

It seems to be a normal secure google.com link so you authentificate yourself and booom, you've been hacked !

## Exploit

To exploit it you need to understand how url are accepted in the uri, if no check are perform you can pass any website.

So `https://normal-site.com?url="https://phising.com"` will work.

---

[**:arrow_right_hook: Back home**](/README.md)
