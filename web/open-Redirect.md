# Open Redirect

"Open Redirect" is a web vulnerability that allows attackers to send users from a trusted website to a harmful one. It happens when a website uses user input in a way that can be manipulated, leading to potential security risks like phishing attacks or data theft.

### Talbe of Content

- [Theory](#theory)
- [Exploit](#exploit)
	- [Server Side](#server-side)

## Theory

Open Redirect occur when a user can redirect a web page to his own webpage:

Imagine `https://normal-site.com` can take as get method: `https://normal-site.com?url="https://twitter.com"`

It redirect user Without checking anything.

So `https://normal-site.com?url="https://phising.com"` will work.

I send you a mail to recover your google web authentification with this link: `https://google.com/auth/redirect?url="https://phising.com"`

It seems to be a normal secure google.com link so you authentificate yourself and booom, you've been hacked !


## Exploit

### Server Side

To exploit it on the server side, you need to understand how url are accepted in the uri, if no check are perform you can pass any website.

So `https://normal-site.com?url="https://phising.com"` will work.

---

[**:arrow_right_hook: Back home**](/README.md)
