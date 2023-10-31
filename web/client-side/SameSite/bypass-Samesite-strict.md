# Bypassing SameSite Strict restrictions

## Bypassing SameSite Strict restrictions using on-site gadgets

If a cookie is set with the `SameSite=Strict` attribute, browsers won't include it in any cross-site requests. You may be able to get around this limitation if you can find a gadget that results in a secondary request within the same site.

One possible gadget is a client-side redirect that dynamically constructs the redirection target using attacker-controllable input like URL parameters. 

One possible gadget could be [open redirect]() because you send the user to infected open redirect page which gonna redirect the user to the same site to perform malicious actions. Same-site strict is bypass, because it give cookies between same site !

## Bypassing SameSite restrictions via vulnerable sibling domains

Whether you're testing someone else's website or trying to secure your own, it's essential to keep in mind that a request can still be same-site even if it's issued cross-origin.

In addition to classic CSRF, don't forget that if the target website supports WebSockets, this functionality might be vulnerable to cross-site WebSocket hijacking (CSWSH), which is essentially just a CSRF attack targeting a WebSocket handshake. For more details, see our topic on WebSocket vulnerabilities.

```c
// work to do here 
```

---

[**:arrow_right_hook: Back home**](/README.md)