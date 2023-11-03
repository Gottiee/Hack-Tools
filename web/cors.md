# CORS (Cross-origin resource sharing)

CORS (Cross-Origin Resource Sharing) is a security feature implemented by web browsers that controls how web pages in one domain can request and interact with resources from another domain.

### Table of content 

- [Same-origin policy (SOP)](#same-origin-policy-sop)
- [Access-Control-Allow-Origin](#access-control-allow-origin)
    - [Handling cross-origin resource requests with credentials](#handling-cross-origin-resource-requests-with-credentials)
    - [Pre-flight checks](#pre-flight-checks)

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