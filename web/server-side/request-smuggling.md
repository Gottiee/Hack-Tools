# HTTP request smuggling

HTTP request smuggling is a server-side attack that takes advantage of discrepancies in how web servers and proxies interpret HTTP requests, potentially leading to request manipulation, security bypasses, or the exposure of sensitive data.

### Table of Content

- **[Explanation](#explanation)**
    - [How do HTTP request smuggling vulnerabilities arise?](#how-do-http-request-smuggling-vulnerabilities-arise)
- **[Exploit](#exploit)**
    - [prepare smuggling](#prepare)
    - [Detect type of smuggling](#detect-type-of-smuggling)
    - [CL.TE vulnerabilities](#clte-vulnerabilities)

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

## Exploit

Classic request smuggling attacks involve placing both the Content-Length header and the Transfer-Encoding header into a single HTTP/1 request and manipulating these so that the front-end and back-end servers process the request differently. The exact way in which this is done depends on the behavior of the two servers:

- CL.TE: the front-end server uses the Content-Length header and the back-end server uses the Transfer-Encoding header.
- TE.CL: the front-end server uses the Transfer-Encoding header and the back-end server uses the Content-Length header.
- TE.TE: the front-end and back-end servers both support the Transfer-Encoding header, but one of the servers can be induced not to process it by obfuscating the header in some way.

### Prepare

![prepare](/web/img/prepare-smuggling.png)

### Detect type of smuggling

![detect](/web/img/detect-smugglin.png)

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

---

[**:arrow_right_hook: Back home**](/README.md)