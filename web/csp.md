# CSP (Content Security Policy)

Content Security Policy (CSP) is a web security feature that helps prevent cross-site scripting (XSS) and other code injection attacks by allowing website owners to specify which sources of content are trusted and which are not.

### Table of content

- [How it works](#how-csp-works)
    - [Defining resources](#defining-resources)
    - [Directives](#directives)
    - [Sources](#sources)
- [Exploit](#exploit)
    -[unsafe-inline](#unsafe-inline)
- [docu](#documentation)

## How CSP works

Content Security Policy is implemented via response headers or meta elements of the HTML page. The browser follows the received policy and actively blocks violations as they are detected.

- Implemented via response header:

`Content-Security-policy: default-src 'self'; img-src 'self' allowed-website.com; style-src 'self';`

- Implemented via meta tag:

`<meta http-equiv="Content-Security-Policy" content="default-src 'self'; img-src https://*; child-src 'none';">`

#### Headers

- Content-Security-Policy
- Content-Security-Policy-Report-Only This one won't block anything, only send reports (use in Pre environment).

### Defining Resources

CSP works by restricting the origins from where active and passive content can be loaded from.

Example: 

```js
connect-src 'none';
font-src 'none';
frame-src 'none';
img-src 'self';
manifest-src 'none';
media-src 'none';
object-src 'none';
script-src 'unsafe-inline';
style-src 'self';
worker-src 'none';
frame-ancestors 'none';
block-all-mixed-content;
```

### Directives

- **script-src**: This directive specifies allowed sources for JavaScript. This includes not only URLs loaded directly into elements, but also things like inline script event handlers (onclick) and XSLT stylesheets which can trigger script execution.
- **default-src**: This directive defines the policy for fetching resources by default. When fetch directives are absent in the CSP header the browser follows this directive by default.
- **Child-src: This directive defines allowed resources for web workers and embedded frame contents.
- **connect-src**: This directive restricts URLs to load using interfaces like fetch, websocket, XMLHttpRequest
- **frame-src: This directive restricts URLs to frames that can be called out.
- **frame-ancestors**: This directive specifies the sources that can embed the current page. This directive applies to `<frame>`, `<iframe>`, `<object>`, `<embed>`, or `<applet>`. This directive can't be used in tags and applies only to non-HTML resources.
- **img-src**: It defines allowed sources to load images on the web page.
- **font-src: directive specifies valid sources for fonts loaded using @font-face.
- **manifest-src**: This directive defines allowed sources of application manifest files.
- **media-src: It defines allowed sources from where media objects can be loaded.
- **object-src**: It defines allowed sources for the `<object>`, `<embed>`, and `<applet>` elements elements.
- **base-uri: It defines allowed URLs which can be loaded using an element.
- **form-action**: This directive lists valid endpoints for submission from tags.
- **plugin-types: It defines limits on the kinds of mime types a page may invoke.
- **upgrade-insecure-requests**: This directive instructs browsers to rewrite URL schemes, changing HTTP to HTTPS. This directive can be useful for websites with large numbers of old URLs that need to be rewritten.
- **sandbox**: sandbox directive enables a sandbox for the requested resource similar to the sandbox attribute. It applies restrictions to a page's actions including preventing popups, preventing the execution of plugins and scripts, and enforcing a same-origin policy.

### Sources

- <strong>*</strong>: This allows any URL except data: , blob: , filesystem: schemes
- **self**: This source defines that loading of resources on the page is allowed from the same domain.
- **data**: This source allows loading resources via the data scheme (eg Base64 encoded images)
- **none**: This directive allows nothing to be loaded from any source.
- **unsafe-eval**: This allows the use of eval() and similar methods for creating code from strings. This is not a safe practice to include this source in any directive. For the same reason, it is named unsafe.
- **unsafe-hashes**: This allows to enable of specific inline event handlers.
- **unsafe-inline**: This allows the use of inline resources, such as inline elements, javascript: URLs, inline event handlers, and inline elements. Again this is not recommended for security reasons.
- **nonce**: A whitelist for specific inline scripts using a cryptographic nonce (number used once). The server must generate a unique nonce value each time it transmits a policy.
- **sha256-\<hash\>**: Whitelist scripts with an specific sha256 hash
- **strict-dynamic**: It allows the browser to load and execute new JavaScript tags in the DOM from any script source that has previously been whitelisted by a "nonce" or "hash" value.
- **host**: Indicate a host such as example.com

## Exploit

### unsafe-inline

`Content-Security-Policy: script-src 'unsafe-inline';`

#### Payload:

- `"/><script>alert(1);</script>`
- `<img src=1 onerror=alert(1)>`

### Documentation

- [HackTrick](https://book.hacktricks.xyz/pentesting-web/content-security-policy-csp-bypass)

---

[**:arrow_right_hook: Back home**](/README.md)
