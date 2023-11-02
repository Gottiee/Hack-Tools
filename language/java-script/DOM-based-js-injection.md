# DOM-based JavaScript injection

DOM-based JavaScript-injection vulnerabilities arise when a script executes attacker-controllable data as JavaScript. An attacker may be able to use the vulnerability to construct a URL that, if visited by another user, will cause arbitrary JavaScript supplied by the attacker to execute in the context of the user's browser session.

## vulnerable sinks

```js
eval()
Function()
setTimeout()
setInterval()
setImmediate()
execCommand()
execScript()
msSetImmediate()
range.createContextualFragment()
crypto.generateCRMFRequest()
```