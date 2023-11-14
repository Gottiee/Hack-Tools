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

Many applications that place user input into file paths implement defenses against path traversal attacks. These can often be bypassed.

If an application strips or blocks directory traversal sequences from the user-supplied filename, it might be possible to bypass the defense using a variety of techniques.

- Absolute path from the filesystem root, such as `filename=/etc/passwd`, to directly reference a file without using any traversal sequences.
- nested traversal sequences, such as ....// or ....\/. These revert to simple traversal sequences when the inner sequence is stripped. Because application could erase every `../` existing so `....//` become -> `../`.
- encode it standart: `%2e%2e%2f` OR non-standart: `..%c0%af`
- double encode it standart: `%252e%252e%252f` OR non-standart: `..%ef%bc%8f`

if an application ask to end with `.png` you can bypass it with: `filename=../../../etc/passwd%00.png`

---

[**:arrow_right_hook: Back home**](/README.md)