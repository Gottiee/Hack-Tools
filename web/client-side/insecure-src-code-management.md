# Insecure Source Code Management

Insecure Source Code Management refers to the inadequate protection and handling of source code repositories, leading to vulnerabilities and potential unauthorized access to sensitive code.

Following the best practices in cybersecurity, the .git directory should not be accessible to the public, but some software engineers are neglecting this practice and are simply uploading the entire project to the internet, and this is when information leaks occur.

### Table of content


## Finding .git repo

### Google Searching

By simply searching for the following Google Dork `intitle:"Index of /.git"`, any user can find websites with a publicly exposed and accessible Git Repository.

### Shodan

Shodan is the search engine for everything on the internet. Using the following query `http.title:"Index of /" http.html:".git"`, it will return you a list of websites with exposed .git repository.

## Tools

[Downloading src code from a .git url](https://github.com/Gottiee/Extract-Git-Src-Code)

### Documentation

- [blog secuna.io](https://blog.secuna.io/insecure-source-code-management/)

---

[**:arrow_right_hook: Back home**](/README.md)