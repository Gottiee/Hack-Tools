# Template injection

Server-Side Template Injection (SSTI) is a vulnerability that occurs when an application allows an attacker to inject malicious content into a template, which is then executed on the server side. This can lead to various security risks, including data leakage, remote code execution, or the manipulation of the server's behavior.

### Table of Content

- [Theory](#theory)
- [Detect](#detect)
- [PlainText context](#plaintext-context)
- [Code context](#code-context)
- [Identify](#identify)
- **[Exploit](#exploit)**

## Theory

Server-side template injection vulnerabilities arise when user input is concatenated into templates rather than being passed in as data.

```js
$output = $twig->render("Dear " . $_GET['name']);
```

In this example, instead of a static value being passed into the template, part of the template itself is being dynamically generated using the GET parameter name. As template syntax is evaluated server-side, this potentially allows an attacker to place a server-side template injection payload inside the name parameter as follows:

`http://vulnerable-website.com/?name={{bad-stuff-here}}`

A secure version of the code would be: 

```js
$output = $twig->render("Dear {first_name},", array("first_name" => $user.first_name) );
```

## Detect

Server-side template injection vulnerabilities often go unnoticed not because they are complex but because they are only really apparent to auditors who are explicitly looking for them. If you are able to detect that a vulnerability is present, it can be surprisingly easy to exploit it. This is especially true in unsandboxed environments.

As with any vulnerability, the first step towards exploitation is being able to find it. Perhaps the simplest initial approach is to try fuzzing the template by injecting a sequence of special characters commonly used in template expressions, such as

```js
${{<%[%'"}}%\
```
If an exception is raised, this indicates that the injected template syntax is potentially being interpreted by the server in some way. This is one sign that a vulnerability to server-side template injection may exist.

## PlainText context

For example, consider a template that contains the following vulnerable code:

```js
render('Hello ' + username)
```

During auditing, we might test for server-side template injection by requesting a URL such as: `http://vulnerable-website.com/?username=${7*7}`

If the resulting output contains Hello 49, this shows that the mathematical operation is being evaluated server-side. This is a good proof of concept for a server-side template injection vulnerability.

## Code context

In other cases, the vulnerability is exposed by user input being placed within a template expression:

```js
greeting = getQueryParameter('greeting')
engine.render("Hello {{"+greeting+"}}", data)
```

On the website, the resulting URL would be something like: `http://vulnerable-website.com/?greeting=data.username`

This would be rendered in the output to Hello Carlos, for example.

This context is easily missed during assessment because it doesn't result in obvious XSS and is almost indistinguishable from a simple hashmap lookup. One method of testing for server-side template injection in this context is to first establish that the parameter doesn't contain a direct XSS vulnerability by injecting arbitrary HTML into the value:

```
http://vulnerable-website.com/?greeting=data.username<tag>
```

In the absence of XSS, this will usually either result in a blank entry in the output (just Hello with no username), encoded tags, or an error message. The next step is to try and break out of the statement using common templating syntax and attempt to inject arbitrary HTML after it:

```
http://vulnerable-website.com/?greeting=data.username}}<tag>
```

If this again results in an error or blank output, you have either used syntax from the wrong templating language or, if no template-style syntax appears to be valid, server-side template injection is not possible. Alternatively, if the output is rendered correctly, along with the arbitrary HTML, this is a key indication that a server-side template injection vulnerability is present: `Hello Carlos<tag>`

## Identify

Once you have detected the template injection potential, the next step is to identify the template engine.

Simply submitting invalid syntax is often enough because the resulting error message will tell you exactly what the template engine is, and sometimes even which version. For example, the invalid expression `<%=foobar%>` triggers the following response from the Ruby-based ERB engine:

```html
(erb):1:in `<main>': undefined local variable or method `foobar' for main:Object (NameError)
from /usr/lib/ruby/2.5.0/erb.rb:876:in `eval'
from /usr/lib/ruby/2.5.0/erb.rb:876:in `result'
from -e:4:in `<main>'
```

Otherwise: 

![template decision tree](/web/img/template-decision-tree.png)

## Exploit

To exploit, first use the [detect](#detect) payload and see if there is some metacharacter unprint or an error.

Then read the doc of the template to exploit it well !

:warning: *In addition to providing the fundamentals of how to create and use templates, the documentation may also provide some sort of "Security" section. The name of this section will vary, but it will usually outline all the potentially dangerous things that people should avoid doing with the template. This can be an invaluable resource, even acting as a kind of cheat sheet for which behaviors you should look for during auditing, as well as how to exploit them.*

### Look for known exploits

Once you are able to identify the template engine being used, you should browse the web for any vulnerabilities that others may have already discovered. Due to the widespread use of some of the major template engines, it is sometimes possible to find well-documented exploits that you might be able to tweak to exploit your own target website.

---

[**:arrow_right_hook: Back home**](/README.md)