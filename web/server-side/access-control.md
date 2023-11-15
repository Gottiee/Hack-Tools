# Acess Control

Access control is the application of constraints on who or what is authorized to perform actions or access resources. In the context of web applications, access control is dependent on authentication and session management: 

- Authentication confirms that the user is who they say they are.
- Session management identifies which subsequent HTTP requests are being made by that same user. 
- Access control determines whether the user is allowed to carry out the action that they are attempting to perform.

## Table of Content

- [Unprotected functionality](#unprotected-functionality)
    - [Dirb](#dirb)
    - [Obfuscated Urls](#obfuscated-urls)
- [Parameter-based access control method](#parameter-based-access-control-method)
    - [Cookie demonstration](#cookie-demonstration)
- [Broken access control resulting from platform misconfiguration](#broken-access-control-resulting-from-platform-misconfiguration)
- [Horizontal privilerge escaladation](#horizontal-privilerge-escaladation)
- [Insecure direct object references](#insecure-direct-object-references)
- [Access control vulnerabilities in multi-step processes](#access-control-vulnerabilities-in-multi-step-processes)
- [Referer-based access control](#referer-based-access-control)

## Unprotected functionality

At its most basic, vertical privilege escalation arises where an application does not enforce any protection for sensitive functionality. For example, administrative functions might be linked from an administrator's welcome page but not from a user's welcome page.

Example : `https://insecure-website.com/admin`

### Dirb

Use [dirb](/tools/dirb.md) to brute-force the location of sensitive functionality

### Obfuscated Urls

Html page can leaks sensitive informations about hidden URL :

```js
var isAdmin = false;
if (isAdmin) {
   var topLinksTag = document.getElementsByClassName("top-links")[0];
   var adminPanelTag = document.createElement('a');
   adminPanelTag.setAttribute('href', '/admin-h8guc9');
   adminPanelTag.innerText = 'Admin panel';
   topLinksTag.append(adminPanelTag);
   var pTag = document.createElement('p');
   pTag.innerText = '|';
   topLinksTag.appendChild(pTag);
}
```

In this example, if the user is an admin, it display a new <a href="/admin-h8guc9"></a> in the adminPanelTag.

## Parameter-based access control method

Some applications determine the user's access rights or role at login, and then store this information in a user-controllable location. This could be:

- A hidden field.
- A cookie.
- A preset query string parameter.

Example:

`https://insecure-website.com/login/home.jsp?admin=true`
`https://insecure-website.com/login/home.jsp?role=1`

### Cookie demonstration:

When we connect and analys the answers we can see a cookie Admin:

```
HTTP/2 302 Found
Location: /my-account?id=wiener
Set-Cookie: Admin=false; Secure; HttpOnly
Set-Cookie: session=8xDYx9scde3EA0fBAJeUtfOenxss3jAe; Secure; HttpOnly; SameSite=None
X-Frame-Options: SAMEORIGIN
Content-Length: 0
```

If we had the cookie or change it values when sending the request we can act like the admin.

## Broken access control resulting from platform misconfiguration

Some applications enforce access controls at the platform layer. they do this by restricting access to specific URLs and HTTP methods based on the user's role. For example, an application might configure a rule as follows: `DENY: POST, /admin/deleteUser, managers`

This rule denies access to the POST method on the URL /admin/deleteUser, for users in the managers group. Various things can go wrong in this situation, leading to access control bypasses.

Some application frameworks support various non-standard HTTP headers that can be used to override the URL in the original request, such as X-Original-URL and X-Rewrite-URL. If a website uses rigorous front-end controls to restrict access based on the URL, but the application allows the URL to be overridden via a request header, then it might be possible to bypass the access controls using a request like the following:

```
GET /?usename=admin HTTP/1.1
X-Original-URL: /admin/deleteUser
...
```

OR try to change Request method (POSTX | PUT ...)

## Horizontal privilerge escaladation

Horizontal privilege escalation occurs if a user is able to gain access to resources belonging to another user.

Example:

when we access to a user blog the url display this: `https://web-security.net/blogs?userId=8cebb120-7d26-448b-b149-9a8055158712`

And when we display my-account page, parameters takes user id to display so we can pass blogger user's ID:

`https://web-security.net/my-account?id=8cebb120-7d26-448b-b149-9a8055158712`

This Technique can be use to acess administrator account and escalad privileg. 

In some cases, an application does detect when the user is not permitted to access the resource, and returns a redirect to the login page. However, the response containing the redirect might still include some sensitive data belonging to the targeted user, so the attack is still successful.

## Insecure direct object references

Insecure direct object references (IDORs) are a subcategory of access control vulnerabilities. IDORs occur if an application uses user-supplied input to access objects directly and an attacker can modify the input to obtain unauthorized access. It was popularized by its appearance in the OWASP 2007 Top Ten. It's just one example of many implementation mistakes that can provide a means to bypass access controls.

Example : `https://banquier.net/quote?quote=234quote.txt` download your quote.

but if you change `234` per another number you can dowload others users quotes: `https://banquier.net/quote?quote=11quote.txt`

## Access control vulnerabilities in multi-step processes

Many websites implement important functions over a series of steps. This is common when:

- A variety of inputs or options need to be captured.
- The user needs to review and confirm details before the action is performed.

For example, the administrative function to update user details might involve the following steps:

- Load the form that contains details for a specific user.
- Submit the changes.
- Review the changes and confirm.

Sometimes, a website will implement rigorous access controls over some of these steps, but ignore others. Imagine a website where access controls are correctly applied to the first and second steps, but not to the third step. The website assumes that a user will only reach step 3 if they have already completed the first steps, which are properly controlled. An attacker can gain unauthorized access to the function by skipping the first two steps and directly submitting the request for the third step with the required parameters.

## Referer-based access control

Some websites base access controls on the Referer header submitted in the HTTP request. The Referer header can be added to requests by browsers to indicate which page initiated a request.

For example, an application robustly enforces access control over the main administrative page at /admin, but for sub-pages such as /admin/deleteUser only inspects the Referer header. If the Referer header contains the main /admin URL, then the request is allowed.

In this case, the Referer header can be fully controlled by an attacker. This means that they can forge direct requests to sensitive sub-pages by supplying the required Referer header, and gain unauthorized access.

### Documentation

- [portswigger](https://portswigger.net/web-security/learning-paths/server-side-vulnerabilities-apprentice/access-control-apprentice/access-control/what-is-access-control)

---

[**:arrow_right_hook: Back home**](/README.md)