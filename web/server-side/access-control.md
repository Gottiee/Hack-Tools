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
- [Horizontal privilerge escaladation](#horizontal-privilerge-escaladation)

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

## Horizontal privilerge escaladation

Horizontal privilege escalation occurs if a user is able to gain access to resources belonging to another user.

Example:

when we access to a user blog the url display this: `https://web-security.net/blogs?userId=8cebb120-7d26-448b-b149-9a8055158712`

And when we display my-account page, parameters takes user id to display so we can pass blogger user's ID:

`https://web-security.net/my-account?id=8cebb120-7d26-448b-b149-9a8055158712`

This Technique can be use to acess administrator account and escalad privileg. 

### Documentation

- [portswigger](https://portswigger.net/web-security/learning-paths/server-side-vulnerabilities-apprentice/access-control-apprentice/access-control/what-is-access-control)

---

[**:arrow_right_hook: Back home**](/README.md)