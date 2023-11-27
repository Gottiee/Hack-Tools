# Authentification

Authentication vulnerabilities can allow attackers to gain access to sensitive data and functionality. They also expose additional attack surface for further exploits. For this reason, it's important to learn how to identify and exploit authentication vulnerabilities, and how to bypass common protection measures.

## Table of content

- [Vulnerabilities in password-based login](#vulnerabilities-in-password-based-login)
    - [Brut Force Attack](#brut-force-attack)
    - [Brut Force with Burpsuite](/tools/burpsuite/brutforce.md)
    - [UserName Enumeration](#username-enumeration)
    - [Flawed brute-force protection](#flawed-brute-force-protection)
    - [Account locking](#account-locking)
    - [User rate limiting](#user-rate-limiting)
    - [HTTP basic authentication](#http-basic-authentication)
- [Vulnerabilities in multi-factor authentication](#vulnerabilities-in-multi-factor-authentication)
    - [Bypass 2FA](#bypass-2fa-two-factor-authentification)


## Vulnerabilities in password-based login

### Brut Force Attack

A brute force attack is an attempt to gain unauthorized access to a system or account by trying a large number of possible passwords or combinations until the correct one is found.

### Brut force with BuprSuite

[BurpSuite Brut Force](/tools/burpsuite/brutforce.md)

### Username Enumeration

There is 3 way to determine if a username was found:

- Status codes: During a brute-force attack, the returned HTTP status code is likely to be the same for the vast majority of guesses because most of them will be wrong. If a guess returns a different status code, this is a strong indication that the username was correct.
- Error messages: Sometimes the returned error message is different depending on whether both the username AND password are incorrect or only the password was incorrect.
- Response times: If most of the requests were handled with a similar response time, any that deviate from this suggest that something different was happening behind the scenes.

### Flawed brute-force protection

It is highly likely that a brute-force attack will involve many failed guesses before the attacker successfully compromises an account. Logically, brute-force protection revolves around trying to make it as tricky as possible to automate the process and slow down the rate at which an attacker can attempt logins. The two most common ways of preventing brute-force attacks are:

- Locking the account that the remote user is trying to access if they make too many failed login attempts
- Blocking the remote user's IP address if they make too many login attempts in quick succession

Both approaches offer varying degrees of protection, but neither is invulnerable, especially if implemented using flawed logic.

For example, you might sometimes find that your IP is blocked if you fail to log in too many times. In some implementations, the counter for the number of failed attempts resets if the IP owner logs in successfully. This means an attacker would simply have to log in to their own account every few attempts to prevent this limit from ever being reached.

In this case, merely including your own login credentials at regular intervals throughout the wordlist is enough to render this defense virtually useless.

#### Account locking

One way in which websites try to prevent brute-forcing is to lock the account if certain suspicious criteria are met, usually a set number of failed login attempts. Just as with normal login errors, responses from the server indicating that an account is locked can also help an attacker to enumerate usernames.

### User rate limiting

Another way websites try to prevent brute-force attacks is through user rate limiting. In this case, making too many login requests within a short period of time causes your IP address to be blocked. Typically, the IP can only be unblocked in one of the following ways:

- Automatically after a certain period of time has elapsed
- Manually by an administrator
- Manually by the user after successfully completing a CAPTCHA

User rate limiting is sometimes preferred to account locking due to being less prone to username enumeration and denial of service attacks. However, it is still not completely secure. As we saw an example of in an earlier lab, there are several ways an attacker can manipulate their apparent IP in order to bypass the block.

As the limit is based on the rate of HTTP requests sent from the user's IP address, it is sometimes also possible to bypass this defense if you can work out how to guess multiple passwords with a single request.

Example mutilple password attempt in one request: 

Initial request:

```json
{
    "username":"test",
    "password":"test"
}
```

Attack request:

```json
{
    "username":"test",
    "password": [
        "123456",
        "test",
        "qwerty"
    ]
}
```

### HTTP basic authentication

Although fairly old, its relative simplicity and ease of implementation means you might sometimes see HTTP basic authentication being used. In HTTP basic authentication, the client receives an authentication token from the server, which is constructed by concatenating the username and password, and encoding it in Base64. This token is stored and managed by the browser, which automatically adds it to the Authorization header of every subsequent request as follows:

```
Authorization: Basic base64(username:password)
```

For a number of reasons, this is generally not considered a secure authentication method. Firstly, it involves repeatedly sending the user's login credentials with every request. Unless the website also implements HSTS, user credentials are open to being captured in a man-in-the-middle attack.

In addition, implementations of HTTP basic authentication often don't support brute-force protection. As the token consists exclusively of static values, this can leave it vulnerable to being brute-forced.

HTTP basic authentication is also particularly vulnerable to session-related exploits, notably CSRF, against which it offers no protection on its own.

## Vulnerabilities in multi-factor authentication

### ByPass 2FA (two Factor Authentification)

Let suppose the website follow this way:

*`->` means the operation is sucessfull*

- `https://simple.net/login` -> `https://simple.net/2fA` -> `https://simple.net/my-account`

2FA often lead user to it home page: `https://simple.net/my-account`

Some time, it doesnt check if we have correctly pass the 2FA:

- `https://simple.net/login` -> (well connected) `https://simple.net/2fA` :cross
- redirect `https://simple.net/2fA` to `https://simple.net/my-account` and it will fake a sucess full 2FA !

### Documentation

- [portSwigger](https://portswigger.net/web-security/learning-paths/server-side-vulnerabilities-apprentice/authentication-apprentice/authentication/multi-factor/lab-2fa-simple-bypass)

---

[**:arrow_right_hook: Back home**](/README.md)