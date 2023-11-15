# Authentification

Authentication vulnerabilities can allow attackers to gain access to sensitive data and functionality. They also expose additional attack surface for further exploits. For this reason, it's important to learn how to identify and exploit authentication vulnerabilities, and how to bypass common protection measures.

## Table of content

- [Vulnerabilities in password-based login](#vulnerabilities-in-password-based-login)
    - [Brut Force Attack](#brut-force-attack)
    - [Brut Force with Burpsuite](/tools/burpsuite/brutforce.md)
    - [UserName Enumeration](#username-enumeration)
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

## ByPass 2FA (two Factor Authentification)

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