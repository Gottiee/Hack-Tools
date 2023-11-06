# SSRF (Server Side Request Forgery)

Server-side request forgery is a web security vulnerability that allows an attacker to cause the server-side application to make requests to an unintended location. 

### Table of Content

- **Exloit**
    - [localhost server](#localhost-server)
- **Bypass defenses**
    - [SSRF with blacklist-based input filters](#ssrf-with-blacklist-based-input-filters)
    - [SSRF with whitelist-based input filters](#ssrf-with-whitelist-based-input-filters)
- [Blind SSRF](#blind-ssrf)


## Localhost server

With this POST method asking for an Api to provide it information we can divert the URL to asking him for sensible files.

If no security is provide from the server side and always trust the POST we can acess to privates files.

Regulare POST:

```
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 118

stockApi=http://stock.weliketoshop.net:8080/product/stock/check%3FproductId%3D6%26storeId%3D1
```

Divert to:

```py
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 118

stockApi=http://localhost/admin
# OR
stockApi=http://192.168.0.68/admin
```

## Bypass Defenses

## SSRF with blacklist-based input filters

Some applications block input containing hostnames like 127.0.0.1 and localhost, or sensitive URLs like /admin. In this situation, you can often circumvent the filter using the following techniques:

- Use an alternative IP representation of 127.0.0.1, such as 2130706433, 017700000001, or 127.1.
- Register your own domain name that resolves to 127.0.0.1. You can use spoofed.burpcollaborator.net for this purpose.
- Obfuscate blocked strings using URL encoding or case variation.
- Provide a URL that you control, which redirects to the target URL. Try using different redirect codes, as well as different protocols for the target URL. For example, switching from an http: to https: URL during the redirect has been shown to bypass some anti-SSRF filters.

## SSRF with whitelist-based input filters

Some applications only allow inputs that match, a whitelist of permitted values.

- You can embed credentials in a URL before the hostname, using the @ character. For example: `https://expected-host:fakepassword@evil-host` OR `https://localhost#@expected-host`
- You can use the # character to indicate a URL fragment. For example: `https://evil-host#expected-host`
- You can leverage the DNS naming hierarchy to place required input into a fully-qualified DNS name that you control. For example: `https://expected-host.evil-host`
- You can URL-encode characters to confuse the URL-parsing code. This is particularly useful if the code that implements the filter handles URL-encoded characters differently than the code that performs the back-end HTTP request. You can also try double-encoding characters; some servers recursively URL-decode the input they receive, which can lead to further discrepancies.
- You can use combinations of these techniques together.

## Bypassing SSRF filters via open redirection

It is sometimes possible to bypass filter-based defenses by exploiting an open redirection vulnerability.

For example, the application contains an open redirection vulnerability in which the following URL: `/product/nextProduct?currentProductId=6&path=http://evil-user.net`

returns a redirection to: `http://evil-user.net`

You can leverage the open redirection vulnerability to bypass the URL filter, and exploit the SSRF vulnerability as follows:

```
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 118

stockApi=http://weliketoshop.net/product/nextProduct?currentProductId=6&path=http://192.168.0.68/admin
```

This SSRF exploit works because the application first validates that the supplied stockAPI URL is on an allowed domain, which it is. The application then requests the supplied URL, which triggers the open redirection. It follows the redirection, and makes a request to the internal URL of the attacker's choosing.

## blind SSRF

Blind SSRF vulnerabilities arise when an application can be induced to issue a back-end HTTP request to a supplied URL, but the response from the back-end request is not returned in the application's front-end response.

The most reliable way to detect blind SSRF vulnerabilities is using out-of-band (OAST) techniques. This involves attempting to trigger an HTTP request to an external system that you control, and monitoring for network interactions with that system.

---

[**:arrow_right_hook: Back home**](/README.md)