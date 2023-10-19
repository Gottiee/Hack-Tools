# SQL

SQL, which stands for Structured Query Language, is a specialized programming language used for managing and interacting with relational databases. It enables users to retrieve, store, update, and delete data, making it a fundamental tool for database management and data manipulation.

## Table of Content

- [SQL injection](#sql-injection-sqli)
    - [detect injection vuln](#how-to-detect-sql-injection-vulnerabilities)
- [Comments](#comments)
- [String Concatenation](#string-concatenation)
- [Blind Injection](/language/sql/blind-injection.md)

## SQL injection (SQLi)

SQL injection (SQLi) is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. This can allow an attacker to view data that they are not normally able to retrieve. This might include data that belongs to other users, or any other data that the application can access. In many cases, an attacker can modify or delete this data, causing persistent changes to the application's content or behavior.

### How to detect SQL injection vulnerabilities

You can detect SQL injection manually using a systematic set of tests against every entry point in the application. To do this, you would typically submit:

- The single quote character `'` and look for errors or other anomalies.
- Some SQL-specific syntax that evaluates to the base (original) value of the entry point, and to a different value, and look for systematic differences in the application responses.
- Boolean conditions such as `OR 1=1` and `OR 1=2`, and look for differences in the application's responses.
- Payloads designed to trigger time delays when executed within a SQL query, and look for differences in the time taken to respond.
- OAST payloads designed to trigger an out-of-band network interaction when executed within a SQL query, and monitor any resulting interactions.

## Comments

SQL | Query
--- | ---
Oracle | `--comment`
Microsoft | `--comment` OR `/*comment*/`
PostgreSQL | `--comment` OR `/*comment*/`
MySQL | `#comment` OR `-- comment` OR `/*comment*/`

## String Concatenation

SQL | Query
--- | ---
Oracle | `'foo'||'bar'`
Microsoft | `'foo'+'bar'`
PostgreSQL | `'foo'||'bar'`
MySQL | `'foo' 'bar'` OR `CONCAT('foo','bar')`

For example, on Oracle you could submit the input:
`' UNION SELECT username || '~' || password FROM users--`

### Documentation

- [cheat sheet sql](https://portswigger.net/web-security/sql-injection/cheat-sheet)

---

[**:arrow_right_hook: Back home**](/README.md)
