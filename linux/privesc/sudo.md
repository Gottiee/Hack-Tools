# Sudo Misconfigurations

Sudo allows a permitted user to execute a command as the superuser or another user, as specified by the security policy.

### Table of Contents

- [List Availables Commands](#list-availables-commands)
- [Docu](#documentation)

## List Availables Commands

#### Explanation

The command `sudo -l`, `If no command is specified, the -l (list) option will list the allowed (and forbidden) commands for the invoking user (or the user specified by the -U option) on the current host` from the man, show us which commands we can use as sudo.

`sudo <cmd>` allow us to run the \<cmd\> as the super user -> **IT GIVE US ALL RIGHT**.

#### Usage

```
$sudo -l
user $USER may run the following commands
/bin/cat
$sudo /bin/cat /etc/passwd
```

- _this will never been that easy but who knows_

### Documentation

- [Man sudo](https://linux.die.net/man/8/sudo)
- [Sudo explanations](https://www.linuxtricks.fr/wiki/sudo-utiliser-et-parametrer-sudoers)

---

[**:arrow_right_hook: Back home**](/README.md)
