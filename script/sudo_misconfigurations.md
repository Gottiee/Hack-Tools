# Sudo Misconfigurations 

###Table of Contents

- [List Availables Commands](#list-availables-commands)

## List Availables Commands

#### Documentation
[Man sudo](https://linux.die.net/man/8/sudo).<br>
[Sudo explanations](https://www.linuxtricks.fr/wiki/sudo-utiliser-et-parametrer-sudoers).<br>

#### Explanation
The command `sudo -l`, `If no command is specified, the -l (list) option will list the allowed (and forbidden) commands for the invoking user (or the user specified by the -U option) on the current host` from the man, show us which commands we can use as sudo.<br>
`sudo <cmd>` allow us to run the <cmd> as the super user -> **IT GIVE US ALL RIGHT**.

#### Exemples
```
$sudo -l
user $USER may run the following commands
/bin/cat
$sudo /bin/cat /etc/passwd
```
* *this will never been that easy but who knows* *
