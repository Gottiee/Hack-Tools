# Gdb Calcul Offset Overflow

Gdb as command line to help us calcul overflow offset.

```gdb
>pattern create 100
[+] Generating a pattern of 100 bytes (n=8)
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
[+] Saved as '$_gef0'
>run
send malicious input:
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
```

At this point lets say the program has crash

```gdb
>x/xg rbp
0x7fffffffe418: 0x6161616161616166
> pattern search 0x6161616161616166
[+] Searching '0x6161616161616166'
[+] Found at offset 40 (little-endian search) likely
[+] Found at offset 33 (big-endian search)
```

We know that offset is 40, we need add 40 byte of trash before adding new return adress.

---

[**:arrow_right_hook: Back GDB**](/tools/gdb/gdb-gef.md)