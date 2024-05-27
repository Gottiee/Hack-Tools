# Call a function

Gdb allow you to call a uncall function, even print it result:

## jump func()

```py
b <func>
jump <func>
```

## 

## Print

### Print <type> func(arg1, arg2)

```py
print (<type>)test2("arg1","arg2")
```

ex: 

```py
print (int)addition(1,2)
$1 = 0x3
```

### Print char * func()

```py
print ((char *(*)()) printFlag)()
```

---

[**:arrow_right_hook: Back GDB**](/tools/gdb/gdb-gef.md)