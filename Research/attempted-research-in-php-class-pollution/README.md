# Attempted Research in PHP Class Pollution

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [How Does Developers Do Object Merges In PHP?](#how-does-developers-do-object-merges-in-php)
    - [Built-in Functions](#built-in-functions)
    - [Other Object Merge Methods](#other-object-merge-methods)
- [Overwriting Object's Methods?](#overwriting-objects-methods)
- [Merging on Object Attributes/Associative Array Keys](#merging-on-object-attributesassociative-array-keys)
- [Conclusion](#conclusion)

</details>

## Overview

*Update: (30/7/2025)*

I gave a talk about this attempted research in BSides Hong Kong 2025. If you preferred video to text format, try to watch the following video!

<iframe width="560" height="315" src="https://www.youtube.com/embed/DVHRZcPGCBg?si=n-oE4_p6tkR0l60B" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

[![](https://img.youtube.com/vi/DVHRZcPGCBg/0.jpg)](https://www.youtube.com/watch?v=DVHRZcPGCBg)

The above slides is also available in [https://github.com/siunam321/My-Conference-Talks/tree/main](https://github.com/siunam321/My-Conference-Talks/tree/main).

* * *

After reading the [Ruby class pollution research](https://blog.doyensec.com/2024/10/02/class-pollution-ruby.html) from [Doyensec](https://blog.doyensec.com/) and re-read [the blog post about class pollution in Python](https://blog.abdulrah33m.com/prototype-pollution-in-python/), I started to think this research question:
- If class pollution is possible in Python and Ruby, does that mean **other programming languages that support OOP** (Object-Oriented Programming) is inherently vulnerable to class pollution?

With this in my mind, I started to dig deeper into different programming language about this class pollution. The first one that I picked is PHP, as I'm quite familiar with it. Although I couldn't find a way to perform class pollution in PHP, I did found something that might be interesting.

In essence, I found that PHP class pollution only works in **merging on attributes**, both non-recursive and recursive. Which means we could replace **an object instance's attributes** or **an associative array key's value** with our malicious one.

## How Does Developers Do Object Merges In PHP?

### Built-in Functions

In PHP, it has some built-in recursive merge functions, such as [`array_merge`](https://www.php.net/manual/en/function.array-merge.php), [`array_merge_recursively`](https://www.php.net/manual/en/function.array-merge-recursive.php), and [`array_replace_recursive`](https://www.php.net/manual/en/function.array-replace-recursive.php). However, **the object must be converted into an associative array** using [type casting](https://www.php.net/manual/en/language.types.type-juggling.php#language.types.typecasting). Also, since those built-in merge functions return data type array, we need to use type casting to convert the returned array into an object instance:

```php
function merge($baseObject, $object) {
    return (object) array_merge((array) $baseObject, (array) $object);
}
```

If we try to merge a base object with another object using the above `merge` function, we can see that it returns a new instance of the **[`stdClass`](https://www.php.net/manual/en/class.stdclass.php) built-in class**:

```php
class Foo {
    public $age = 1337;
}

$foo = new Foo();
echo "[*] Before merging:\n";
print_r($foo);

$userInputObject = json_decode('{"age": 7331}');
echo "[*] After merging:\n";
$mergedObject = merge($foo, $userInputObject);
print_r($mergedObject);
```

```shell
└> php merge.php
[*] Before merging:
Foo Object
(
    [age] => 1337
)
[*] After merging:
stdClass Object
(
    [age] => 7331
)
```

Sadly, if the original object instance is converted into a `stdClass` object instance, the original object instance will lose all the methods, which means after type casting, **the merged object's methods cannot be called**:

```php
class Foo {
    public $age = 1337;

    function hello() {
        echo "world\n";
    }
}

$foo = new Foo();
echo "[*] Before merging:\n";
print_r($foo);
$foo->hello();

$userInputObject = json_decode('{"age": 7331}');
echo "[*] After merging:\n";
$mergedObject = merge($foo, $userInputObject);
print_r($mergedObject);
$mergedObject->hello();
```

```shell
└> php merge.php
[*] Before merging:
Foo Object
(
    [age] => 1337
)
world
[*] After merging:
stdClass Object
(
    [age] => 7331
)
PHP Fatal error:  Uncaught Error: Call to undefined method stdClass::hello() in /home/siunam/research/class-pollution/php/merge.php:23
Stack trace:
#0 {main}
  thrown in /home/siunam/research/class-pollution/php/merge.php on line 23
```

According to [the `stdClass` class documentation](https://www.php.net/manual/en/class.stdclass.php), this class is a generic empty class, and it's not a base class because PHP doesn't have the concept of "universal base class".

Therefore, to perform class pollution using built-in PHP functions, we need to somehow escape `stdClass` class context and pollute other classes. Unfortunately, I couldn't find a way to do so, as PHP doesn't have any special attributes that could go to a parent/other classes.

### Other Object Merge Methods

The another way to do this merging is from this blog post: [Tutorial: How to Recursively Merge Two Objects In PHP](https://dev.to/joshualjohnson/tutorial-how-to-recursively-merge-two-objects-in-php-3jf9), which loops through all the attributes in the source object, and set the original object's attributes with the source object's attributes.

There are some simpler solutions to do the exact same thing, such as the following: (From [https://stackoverflow.com/a/455736](https://stackoverflow.com/a/455736))

```php
function merge($baseObject, $object) {
    foreach($object as $key => $value) {
        $baseObject->$key = $value;
    }
    return $baseObject;
}
```

Or, we can use the [`clone` keyword](https://www.php.net/manual/en/language.oop5.cloning.php) to copy the base object:

```php
function merge($baseObject, $object) {
    $clonedObject = clone $baseObject;
    foreach($object as $key => $value) {
        $clonedObject->$key = $value;
    }
    return $clonedObject;
}
```

## Overwriting Object's Methods?

Based on the above merging functions, could we overwrite an object's methods? Unfortunately, no. This is because those merging functions can only get the object's attributes, but not methods:

```php
class Foo {
    public $age = 1337;

    function hello() {
        echo "world\n";
    }
}

$foo = new Foo();
foreach($foo as $key => $value) {
    var_dump($key, $value);
}
```

```shell
└> php merge.php
string(3) "age"
int(1337)
```

So, if we try to overwrite a method, PHP will just set a new attribute:

```php
$foo = new Foo();
$foo->hello = "bar";
$foo->hello();
print_r($foo);
```

```shell
└> php merge.php
world
Foo Object
(
    [age] => 1337
    [hello] => bar
)
```

Also, PHP doesn't support overwriting an object's method dynamically.

## Merging on Object Attributes/Associative Array Keys

Now, since we can't pollute an object's methods and escape the object context, the only thing that we can do is to **pollute the object's attributes**.

Before I demonstrate that, I'll first define the merge function and the base object's class:

A simple merge objects function:

```php
function merge($baseObject, $object) {
    foreach($object as $key => $value) {
        $baseObject->$key = $value;
    }
    return $baseObject;
}
```

> Note: The merge function could be any alternatives in section "[Other Object Merge Methods](#other-object-merge-methods)".

Base object's class:

```php
class Foo {
    public $healthCheckCommands = array("ping -c 1 127.0.0.1");
    public $username = "not_admin";

    // RCE gadget
    function healthCheck() {
        foreach ($this->healthCheckCommands as $command) {
            passthru($command);
        }
    }

    // Authentication bypass gadget
    function isAdmin() {
        if ($this->username === "admin") {
            echo "[+] Is admin\n";
        } else {
            echo "[-] Is NOT admin\n";
        }
    }
}
```

In this class `Foo`, method `healthCheck` is an RCE gadget and method `isAdmin` is an authentication bypass gadget.

With that said, if the attacker can control the merging object's attributes, such as via [`json_decode`](https://www.php.net/manual/en/function.json-decode.php), he/she can overwrite the object's attributes to the desired one. For example, the attacker can overwrite public attribute `healthCheckCommands` array's value with malicious one:

```php
// $userInputJson = '{"healthCheckCommands": ["echo RCE gadget executed!"], "username": "admin"}';
$userInputJson = file_get_contents('php://input');
if (!empty($userInputJson)) {
    $baseObject = new Foo();
    
    echo "[*] Before merging:\n";
    print_r($baseObject);
    $baseObject->healthCheck();
    $baseObject->isAdmin();
    
    $userInputObject = json_decode($userInputJson);
    $mergedObject = merge($baseObject, $userInputObject);
    
    echo "\n[*] After merging:\n";
    print_r($mergedObject);
    $mergedObject->healthCheck();
    $mergedObject->isAdmin();
}
```

```shell
└> curl -X POST http://localhost:8000/merge.php --data '{"healthCheckCommands": ["echo RCE gadget executed!"], "username": "admin"}'
[*] Before merging:
Foo Object
(
    [healthCheckCommands] => Array
        (
            [0] => ping -c 1 127.0.0.1
        )

    [username] => not_admin
)
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.031 ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.031/0.031/0.031/0.000 ms
[-] Is NOT admin

[*] After merging:
Foo Object
(
    [healthCheckCommands] => Array
        (
            [0] => echo RCE gadget executed!
        )

    [username] => admin
)
RCE gadget executed!
[+] Is admin
```

But wait, how about those **built-in array merging functions**?

For using built-in merging functions and type casting, since the `(object)` type casting will return an object instance of class `stdClass`, we cannot pollute the base object's attributes. However, if we don't use type casting, we can still **pollute the array's keys**. Here's an example.

Assume the application has this `$config` associative array:

```php
$config = array(
    "healthCheckCommands" => array(
        "ping -c 1 127.0.0.1"
    ),
    "username" => "not_admin"
);
```

With these 2 gadgets:

```php
// RCE gadget
function healthCheck($config) {
    foreach ($config["healthCheckCommands"] as $command) {
        passthru($command);
    }
}

// Authentication bypass gadget
function isAdmin($config) {
    if ($config["username"] === "admin") {
        echo "[+] Is admin\n";
    } else {
        echo "[-] Is NOT admin\n";
    }
}
```

And the following array merging logic using built-in merge function `array_merge`:

```php
// $userInputJson = '{"healthCheckCommands": ["echo RCE gadget executed!"], "username": "admin"}';
$userInputJson = file_get_contents('php://input');
if (!empty($userInputJson)) {
    echo "[*] Before merging:\n";
    print_r($config);
    healthCheck($config);
    isAdmin($config);
    
    $userInputObject = json_decode($userInputJson, $associative=true);
    $mergedConfig = array_merge($config, $userInputObject);
    
    echo "\n[*] After merging:\n";
    print_r($mergedConfig);
    healthCheck($mergedConfig);
    isAdmin($mergedConfig);
}
```

> Note: The parsed JSON data must be converted into an associative array, otherwise `array_merge` can't merge an array with a `stdClass` object instance.

The attacker can overwrite the `$config` associative array key's value:

```shell
└> curl -X POST http://localhost:8000/merge.php --data '{"healthCheckCommands": ["echo RCE gadget executed!"], "username": "admin"}'
[*] Before merging:
Array
(
    [healthCheckCommands] => Array
        (
            [0] => ping -c 1 127.0.0.1
        )

    [username] => not_admin
)
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.024 ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.024/0.024/0.024/0.000 ms
[-] Is NOT admin

[*] After merging:
Array
(
    [healthCheckCommands] => Array
        (
            [0] => echo RCE gadget executed!
        )

    [username] => admin
)
RCE gadget executed!
[+] Is admin
```

Therefore, we can pollute (overwrite) an **object**'s properties or an **associative array**'s keys.

## Conclusion

Unfortunately, I couldn't find any real-world cases where the polluted object's properties or associative array's keys is flow to an impactful gadget. As well as there are a lot of gadgets and merging, which makes this process much harder. Luckily, this kind of "object properties pollution" and "associative array keys pollution" could still be useful if they flow to an impactful gadget.

In the future, hopefully we can find a way to escape the object context and pollute other classes and methods, as well as find an exploit that can lead to a full-blown RCE! Moreover, we don't want to research in class pollution in Python, Ruby, and PHP only, we should also research **this vulnerability class in other programming languages** that support OOP, such as Golang, Perl, and more.